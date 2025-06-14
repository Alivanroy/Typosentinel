package database

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/minio/minio-go/v7"
	"github.com/typosentinel/typosentinel/pkg/types"
)

type Repository struct {
	db          *sql.DB
	redis       *redis.Client
	blobStorage *minio.Client
	clickhouse  *sql.DB
}

func NewRepository(db *sql.DB, redis *redis.Client, blobStorage *minio.Client, clickhouse *sql.DB) *Repository {
	return &Repository{
		db:          db,
		redis:       redis,
		blobStorage: blobStorage,
		clickhouse:  clickhouse,
	}
}

// Cached package lookup
func (r *Repository) GetPackage(name, registry string) (*types.Package, error) {
	cacheKey := fmt.Sprintf("package:%s:%s", name, registry)

	// Try cache first
	cached, err := r.redis.Get(context.Background(), cacheKey).Result()
	if err == nil {
		var pkg types.Package
		if json.Unmarshal([]byte(cached), &pkg) == nil {
			return &pkg, nil
		}
	}

	// Fallback to database
	var pkg types.Package
	err = r.db.QueryRow(`
		SELECT id, name, registry, version, package_url, created_at
		FROM packages
		WHERE name = $1 AND registry = $2
		ORDER BY created_at DESC
		LIMIT 1
	`, name, registry).Scan(&pkg.ID, &pkg.Name, &pkg.Registry, &pkg.Version, &pkg.PackageURL, &pkg.CreatedAt)

	if err != nil {
		return nil, err
	}

	// Cache for 1 hour
	data, _ := json.Marshal(pkg)
	r.redis.Set(context.Background(), cacheKey, data, time.Hour)

	return &pkg, nil
}

// Store large scan artifacts in blob storage
func (r *Repository) StoreScanArtifacts(scanID string, artifacts map[string][]byte) error {
	bucketName := "scan-artifacts"

	for filename, data := range artifacts {
		objectName := fmt.Sprintf("%s/%s", scanID, filename)

		_, err := r.blobStorage.PutObject(
			context.Background(),
			bucketName,
			objectName,
			bytes.NewReader(data),
			int64(len(data)),
			minio.PutObjectOptions{ContentType: "application/octet-stream"},
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// Get scan artifacts from blob storage
func (r *Repository) GetScanArtifacts(scanID string) (map[string][]byte, error) {
	bucketName := "scan-artifacts"
	artifacts := make(map[string][]byte)

	// List objects with scanID prefix
	objectCh := r.blobStorage.ListObjects(context.Background(), bucketName, minio.ListObjectsOptions{
		Prefix: scanID + "/",
	})

	for object := range objectCh {
		if object.Err != nil {
			return nil, object.Err
		}

		// Get object content
		obj, err := r.blobStorage.GetObject(context.Background(), bucketName, object.Key, minio.GetObjectOptions{})
		if err != nil {
			return nil, err
		}

		// Read content
		buf := new(bytes.Buffer)
		_, err = buf.ReadFrom(obj)
		if err != nil {
			return nil, err
		}

		// Extract filename from object key
		filename := object.Key[len(scanID)+1:]
		artifacts[filename] = buf.Bytes()
	}

	return artifacts, nil
}

// Store scan result with caching
func (r *Repository) StoreScanResult(result *types.ScanResult) error {
	// Store in primary database
	query := `
		INSERT INTO scan_results (id, package_id, organization_id, scan_type, overall_risk, risk_score, findings, metadata, scan_duration_ms, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	findingsJSON, _ := json.Marshal(result.Findings)
	metadataJSON, _ := json.Marshal(result.Metadata)

	_, err := r.db.Exec(query,
		result.ID,
		result.PackageID,
		result.OrganizationID,
		result.ScanType,
		result.OverallRisk,
		result.RiskScore,
		findingsJSON,
		metadataJSON,
		result.ScanDurationMs,
		result.CreatedAt,
	)

	if err != nil {
		return err
	}

	// Store in ClickHouse for analytics
	go r.storeAnalyticsData(result)

	// Invalidate related caches
	cacheKeys := []string{
		fmt.Sprintf("scan_results:org:%s", result.OrganizationID),
		fmt.Sprintf("scan_results:package:%s", result.PackageID),
	}

	for _, key := range cacheKeys {
		r.redis.Del(context.Background(), key)
	}

	return nil
}

// Store analytics data in ClickHouse
func (r *Repository) storeAnalyticsData(result *types.ScanResult) {
	if r.clickhouse == nil {
		return
	}

	query := `
		INSERT INTO scan_analytics (
			scan_id, package_name, registry, organization_id, 
			risk_score, scan_type, scan_duration_ms, 
			threat_count, timestamp
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	threatCount := len(result.Findings)

	_, err := r.clickhouse.Exec(query,
		result.ID,
		result.PackageName,
		result.Registry,
		result.OrganizationID,
		result.RiskScore,
		result.ScanType,
		result.ScanDurationMs,
		threatCount,
		result.CreatedAt,
	)

	if err != nil {
		// Log error but don't fail the main operation
		fmt.Printf("Failed to store analytics data: %v\n", err)
	}
}

// Get scan results with caching
func (r *Repository) GetScanResults(orgID string, limit, offset int) ([]*types.ScanResult, error) {
	cacheKey := fmt.Sprintf("scan_results:org:%s:%d:%d", orgID, limit, offset)

	// Try cache first
	cached, err := r.redis.Get(context.Background(), cacheKey).Result()
	if err == nil {
		var results []*types.ScanResult
		if json.Unmarshal([]byte(cached), &results) == nil {
			return results, nil
		}
	}

	// Query database
	query := `
		SELECT id, package_id, organization_id, scan_type, overall_risk, 
		       risk_score, findings, metadata, scan_duration_ms, created_at
		FROM scan_results
		WHERE organization_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.Query(query, orgID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*types.ScanResult
	for rows.Next() {
		var result types.ScanResult
		var findingsJSON, metadataJSON []byte

		err := rows.Scan(
			&result.ID,
			&result.PackageID,
			&result.OrganizationID,
			&result.ScanType,
			&result.OverallRisk,
			&result.RiskScore,
			&findingsJSON,
			&metadataJSON,
			&result.ScanDurationMs,
			&result.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		json.Unmarshal(findingsJSON, &result.Findings)
		json.Unmarshal(metadataJSON, &result.Metadata)

		results = append(results, &result)
	}

	// Cache for 5 minutes
	data, _ := json.Marshal(results)
	r.redis.Set(context.Background(), cacheKey, data, 5*time.Minute)

	return results, nil
}