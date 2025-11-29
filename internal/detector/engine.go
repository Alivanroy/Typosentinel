// Package detector provides typosquatting and threat detection algorithms.
package detector

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	redis "github.com/redis/go-redis/v9"
)

type Options struct {
	SimilarityThreshold float64
	DeepAnalysis        bool
}

type Engine struct {
	enhancedDetector *EnhancedTyposquattingDetector
	popularCache     *PopularCache
	maxPopular       int
}

func New(cfg *config.Config) *Engine {
	ttl := time.Duration(0)
	max := 25
	if cfg != nil && cfg.TypoDetection != nil {
		if cfg.Cache != nil && cfg.Cache.TTL > 0 {
			ttl = cfg.Cache.TTL
		}
	}
	if ttl == 0 {
		ttl = time.Hour
	}
	var cache *PopularCache
	if cfg != nil && cfg.Redis.Enabled {
		addr := fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port)
		rdb := redis.NewClient(&redis.Options{Addr: addr, Password: cfg.Redis.Password, DB: cfg.Redis.Database})
		cache = NewPopularCacheWithRedis(ttl, rdb)
	} else {
		cache = NewPopularCache(ttl)
	}
	// Backoff config (optional config wiring can be added later)
	return &Engine{
		enhancedDetector: NewEnhancedTyposquattingDetector(),
		popularCache:     cache,
		maxPopular:       max,
	}
}

func (e *Engine) Version() string { return "1.0.0" }

type CheckPackageResult struct {
	Threats  []types.Threat
	Warnings []types.Warning
}

func (e *Engine) CheckPackage(ctx context.Context, name, registry string) (*CheckPackageResult, error) {
	// Select popular packages based on registry for better coverage
	if e.popularCache != nil {
		popularPackages := e.popularCache.Get(registry, e.maxPopular)
		if len(popularPackages) == 0 {
			popularPackages = getPopularByRegistry(registry)
		}
		// use popularPackages below
		dep := types.Dependency{
			Name:     name,
			Version:  "unknown",
			Registry: registry,
		}
		threats, warnings := e.AnalyzeDependency(dep, popularPackages, &Options{
			SimilarityThreshold: 0.75,
			DeepAnalysis:        true,
		})
		return &CheckPackageResult{Threats: threats, Warnings: warnings}, nil
	}
	popularPackages := getPopularByRegistry(registry)

	// Create a dependency for analysis
	dep := types.Dependency{
		Name:     name,
		Version:  "unknown",
		Registry: registry,
	}

	threats, warnings := e.AnalyzeDependency(dep, popularPackages, &Options{
		SimilarityThreshold: 0.75,
		DeepAnalysis:        true,
	})

	return &CheckPackageResult{
		Threats:  threats,
		Warnings: warnings,
	}, nil
}

// cfgFromContext placeholder (not used)
type ctxKey int

const detectorCfgKey ctxKey = iota

func WithConfig(ctx context.Context, cfg *config.Config) context.Context {
	return context.WithValue(ctx, detectorCfgKey, cfg)
}
func cfgFromContext(ctx context.Context) *config.Config {
	if v := ctx.Value(detectorCfgKey); v != nil {
		if c, ok := v.(*config.Config); ok {
			return c
		}
	}
	return nil
}

// getPopularByRegistry returns curated popular package names per registry
func getPopularByRegistry(registry string) []string {
	switch strings.ToLower(registry) {
	case "npm":
		return []string{"react", "lodash", "express", "axios", "webpack", "babel", "eslint", "typescript", "jquery", "moment", "next", "vue", "angular", "rxjs", "vite", "rollup", "yarn", "pnpm", "mocha", "jest", "chai", "sinon", "cross-env", "nodemon", "pm2"}
	case "pypi":
		return []string{"requests", "numpy", "pandas", "django", "flask", "tensorflow", "pytorch", "scikit-learn", "matplotlib", "pillow", "beautifulsoup4", "selenium", "pytest", "black", "flake8", "click", "jinja2", "sqlalchemy", "fastapi", "pydantic", "boto3", "redis", "celery", "gunicorn", "uvicorn", "httpx", "aiohttp", "typing-extensions", "setuptools", "wheel", "pip", "certifi", "urllib3", "charset-normalizer"}
	case "rubygems":
		return []string{"rails", "bundler", "rake", "rspec", "puma", "nokogiri", "devise", "activerecord", "activesupport", "thor", "json", "minitest", "rack", "sinatra", "capistrano", "sidekiq", "redis", "pg", "mysql2", "sqlite3", "faraday", "httparty", "factory_bot", "rubocop", "pry"}
	case "maven":
		return []string{"org.springframework:spring-core", "org.springframework:spring-boot-starter", "junit:junit", "org.apache.commons:commons-lang3", "com.google.guava:guava", "org.slf4j:slf4j-api", "ch.qos.logback:logback-classic", "com.fasterxml.jackson.core:jackson-core", "org.apache.httpcomponents:httpclient", "org.hibernate:hibernate-core", "org.mockito:mockito-core", "org.apache.maven.plugins:maven-compiler-plugin", "org.springframework.boot:spring-boot-starter-web", "org.springframework.boot:spring-boot-starter-data-jpa", "mysql:mysql-connector-java", "org.postgresql:postgresql", "redis.clients:jedis", "org.apache.kafka:kafka-clients", "com.amazonaws:aws-java-sdk", "org.elasticsearch.client:elasticsearch-rest-high-level-client"}
	case "nuget":
		return []string{"Newtonsoft.Json", "Microsoft.Extensions.DependencyInjection", "Microsoft.Extensions.Logging", "Microsoft.EntityFrameworkCore", "AutoMapper", "Serilog", "FluentValidation", "Microsoft.AspNetCore.Mvc", "System.Text.Json", "Microsoft.Extensions.Configuration", "NUnit", "xunit", "Moq", "Microsoft.Extensions.Hosting", "Swashbuckle.AspNetCore", "Microsoft.EntityFrameworkCore.SqlServer", "Microsoft.AspNetCore.Authentication.JwtBearer", "StackExchange.Redis", "Polly", "MediatR"}
	default:
		return []string{"react", "lodash", "express", "axios", "requests", "numpy", "pandas", "django", "flask", "rails", "bundler", "rake", "junit:junit", "org.apache.commons:commons-lang3"}
	}
}

func (e *Engine) AnalyzeDependency(dep types.Dependency, popularPackages []string, options *Options) ([]types.Threat, []types.Warning) {
	if e.enhancedDetector == nil {
		return []types.Threat{}, []types.Warning{}
	}

	// Use enhanced detector for typosquatting analysis
	threshold := 0.75 // default threshold
	if options != nil && options.SimilarityThreshold > 0 {
		threshold = options.SimilarityThreshold
	}

	threats := e.enhancedDetector.DetectEnhanced(dep, popularPackages, threshold)

	return threats, []types.Warning{}
}

type EnhancedSupplyChainDetector struct{}

func NewEnhancedSupplyChainDetector() *EnhancedSupplyChainDetector {
	return &EnhancedSupplyChainDetector{}
}

type EnhancedSupplyChainResult struct {
	Package           string
	Registry          string
	ThreatType        string
	Severity          string
	ConfidenceScore   float64
	IsFiltered        bool
	Recommendations   []string
	SupplyChainRisk   float64
	FalsePositiveRisk float64
	FilterReasons     []string
	Evidence          []string
}

func (d *EnhancedSupplyChainDetector) DetectThreats(ctx context.Context, pkgs []types.Package) ([]EnhancedSupplyChainResult, error) {
	return nil, nil
}
