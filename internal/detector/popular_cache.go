package detector

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	reg "github.com/Alivanroy/Typosentinel/internal/registry"
	redis "github.com/redis/go-redis/v9"
)

type popularEntry struct {
	names   []string
	expires time.Time
}

type PopularCache struct {
	ttl            time.Duration
	store          map[string]popularEntry
	rdb            *redis.Client
	backoffs       []time.Duration
	attempts       int
	npmQuality     float64
	npmPopularity  float64
	npmMaintenance float64
}

func NewPopularCache(ttl time.Duration) *PopularCache {
	return &PopularCache{ttl: ttl, store: make(map[string]popularEntry), backoffs: []time.Duration{100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond}, attempts: 3}
}
func NewPopularCacheWithRedis(ttl time.Duration, client *redis.Client) *PopularCache {
	return &PopularCache{ttl: ttl, store: make(map[string]popularEntry), rdb: client, backoffs: []time.Duration{100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond}, attempts: 3}
}
func (c *PopularCache) SetBackoffs(backoffs []time.Duration) {
	if len(backoffs) > 0 {
		c.backoffs = backoffs
	}
}
func (c *PopularCache) SetAttempts(n int) {
	if n > 0 {
		c.attempts = n
	}
}
func (c *PopularCache) SetNPMWeights(quality, popularity, maintenance float64) {
	c.npmQuality = quality
	c.npmPopularity = popularity
	c.npmMaintenance = maintenance
}

func (c *PopularCache) Get(registry string, max int) []string {
	key := strings.ToLower(registry)
	// Try Redis first
	if c.rdb != nil {
		val, err := c.rdb.Get(context.Background(), "popular:"+key).Result()
		if err == nil && val != "" {
			var names []string
			if json.Unmarshal([]byte(val), &names) == nil {
				return truncate(names, max)
			}
		}
	}
	if e, ok := c.store[key]; ok {
		if time.Now().Before(e.expires) {
			return truncate(e.names, max)
		}
	}

	names := c.fetchPopularDynamic(key, max)
	if len(names) == 0 {
		names = truncate(getPopularByRegistry(key), max)
	}

	c.store[key] = popularEntry{names: names, expires: time.Now().Add(c.ttl)}
	if c.rdb != nil && len(names) > 0 {
		data, _ := json.Marshal(names)
		c.rdb.Set(context.Background(), "popular:"+key, string(data), c.ttl)
	}
	return truncate(names, max)
}

func truncate(list []string, max int) []string {
	if max > 0 && len(list) > max {
		return list[:max]
	}
	return list
}

func (c *PopularCache) fetchPopularDynamic(registry string, limit int) []string {
	f := reg.NewFactory()
	conn, err := f.CreateConnectorFromType(registry)
	if err != nil {
		return nil
	}

	backoffs := c.backoffs
	try := func(fetch func() ([]string, error)) []string {
		attempts := c.attempts
		if attempts <= 0 {
			attempts = len(backoffs)
		}
		for i := 0; i < attempts; i++ {
			names, err := fetch()
			if err == nil && len(names) > 0 {
				return names
			}
			idx := i
			if idx >= len(backoffs) {
				idx = len(backoffs) - 1
			}
			if idx >= 0 && len(backoffs) > 0 {
				time.Sleep(backoffs[idx])
			}
		}
		return nil
	}

	switch strings.ToLower(registry) {
	case "pypi":
		if p, ok := conn.(*reg.PyPIConnector); ok {
			return try(func() ([]string, error) { return p.PopularPackageNames(limit) })
		}
	case "maven":
		if m, ok := conn.(*reg.MavenConnector); ok {
			return try(func() ([]string, error) { return m.PopularPackageNames(limit) })
		}
	case "nuget":
		if n, ok := conn.(*reg.NuGetConnector); ok {
			return try(func() ([]string, error) { return n.PopularPackageNames(limit) })
		}
	case "rubygems":
		if r, ok := conn.(*reg.RubyGemsConnector); ok {
			return try(func() ([]string, error) { return r.PopularPackageNames(limit) })
		}
	case "npm":
		if n, ok := conn.(*reg.NPMConnector); ok {
			n.SetBias(c.npmQuality, c.npmPopularity, c.npmMaintenance)
			names, err := n.PopularPackageNames(limit)
			if err == nil && len(names) > 0 {
				return names
			}
			names = getPopularByRegistry("npm")
			return truncate(names, limit)
		}
	case "composer":
		if c, ok := conn.(*reg.ComposerConnector); ok {
			// Fetch names from Packagist list
			pkgs, err := c.PopularPackageNames(limit)
			if err == nil {
				return pkgs
			}
		}
	case "cargo":
		if cg, ok := conn.(*reg.CargoConnector); ok {
			pkgs, err := cg.PopularPackageNames(limit)
			if err == nil {
				return pkgs
			}
		}
	}
	return nil
}
