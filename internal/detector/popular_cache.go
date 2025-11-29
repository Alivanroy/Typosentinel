package detector

import (
    "time"
    "strings"
    reg "github.com/Alivanroy/Typosentinel/internal/registry"
)

type popularEntry struct {
    names    []string
    expires  time.Time
}

type PopularCache struct {
    ttl    time.Duration
    store  map[string]popularEntry
}

func NewPopularCache(ttl time.Duration) *PopularCache {
    return &PopularCache{ttl: ttl, store: make(map[string]popularEntry)}
}

func (c *PopularCache) Get(registry string, max int) []string {
    key := strings.ToLower(registry)
    if e, ok := c.store[key]; ok {
        if time.Now().Before(e.expires) {
            return truncate(e.names, max)
        }
    }

    names := fetchPopularDynamic(key, max)
    if len(names) == 0 {
        names = truncate(getPopularByRegistry(key), max)
    }

    c.store[key] = popularEntry{names: names, expires: time.Now().Add(c.ttl)}
    return truncate(names, max)
}

func truncate(list []string, max int) []string {
    if max > 0 && len(list) > max {
        return list[:max]
    }
    return list
}

func fetchPopularDynamic(registry string, limit int) []string {
    f := reg.NewFactory()
    conn, err := f.CreateConnectorFromType(registry)
    if err != nil { return nil }

    switch strings.ToLower(registry) {
    case "pypi":
        if p, ok := conn.(*reg.PyPIConnector); ok {
            names, err := p.PopularPackageNames(limit)
            if err == nil { return names }
        }
    case "maven":
        if m, ok := conn.(*reg.MavenConnector); ok {
            names, err := m.PopularPackageNames(limit)
            if err == nil { return names }
        }
    case "nuget":
        if n, ok := conn.(*reg.NuGetConnector); ok {
            names, err := n.PopularPackageNames(limit)
            if err == nil { return names }
        }
    case "rubygems":
        if r, ok := conn.(*reg.RubyGemsConnector); ok {
            names, err := r.PopularPackageNames(limit)
            if err == nil { return names }
        }
    }
    return nil
}

