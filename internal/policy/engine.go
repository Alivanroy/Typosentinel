package policy

import (
    "context"
    "fmt"
    "os"
    "path/filepath"

    "github.com/open-policy-agent/opa/rego"
    "github.com/Alivanroy/Typosentinel/pkg/types"
)

type Engine struct {
    modules []string
}

func NewEngine(policyDir string) (*Engine, error) {
    e := &Engine{}
    if policyDir == "" {
        policyDir = "policies"
    }
    // Load .rego files
    entries, err := os.ReadDir(policyDir)
    if err != nil {
        return e, nil // No policies present; run permissive
    }
    for _, entry := range entries {
        if entry.IsDir() { continue }
        if filepath.Ext(entry.Name()) != ".rego" { continue }
        b, err := os.ReadFile(filepath.Join(policyDir, entry.Name()))
        if err == nil { e.modules = append(e.modules, string(b)) }
    }
    return e, nil
}

// Evaluate runs policies against a package and returns policy threats
func (e *Engine) Evaluate(ctx context.Context, pkg *types.Package) ([]*types.Threat, error) {
    if len(e.modules) == 0 || pkg == nil { return nil, nil }

    r := rego.New(
        rego.Query("data.typosentinel.policy.violations"),
        rego.Module("policy.rego", concatModules(e.modules)),
        rego.Input(map[string]interface{}{
            "package": pkg,
        }),
    )
    rs, err := r.Eval(ctx)
    if err != nil { return nil, fmt.Errorf("policy eval: %w", err) }
    if len(rs) == 0 || len(rs[0].Expressions) == 0 { return nil, nil }
    val := rs[0].Expressions[0].Value
    arr, ok := val.([]interface{})
    if !ok { return nil, nil }
    var threats []*types.Threat
    for _, v := range arr {
        m, ok := v.(map[string]interface{})
        if !ok { continue }
        t := &types.Threat{
            Type:            types.ThreatTypeEnterprisePolicy,
            Severity:        types.SeverityHigh,
            Confidence:      0.9,
            Description:     fmt.Sprintf("policy violation: %v", m["message"]),
            DetectionMethod: "opa_policy",
        }
        threats = append(threats, t)
    }
    return threats, nil
}

func concatModules(mods []string) string {
    s := ""
    for _, m := range mods { s += m + "\n" }
    return s
}

