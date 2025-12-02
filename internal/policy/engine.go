package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/fsnotify/fsnotify"
	"github.com/open-policy-agent/opa/rego"
	"github.com/spf13/viper"
)

type Engine struct {
	modules   []string
	policyDir string
}

func NewEngine(policyDir string) (*Engine, error) {
	e := &Engine{}
	if policyDir == "" {
		policyDir = viper.GetString("policies.path")
	}
	if policyDir == "" {
		policyDir = "policies"
	}
	e.policyDir = policyDir
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		return e, nil // No policies present; run permissive
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".rego" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(policyDir, entry.Name()))
		if err == nil {
			e.modules = append(e.modules, string(b))
		}
	}
	if viper.GetBool("policies.hot_reload") {
		_ = e.watch()
	}
	return e, nil
}

// Evaluate runs policies against a package and returns policy threats
func (e *Engine) Evaluate(ctx context.Context, pkg *types.Package) ([]*types.Threat, error) {
	if len(e.modules) == 0 || pkg == nil {
		return nil, nil
	}

	r := rego.New(
		rego.Query("data.typosentinel.policy.violations"),
		rego.Module("policy.rego", concatModules(e.modules)),
		rego.Input(map[string]interface{}{
			"package": pkg,
		}),
	)
	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy eval: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil
	}
	val := rs[0].Expressions[0].Value
	arr, ok := val.([]interface{})
	if !ok {
		return nil, nil
	}
	var threats []*types.Threat
	for _, v := range arr {
		m, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
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
	for _, m := range mods {
		s += m + "\n"
	}
	return s
}

func (e *Engine) watch() error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	_ = w.Add(e.policyDir)
	go func() {
		for {
			select {
			case ev := <-w.Events:
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0 {
					e.reload()
				}
			case <-w.Errors:
			}
		}
	}()
	return nil
}

func (e *Engine) reload() {
	var mods []string
	entries, err := os.ReadDir(e.policyDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".rego" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(e.policyDir, entry.Name()))
		if err == nil {
			mods = append(mods, string(b))
		}
	}
	e.modules = mods
}
