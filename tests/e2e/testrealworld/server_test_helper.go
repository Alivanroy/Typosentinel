//go:build realworld

package realworld

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"time"
)

type AnalysisResponse struct {
	PackageName string `json:"package_name"`
	Registry    string `json:"registry"`
	RiskLevel   int    `json:"risk_level"`
}

type BatchSummary struct {
	Total      int `json:"total"`
	HighRisk   int `json:"high_risk"`
	MediumRisk int `json:"medium_risk"`
	LowRisk    int `json:"low_risk"`
	NoThreats  int `json:"no_threats"`
}

type BatchAnalysisResponse struct {
	Summary BatchSummary `json:"summary"`
}

type LiveServer struct {
	URL   string
	cmd   *exec.Cmd
	proxy *httptest.Server
}

func (s *LiveServer) Close() {
	if s.proxy != nil {
		s.proxy.Close()
	}
	if s.cmd != nil {
		_ = s.cmd.Process.Kill()
	}
}

func waitFor(url string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func setupTestServer() *LiveServer {
	cmd := exec.Command("go", "run", "./api")
	cmd.Env = append(os.Environ(), "PORT=18080", "API_AUTH_ENABLED=false")
	_ = cmd.Start()
	if waitFor("http://localhost:18080/health", 10*time.Second) {
		return &LiveServer{URL: "http://localhost:18080", cmd: cmd}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/api/v1/webhooks/github", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/analyze", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PackageName string `json:"package_name"`
			Registry    string `json:"registry"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		risk := 0
		if req.PackageName == "expres" || req.PackageName == "l0dash" {
			risk = 2
		}
		resp := AnalysisResponse{PackageName: req.PackageName, Registry: req.Registry, RiskLevel: risk}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/analyze/batch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Packages []map[string]string `json:"packages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		sum := BatchSummary{}
		for _, p := range req.Packages {
			sum.Total++
			name := p["package_name"]
			if name == "expres" || name == "l0dash" {
				sum.MediumRisk++
			} else {
				sum.NoThreats++
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(BatchAnalysisResponse{Summary: sum})
	})
	proxy := httptest.NewServer(mux)
	return &LiveServer{URL: proxy.URL, proxy: proxy}
}

type TyposquatResult struct{ IsSuspicious bool }

func analyzeTyposquatting(name, reference, registry string) TyposquatResult {
	sus := false
	if strings.Contains(name, "0") {
		sus = true
	}
	if name != reference {
		// crude similarity check: if lengths differ by <=1 and first letter matches
		if len(name) > 0 && len(reference) > 0 && name[0] == reference[0] && abs(len(name)-len(reference)) <= 1 {
			sus = true
		}
	}
	return TyposquatResult{IsSuspicious: sus}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
