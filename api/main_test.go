package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestValidatePackageInput_NPM(t *testing.T) {
	if err := validatePackageInput("express", "npm"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := validatePackageInput("Express", "npm"); err == nil {
		t.Fatalf("expected invalid npm name")
	}
	if err := validatePackageInput("../evil", "npm"); err == nil {
		t.Fatalf("expected path traversal invalid")
	}
	if err := validatePackageInput("bad name", "npm"); err == nil {
		t.Fatalf("expected space invalid")
	}
}

func TestValidatePackageInput_PyPI(t *testing.T) {
	if err := validatePackageInput("requests", "pypi"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := validatePackageInput("-bad-", "pypi"); err == nil {
		t.Fatalf("expected invalid pypi name")
	}
}

func TestValidatePackageInput_GoAndMaven(t *testing.T) {
	if err := validatePackageInput("github.com/sirupsen/logrus", "go"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := validatePackageInput("org.apache.commons:commons-lang3", "maven"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := validatePackageInput("github.com/sirupsen/logrus bad", "go"); err == nil {
		t.Fatalf("expected invalid go name with spaces")
	}
	if err := validatePackageInput("org.apache.commons:commons lang3", "maven"); err == nil {
		t.Fatalf("expected invalid maven name with spaces")
	}
}

func TestMetricsEndpointJSON(t *testing.T) {
	req, _ := http.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		m := metrics.GetInstance()
		json.NewEncoder(w).Encode(m.GetMetrics())
	})
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct == "" {
		t.Fatalf("missing content type")
	}
}
func TestSSEStreamEndpoint(t *testing.T) {
	req, _ := http.NewRequest("GET", "/v1/stream", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Write([]byte("data: {\"type\": \"ping\"}\n\n"))
	})
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "data:") {
		t.Fatalf("expected sse data")
	}
}
func TestOpenAPIJSONEndpoint(t *testing.T) {
	req, _ := http.NewRequest("GET", "/openapi.json", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		f, err := os.Open("docs/openapi.json")
		if err != nil {
			http.Error(w, "OpenAPI spec not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		io.Copy(w, f)
	})
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &obj); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if _, ok := obj["openapi"]; !ok {
		t.Fatalf("missing openapi field")
	}
	if _, ok := obj["paths"]; !ok {
		t.Fatalf("missing paths field")
	}
}
