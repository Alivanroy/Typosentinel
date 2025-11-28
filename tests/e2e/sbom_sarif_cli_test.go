package e2e

import (
    "bytes"
    "encoding/json"
    "os/exec"
    "testing"
)

func TestCLI_ScanOutputsSBOMAndSARIF(t *testing.T){
    // NPM sample
    cmd := exec.Command("go", "run", "c:\\Users\\aliko\\Desktop\\Typosentinel", "scan", "c:\\Users\\aliko\\Desktop\\Typosentinel\\tests\\e2e\\test-projects\\npm-vulnerable", "--output", "cyclonedx")
    out, err := cmd.CombinedOutput()
    if err != nil { t.Fatalf("scan cyclonedx failed: %v: %s", err, string(out)) }
    start := bytes.IndexByte(out, '{'); var obj map[string]interface{}
    if start >= 0 { _ = json.Unmarshal(out[start:], &obj) }
    if _, ok := obj["components"]; !ok { t.Fatalf("cyclonedx missing components") }

    cmd2 := exec.Command("go", "run", "c:\\Users\\aliko\\Desktop\\Typosentinel", "scan", "c:\\Users\\aliko\\Desktop\\Typosentinel\\tests\\e2e\\test-projects\\npm-vulnerable", "--output", "sarif")
    out2, err := cmd2.CombinedOutput()
    if err != nil { t.Fatalf("scan sarif failed: %v: %s", err, string(out2)) }
    start2 := bytes.IndexByte(out2, '{'); var obj2 map[string]interface{}
    if start2 >= 0 { _ = json.Unmarshal(out2[start2:], &obj2) }
    if _, ok := obj2["runs"]; !ok { t.Fatalf("sarif missing runs") }
}
