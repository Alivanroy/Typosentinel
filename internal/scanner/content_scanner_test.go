package scanner

import (
    "os"
    "path/filepath"
    "testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
    t.Helper()
    p := filepath.Join(dir, name)
    if err := os.WriteFile(p, []byte(content), 0644); err != nil { t.Fatalf("write: %v", err) }
    return p
}

func TestContentScanner_ObfuscationAndSecrets(t *testing.T) {
    dir := t.TempDir()
    // Obfuscated JS with multiple eval and multiple large base64 payloads
    big := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    js := "var a='" + big + "'; var b='" + big + "'; var c='" + big + "';" +
        "eval('1'); eval('2'); eval('3'); eval('4');"
    writeFile(t, dir, "obf.js", js)
    // Embedded AWS-style secret
    sec := `aws_access_key_id=AKIA1234567890ABCD12; aws_secret_access_key=abcdEFGHijklMNOPqrstUVWXyz1234567890abcd;`
    writeFile(t, dir, "secrets.txt", sec)

    cs := NewContentScanner()
    threats, err := cs.ScanDirectory(dir)
    if err != nil { t.Fatalf("scan err: %v", err) }
    if len(threats) == 0 { t.Fatalf("expected threats, got none") }
}
