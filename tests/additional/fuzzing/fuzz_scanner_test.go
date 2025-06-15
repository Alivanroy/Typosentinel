package fuzzing

import (
    "testing"
    "typosentinel/internal/detector"
)

func FuzzParsePackage(f *testing.F) {
    f.Add([]byte("hello"))
    f.Fuzz(func(t *testing.T, data []byte) {
        _ = detector.ParsePackage(data) // should never panic
    })
}