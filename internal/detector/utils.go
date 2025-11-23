package detector

import (
    "crypto/rand"
    "encoding/hex"
)

func generateThreatID() string {
    b := make([]byte, 16)
    _, _ = rand.Read(b)
    return hex.EncodeToString(b)
}

func minInt(vals ...int) int {
    if len(vals) == 0 {
        return 0
    }
    m := vals[0]
    for i := 1; i < len(vals); i++ {
        if vals[i] < m {
            m = vals[i]
        }
    }
    return m
}