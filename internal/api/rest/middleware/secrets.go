package middleware

import (
    "strings"
    "github.com/gin-gonic/gin"
)

func RedactSecrets() gin.HandlerFunc {
    return func(c *gin.Context) {
        for k := range c.Request.Header {
            key := strings.ToLower(k)
            if key == "authorization" || key == "x-api-key" || strings.Contains(key, "secret") || strings.Contains(key, "token") {
                c.Request.Header.Set(k, "***redacted***")
            }
        }
        c.Next()
    }
}

