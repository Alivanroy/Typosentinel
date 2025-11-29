package logger

import (
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	cases := map[string]LogLevel{"TRACE": TRACE, "DEBUG": DEBUG, "VERBOSE": VERBOSE, "INFO": INFO, "WARN": WARN, "WARNING": WARN, "ERROR": ERROR, "FATAL": FATAL, "unknown": INFO}
	for k, v := range cases {
		if ParseLogLevel(k) != v {
			t.Fatalf("level parse failed for %s", k)
		}
	}
}

func TestNewAndSetters(t *testing.T) {
	l := NewTestLogger()
	l.SetLevel(DEBUG)
	l.SetFormat("json")
	l.Info("info")
	l.Debug("debug")
	l.Warn("warn")
	l.Error("error")
	fl := l.WithFields(map[string]interface{}{"k": "v"})
	fl.Info("with fields")
}
