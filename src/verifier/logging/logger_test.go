// SPDX-License-Identifier: MIT

package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNew_TextFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Level: "info", Format: "text", Output: &buf})

	logger.Info("hello", "key", "value")

	out := buf.String()
	if !strings.Contains(out, "hello") {
		t.Errorf("expected 'hello' in output, got: %s", out)
	}
	if !strings.Contains(out, "key=value") {
		t.Errorf("expected 'key=value' in output, got: %s", out)
	}
}

func TestNew_JSONFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Level: "debug", Format: "json", Output: &buf})

	logger.Info("test message", "count", 42)

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("output is not valid JSON: %v\nraw: %s", err, buf.String())
	}

	if entry["msg"] != "test message" {
		t.Errorf("expected msg='test message', got: %v", entry["msg"])
	}
	if entry["level"] != "INFO" {
		t.Errorf("expected level='INFO', got: %v", entry["level"])
	}
	if count, ok := entry["count"].(float64); !ok || count != 42 {
		t.Errorf("expected count=42, got: %v", entry["count"])
	}
}

func TestSecurityLevel_JSON(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Level: "info", Format: "json", Output: &buf})

	Security(logger, "integrity mismatch", "client_id", "10.0.0.1")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if entry["level"] != "SECURITY" {
		t.Errorf("expected level='SECURITY', got: %v", entry["level"])
	}
	if entry["msg"] != "integrity mismatch" {
		t.Errorf("expected msg='integrity mismatch', got: %v", entry["msg"])
	}
	if entry["client_id"] != "10.0.0.1" {
		t.Errorf("expected client_id='10.0.0.1', got: %v", entry["client_id"])
	}
}

func TestSecurityLevel_Text(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Level: "info", Format: "text", Output: &buf})

	Security(logger, "agent tampering", "pcr14", "abc123")

	out := buf.String()
	if !strings.Contains(out, "SECURITY") {
		t.Errorf("expected 'SECURITY' level in output, got: %s", out)
	}
	if !strings.Contains(out, "agent tampering") {
		t.Errorf("expected message in output, got: %s", out)
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Level: "warn", Format: "text", Output: &buf})

	// these should be filtered
	logger.Debug("debug msg")
	logger.Info("info msg")

	// these should appear
	logger.Warn("warn msg")
	logger.Error("error msg")
	Security(logger, "security msg")

	out := buf.String()
	if strings.Contains(out, "debug msg") {
		t.Error("debug message should be filtered at warn level")
	}
	if strings.Contains(out, "info msg") {
		t.Error("info message should be filtered at warn level")
	}
	if !strings.Contains(out, "warn msg") {
		t.Error("warn message should appear")
	}
	if !strings.Contains(out, "error msg") {
		t.Error("error message should appear")
	}
	if !strings.Contains(out, "security msg") {
		t.Error("security message should always appear")
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"security", LevelSecurity},
		{"SECURITY", LevelSecurity},
		{"unknown", slog.LevelInfo},
	}

	for _, tc := range tests {
		got := ParseLevel(tc.input)
		if got != tc.expected {
			t.Errorf("ParseLevel(%q) = %v, want %v", tc.input, got, tc.expected)
		}
	}
}

func TestNop(t *testing.T) {
	logger := Nop()
	// should not panic
	logger.Info("discarded")
	Security(logger, "discarded too")
}

func TestWithClient(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Level: "info", Format: "json", Output: &buf})

	cl := WithClient(logger, "192.168.1.1")
	cl.Info("connected")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if entry["client_id"] != "192.168.1.1" {
		t.Errorf("expected client_id='192.168.1.1', got: %v", entry["client_id"])
	}
}
