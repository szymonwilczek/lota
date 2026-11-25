// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Structured Logging

package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

// LevelSecurity sits above slog.LevelError, so every level ParseLevel returns
// lets it through.
const LevelSecurity = slog.Level(12)

var levelNames = map[slog.Level]string{
	LevelSecurity: "SECURITY",
}

// Options configures New.
type Options struct {
	Level  string    // see ParseLevel
	Format string    // "json" in any case; anything else is text
	Output io.Writer // nil = os.Stderr
}

// New returns a logger for opts.
func New(opts Options) *slog.Logger {
	level := ParseLevel(opts.Level)

	output := opts.Output
	if output == nil {
		output = os.Stderr
	}

	replaceAttr := func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.LevelKey {
			if lvl, ok := a.Value.Any().(slog.Level); ok {
				if name, ok := levelNames[lvl]; ok {
					a.Value = slog.StringValue(name)
				}
			}
		}
		return a
	}

	var handler slog.Handler
	switch strings.ToLower(opts.Format) {
	case "json":
		handler = slog.NewJSONHandler(output, &slog.HandlerOptions{
			Level:       level,
			ReplaceAttr: replaceAttr,
		})
	default:
		handler = slog.NewTextHandler(output, &slog.HandlerOptions{
			Level:       level,
			ReplaceAttr: replaceAttr,
		})
	}

	return slog.New(handler)
}

// Nop returns a logger that discards its output.
func Nop() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ParseLevel maps debug, info, warn or warning, error and security to a level,
// ignoring case; anything else is info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "info", "":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "security":
		return LevelSecurity
	default:
		return slog.LevelInfo
	}
}

// Security logs msg at LevelSecurity, passing each string argument through
// SanitizeField.
func Security(logger *slog.Logger, msg string, args ...any) {
	for i, a := range args {
		if s, ok := a.(string); ok {
			args[i] = SanitizeField(s)
		}
	}
	logger.Log(context.Background(), LevelSecurity, msg, args...)
}

// SanitizeField replaces CR and LF in s with spaces.
func SanitizeField(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.ReplaceAll(s, "\n", " ")
}

// WithClient returns logger with a sanitized client_id field.
func WithClient(logger *slog.Logger, clientID string) *slog.Logger {
	return logger.With("client_id", SanitizeField(clientID))
}
