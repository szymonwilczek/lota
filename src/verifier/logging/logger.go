// SPDX-License-Identifier: MIT
// LOTA Verifier - Structured Logging
//
// Provides structured logging for the verifier based on log/slog.
// Supports JSON and text output formats with configurable log levels.
//
// Custom log level SECURITY (12) is above ERROR (8) and is used for
// security-relevant events: attestation failures, revocations, bans,
// integrity mismatches, and other events that may indicate cheating
// or system compromise.

package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

// custom slog level for security-critical events
const LevelSecurity = slog.Level(12)

// maps custom levels to their display strings
var levelNames = map[slog.Level]string{
	LevelSecurity: "SECURITY",
}

// configures a new logger instance
type Options struct {
	// minimum log level: debug, info, warn, error
	// security events are always emitted regardless of this setting
	Level string

	// selects output encoding: 'json' or 'text' (default)
	Format string

	// output destination. defaults to os.Stderr if nil
	Output io.Writer
}

// creates a configured *slog.Logger
func New(opts Options) *slog.Logger {
	level := ParseLevel(opts.Level)

	output := opts.Output
	if output == nil {
		output = os.Stderr
	}

	replaceAttr := func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.LevelKey {
			lvl := a.Value.Any().(slog.Level)
			if name, ok := levelNames[lvl]; ok {
				a.Value = slog.StringValue(name)
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

// returns a logger that discards all output
func Nop() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// converts a level name string to slog.Level
// accepted values: debug, info, warn, error, security
// defaults to INFO for unknown values
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

// emits a SECURITY-level log entry
func Security(logger *slog.Logger, msg string, args ...any) {
	logger.Log(context.Background(), LevelSecurity, msg, args...)
}

// returns a child logger with the client_id field pre-set
func WithClient(logger *slog.Logger, clientID string) *slog.Logger {
	return logger.With("client_id", clientID)
}
