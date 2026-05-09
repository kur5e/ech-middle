// Package logger provides a leveled, color-aware logging wrapper
// around the standard library's log/slog.
package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"ech-middle/internal/config"
)

// Level represents a log severity level.
type Level int

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

// String returns the level name.
func (l Level) String() string {
	switch l {
	case LevelError:
		return "ERROR"
	case LevelWarn:
		return "WARN"
	case LevelInfo:
		return "INFO"
	case LevelDebug:
		return "DEBUG"
	default:
		return "UNKNOWN"
	}
}

// slogLevel maps our Level to slog.Level.
func (l Level) slogLevel() slog.Level {
	switch l {
	case LevelError:
		return slog.LevelError
	case LevelWarn:
		return slog.LevelWarn
	case LevelInfo:
		return slog.LevelInfo
	case LevelDebug:
		return slog.LevelDebug
	default:
		return slog.LevelInfo
	}
}

// parseLevel converts a string to a Level. Defaults to LevelInfo.
func parseLevel(s string) Level {
	switch s {
	case "error":
		return LevelError
	case "warn":
		return LevelWarn
	case "info":
		return LevelInfo
	case "debug":
		return LevelDebug
	default:
		return LevelInfo
	}
}

// Logger wraps slog.Logger with level filtering and optional color output.
type Logger struct {
	inner  *slog.Logger
	level  Level
	color  bool
	isFile bool
	closer io.Closer // non-nil when writing to a file
}

// Close releases resources held by the Logger (e.g., closes the log file).
func (l *Logger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

// NewLogger creates a Logger from config.LogConfig. When output is a file,
// color is automatically disabled regardless of the config setting.
func NewLogger(cfg config.LogConfig) *Logger {
	var w io.Writer = os.Stdout
	isFile := false

	if cfg.File != "" {
		f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "logger: cannot open %q, falling back to stdout: %v\n", cfg.File, err)
		} else {
			w = f
			isFile = true
		}
	}

	useColor := cfg.Color && !isFile

	handler := newPrettyHandler(w, useColor)
	inner := slog.New(handler)

	l := &Logger{
		inner:  inner,
		level:  parseLevel(cfg.Level),
		color:  useColor,
		isFile: isFile,
	}
	if isFile {
		l.closer = w.(io.Closer)
	}
	return l
}

// errorf logs at ERROR level.
func (l *Logger) Errorf(format string, v ...any) {
	if l.level >= LevelError {
		l.inner.Error(fmt.Sprintf(format, v...))
	}
}

// Warnf logs at WARN level.
func (l *Logger) Warnf(format string, v ...any) {
	if l.level >= LevelWarn {
		l.inner.Warn(fmt.Sprintf(format, v...))
	}
}

// Infof logs at INFO level.
func (l *Logger) Infof(format string, v ...any) {
	if l.level >= LevelInfo {
		l.inner.Info(fmt.Sprintf(format, v...))
	}
}

// Debugf logs at DEBUG level.
func (l *Logger) Debugf(format string, v ...any) {
	if l.level >= LevelDebug {
		l.inner.Debug(fmt.Sprintf(format, v...))
	}
}

// Inner returns the underlying slog.Logger for integration with libraries
// that accept *slog.Logger (e.g., goproxy's Logger option).
func (l *Logger) Inner() *slog.Logger {
	return l.inner
}
