package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ANSI color escape codes for terminal output.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorWhite  = "\033[97m"
)

// colorForLevel returns the ANSI color for a given slog level.
func colorForLevel(level slog.Level) string {
	switch level {
	case slog.LevelError:
		return colorRed
	case slog.LevelWarn:
		return colorYellow
	case slog.LevelInfo:
		return colorCyan
	case slog.LevelDebug:
		return colorGray
	default:
		return colorWhite
	}
}

// levelLabel returns a short uppercase label for a slog level.
func levelLabel(level slog.Level) string {
	switch level {
	case slog.LevelError:
		return "ERROR"
	case slog.LevelWarn:
		return "WARN "
	case slog.LevelInfo:
		return "INFO "
	case slog.LevelDebug:
		return "DEBUG"
	default:
		return "UNKWN"
	}
}

// prettyHandler is a slog.Handler that writes human-readable log lines
// with optional ANSI color support.
type prettyHandler struct {
	mu     sync.Mutex
	w      io.Writer
	color  bool
	attrs  []slog.Attr
	groups []string
}

// newPrettyHandler creates a new prettyHandler.
func newPrettyHandler(w io.Writer, color bool) *prettyHandler {
	return &prettyHandler{w: w, color: color}
}

// Enabled reports whether the handler handles records at the given level.
func (h *prettyHandler) Enabled(_ context.Context, level slog.Level) bool {
	return true // level filtering is done at the Logger level
}

// Handle formats and writes a log record.
func (h *prettyHandler) Handle(_ context.Context, r slog.Record) error {
	var buf strings.Builder

	// Timestamp
	t := r.Time.Format(time.RFC3339)
	if h.color {
		buf.WriteString(colorGray)
	}
	buf.WriteString(t)
	buf.WriteString(" ")
	if h.color {
		buf.WriteString(colorReset)
	}

	// Level label
	label := levelLabel(r.Level)
	if h.color {
		buf.WriteString(colorForLevel(r.Level))
	}
	buf.WriteString(label)
	if h.color {
		buf.WriteString(colorReset)
	}
	buf.WriteString(" ")

	// Message
	buf.WriteString(r.Message)

	// Source location (file:line) — only for debug level
	if r.Level == slog.LevelDebug {
		frame, _ := runtime.CallersFrames([]uintptr{r.PC}).Next()
		if frame.File != "" {
			buf.WriteString(" ")
			if h.color {
				buf.WriteString(colorGray)
			}
			buf.WriteString(fmt.Sprintf("(%s:%d)", trimPath(frame.File), frame.Line))
			if h.color {
				buf.WriteString(colorReset)
			}
		}
	}

	// Attrs from record
	r.Attrs(func(a slog.Attr) bool {
		buf.WriteString(" ")
		buf.WriteString(a.Key)
		buf.WriteString("=")
		buf.WriteString(fmt.Sprint(a.Value.Any()))
		return true
	})

	buf.WriteString("\n")

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write([]byte(buf.String()))
	return err
}

// WithAttrs returns a new handler with the given attributes added.
func (h *prettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs), len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	newAttrs = append(newAttrs, attrs...)
	return &prettyHandler{
		w:      h.w,
		color:  h.color,
		attrs:  newAttrs,
		groups: append([]string{}, h.groups...),
	}
}

// WithGroup returns a new handler with the given group name.
func (h *prettyHandler) WithGroup(name string) slog.Handler {
	newGroups := make([]string, len(h.groups), len(h.groups)+1)
	copy(newGroups, h.groups)
	newGroups = append(newGroups, name)
	return &prettyHandler{
		w:      h.w,
		color:  h.color,
		attrs:  append([]slog.Attr{}, h.attrs...),
		groups: newGroups,
	}
}

// trimPath strips the long GOPATH prefix from a file path for readability.
func trimPath(path string) string {
	// Keep only the last two path components (e.g., "ech-middle/main.go").
	idx := strings.LastIndex(path, "/")
	if idx >= 0 {
		prev := strings.LastIndex(path[:idx], "/")
		if prev >= 0 {
			return path[prev+1:]
		}
		return path[idx+1:]
	}
	return path
}
