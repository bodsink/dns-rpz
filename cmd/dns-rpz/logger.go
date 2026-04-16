package main

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// multiHandler writes log records to two slog.Handler targets simultaneously.
// Used to tee logs to both stdout and a file.
type multiHandler struct {
	stdout slog.Handler
	file   slog.Handler
}

func (m *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return m.stdout.Enabled(ctx, level) || m.file.Enabled(ctx, level)
}

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	if err := m.stdout.Handle(ctx, r.Clone()); err != nil {
		return err
	}
	return m.file.Handle(ctx, r)
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &multiHandler{
		stdout: m.stdout.WithAttrs(attrs),
		file:   m.file.WithAttrs(attrs),
	}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	return &multiHandler{
		stdout: m.stdout.WithGroup(name),
		file:   m.file.WithGroup(name),
	}
}

// newFileHandler creates a slog.Handler that writes to the given file.
func newFileHandler(f *os.File, format string, opts *slog.HandlerOptions) slog.Handler {
	var w io.Writer = f
	if format == "json" {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}
