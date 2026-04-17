package main

import (
	"context"
	"io"
	"log/slog"
	"os"

	"github.com/bodsink/dns-rpz/config"
)

// multiHandler writes log records to two slog.Handler targets simultaneously.
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

func newFileHandler(f *os.File, format string, opts *slog.HandlerOptions) slog.Handler {
	var w io.Writer = f
	if format == "json" {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

func newLogger(cfg config.LogConfig) (*slog.Logger, *slog.LevelVar) {
	levelVar := &slog.LevelVar{}
	switch cfg.Level {
	case "debug":
		levelVar.Set(slog.LevelDebug)
	case "warn":
		levelVar.Set(slog.LevelWarn)
	case "error":
		levelVar.Set(slog.LevelError)
	default:
		levelVar.Set(slog.LevelInfo)
	}

	opts := &slog.HandlerOptions{Level: levelVar}

	var handler slog.Handler
	if cfg.Format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	if cfg.File && cfg.FilePath != "" {
		f, err := os.OpenFile(cfg.FilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err == nil {
			handler = &multiHandler{
				stdout: handler,
				file:   newFileHandler(f, cfg.Format, opts),
			}
		}
	}

	return slog.New(handler), levelVar
}

func parseLevelVar(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
