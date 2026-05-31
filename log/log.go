package log

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
)

// contextKey is used for storing values in context.
type contextKey string

// Context keys for storing loggers and request IDs.
const (
	ServerLoggerKey = contextKey("ezauth-server-logger")
	LoggerKey       = contextKey("ezauth-request-logger")
	RequestIDKey    = contextKey("ezauth-request-id")
)

// Level represents a log severity level. The numeric values are chosen to be
// compatible with zapcore.Level for the common levels: Debug=-1, Info=0,
// Warn=1, Error=2. PanicLevel (3) does not match zap's PanicLevel (4) since
// we omit the intermediate DPanic level.
type Level int

// Log severity level constants. Numeric values are compatible with zapcore.Level
// for Debug/Info/Warn/Error; PanicLevel maps to zapcore.PanicLevel.
const (
	DebugLevel Level = iota - 1 // -1
	InfoLevel                   // 0
	WarnLevel                   // 1
	ErrorLevel                  // 2
	PanicLevel                  // 3
)

// Field is a type alias for zap.Field. This means Field and zap.Field are
// the same type — zero-cost interop without conversion.
type Field = zap.Field

// Re-exported field constructors for convenience, so callers do not need to
// import go.uber.org/zap directly for common field types.
var (
	Str      = zap.String
	Int      = zap.Int
	Int64    = zap.Int64
	Err      = zap.Error
	Any      = zap.Any
	Bool     = zap.Bool
	Float64  = zap.Float64
	Strings  = zap.Strings
	Time     = zap.Time
	Duration = zap.Duration
)

// Logger is the interface that wraps the basic logging methods.
//
// Implementations may extend the underlying logger with additional fields
// (With), or return the underlying *zap.Logger (Zap) for integration with
// zap-native APIs.
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	Log(level Level, msg string, fields ...Field)
	With(fields ...Field) Logger
	Named(name string) Logger
	Zap() *zap.Logger
}

// zapLogger wraps a *zap.Logger and implements the Logger interface.
type zapLogger struct {
	zap *zap.Logger
}

func (l *zapLogger) Debug(msg string, fields ...Field) {
	l.zap.Debug(msg, fields...)
}

func (l *zapLogger) Info(msg string, fields ...Field) {
	l.zap.Info(msg, fields...)
}

func (l *zapLogger) Warn(msg string, fields ...Field) {
	l.zap.Warn(msg, fields...)
}

func (l *zapLogger) Error(msg string, fields ...Field) {
	l.zap.Error(msg, fields...)
}

func (l *zapLogger) Log(level Level, msg string, fields ...Field) {
	l.zap.Log(toZapLevel(level), msg, fields...)
}

func (l *zapLogger) With(fields ...Field) Logger {
	return &zapLogger{zap: l.zap.With(fields...)}
}

func (l *zapLogger) Named(name string) Logger {
	return &zapLogger{zap: l.zap.Named(name)}
}

func (l *zapLogger) Zap() *zap.Logger {
	return l.zap
}

// core returns the underlying zapcore.Core. Exposed for in-package tests.
func (l *zapLogger) core() zapcore.Core {
	return l.zap.Core()
}

// toZapLevel converts our Level to the corresponding zapcore.Level.
// We cannot use a direct cast because our PanicLevel (3) maps to
// zapcore.DPanicLevel (3), not zapcore.PanicLevel (4), since we omit the
// intermediate DPanic level from our iota.
func toZapLevel(level Level) zapcore.Level {
	switch level {
	case DebugLevel:
		return zapcore.DebugLevel
	case InfoLevel:
		return zapcore.InfoLevel
	case WarnLevel:
		return zapcore.WarnLevel
	case ErrorLevel:
		return zapcore.ErrorLevel
	case PanicLevel:
		return zapcore.PanicLevel
	default:
		return zapcore.InfoLevel
	}
}

// NewNop returns a Logger that discards all log output. It is the interface
// equivalent of zap.NewNop().
func NewNop() Logger {
	return &zapLogger{zap: zap.NewNop()}
}

// New wraps an existing *zap.Logger into a Logger. Useful when the caller
// already has a *zap.Logger (e.g. from test capture infrastructure) and needs
// it to satisfy the Logger interface.
func New(z *zap.Logger) Logger {
	return &zapLogger{zap: z}
}

// ServerContext stores a Logger in the given context under the server key.
func ServerContext(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, ServerLoggerKey, logger)
}

// RequestContext stores a Logger in the given context under the request key.
func RequestContext(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, LoggerKey, logger)
}

// FromContext retrieves the Logger stored in the context. It accepts an
// optional key argument: "server" to look up the server logger, or "request"
// (or omitted) to look up the request logger.
//
// If no logger is found, FromContext returns a Nop logger so callers never
// need nil guards.
func FromContext(ctx context.Context, key ...string) Logger {
	k := LoggerKey
	if len(key) > 0 {
		switch key[0] {
		case "server":
			k = ServerLoggerKey
		case "request":
			k = LoggerKey
		}
	}
	if logger, ok := ctx.Value(k).(Logger); ok {
		return logger
	}
	return NewNop()
}

// WithRequestID stores a request ID in the given context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, RequestIDKey, id)
}

// RequestIDFromContext retrieves the request ID stored in the context.
// Returns an empty string if no request ID is present.
func RequestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(RequestIDKey).(string); ok {
		return id
	}
	return ""
}

// StdLogger creates a standard library *log.Logger from the given Logger and
// config. The log level from cfg is used to determine which zap level
// triggers the standard logger output.
func StdLogger(logger Logger, cfg ezcfg.LogConfig) (*log.Logger, error) {
	l, err := zap.NewStdLogAt(logger.Zap(), parseLogLevel(cfg))
	if err != nil {
		return nil, fmt.Errorf("create std logger: %w", err)
	}
	return l, nil
}

// NewLogger creates and returns a new Logger with the given config. It names
// the underlying logger "ezauth". Non-error messages (Debug, Info, Warn) go to
// stdout; Error, Panic and Fatal go to stderr. When cfg.Path is set, all
// messages are also written to the log file.
func NewLogger(ctx context.Context, cfg ezcfg.LogConfig, errorSyncers ...io.Writer) Logger {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	var encoder zapcore.Encoder
	if strings.ToLower(cfg.Format) == "console" {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	} else {
		encoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	baseLevel := parseLogLevel(cfg)

	stdoutSyncer := zapcore.AddSync(os.Stdout)
	var stderrSyncer zapcore.WriteSyncer
	if len(errorSyncers) > 0 {
		var extraSyncers []zapcore.WriteSyncer
		for _, s := range errorSyncers {
			extraSyncers = append(extraSyncers, zapcore.AddSync(s))
		}
		extraSyncers = append(extraSyncers, zapcore.AddSync(os.Stderr))
		stderrSyncer = zapcore.NewMultiWriteSyncer(extraSyncers...)
	} else {
		stderrSyncer = zapcore.AddSync(os.Stderr)
	}

	var fileSyncer zapcore.WriteSyncer
	if cfg.Path != "" {
		fileSyncer = zapcore.AddSync(&lumberjack.Logger{
			Filename:   cfg.Path,
			MaxSize:    1024,
			MaxBackups: 5,
			MaxAge:     30,
			Compress:   false,
		})
	}

	core := &routingCore{
		encoder:      encoder,
		stdoutSyncer: stdoutSyncer,
		stderrSyncer: stderrSyncer,
		fileSyncer:   fileSyncer,
		minLevel:     baseLevel,
	}

	logger := zap.New(core, zap.AddCaller())
	logger = logger.Named("ezauth")
	return &zapLogger{zap: logger}
}

// routingCore is a zapcore.Core that routes log entries to stdout (non-error)
// or stderr (error+) based on level, with an optional shared file output.
type routingCore struct {
	encoder      zapcore.Encoder
	stdoutSyncer zapcore.WriteSyncer
	stderrSyncer zapcore.WriteSyncer
	fileSyncer   zapcore.WriteSyncer
	minLevel     zapcore.Level
}

func (c *routingCore) Enabled(level zapcore.Level) bool {
	return level >= c.minLevel
}

func (c *routingCore) With(fields []zapcore.Field) zapcore.Core {
	return &routingCore{
		encoder:      c.encoder.Clone(),
		stdoutSyncer: c.stdoutSyncer,
		stderrSyncer: c.stderrSyncer,
		fileSyncer:   c.fileSyncer,
		minLevel:     c.minLevel,
	}
}

func (c *routingCore) Check(entry zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return ce.AddCore(entry, c)
	}
	return ce
}

func (c *routingCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	buf, err := c.encoder.EncodeEntry(entry, fields)
	if err != nil {
		return fmt.Errorf("encode log entry: %w", err)
	}
	defer buf.Free()

	bytes := buf.Bytes()

	if entry.Level >= zapcore.ErrorLevel {
		if _, err := c.stderrSyncer.Write(bytes); err != nil {
			return fmt.Errorf("write to stderr: %w", err)
		}
	} else {
		if _, err := c.stdoutSyncer.Write(bytes); err != nil {
			return fmt.Errorf("write to stdout: %w", err)
		}
	}

	if c.fileSyncer != nil {
		if _, err := c.fileSyncer.Write(bytes); err != nil {
			return fmt.Errorf("write to file: %w", err)
		}
	}

	return nil
}

func (c *routingCore) Sync() error {
	var errs []error
	if err := c.stdoutSyncer.Sync(); err != nil {
		errs = append(errs, err)
	}
	if err := c.stderrSyncer.Sync(); err != nil {
		errs = append(errs, err)
	}
	if c.fileSyncer != nil {
		if err := c.fileSyncer.Sync(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// parseLogLevel converts a LogConfig's string level to a zapcore.Level.
// It defaults to InfoLevel when the string is unrecognized.
func parseLogLevel(cfg ezcfg.LogConfig) zapcore.Level {
	logLevel := zapcore.InfoLevel
	switch strings.ToLower(cfg.Level) {
	case "debug":
		logLevel = zapcore.DebugLevel
	case "warn":
		logLevel = zapcore.WarnLevel
	case "error":
		logLevel = zapcore.ErrorLevel
	case "panic":
		logLevel = zapcore.PanicLevel
	}
	return logLevel
}
