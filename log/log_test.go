package log

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/flipcloud-ai/ezauth/config"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestLog(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Log Suite")
}

var _ = Describe("Log Package", func() {
	Describe("ServerContext and FromContext with server key", func() {
		It("stores and retrieves a server logger from context", func() {
			testLogger := NewLogger(context.Background(), config.LogConfig{})
			ctx := ServerContext(context.Background(), testLogger)
			retrieved := FromContext(ctx, "server")
			Expect(retrieved).To(Equal(testLogger))
		})

		It("returns nop logger when no server logger in context", func() {
			ctx := context.Background()
			retrieved := FromContext(ctx, "server")
			Expect(retrieved).NotTo(BeNil())
		})

		It("returns nop logger for server key when request logger is stored", func() {
			testLogger := NewLogger(context.Background(), config.LogConfig{})
			ctx := RequestContext(context.Background(), testLogger)
			retrieved := FromContext(ctx, "server")
			Expect(retrieved).NotTo(BeNil())
		})
	})

	Describe("RequestContext and FromContext with request key", func() {
		It("stores and retrieves a request logger from context", func() {
			testLogger := NewLogger(context.Background(), config.LogConfig{})
			ctx := RequestContext(context.Background(), testLogger)
			retrieved := FromContext(ctx, "request")
			Expect(retrieved).To(Equal(testLogger))
		})

		It("returns nop logger when no request logger in context", func() {
			ctx := context.Background()
			retrieved := FromContext(ctx, "request")
			Expect(retrieved).NotTo(BeNil())
		})

		It("returns nop logger for request key when server logger is stored", func() {
			testLogger := NewLogger(context.Background(), config.LogConfig{})
			ctx := ServerContext(context.Background(), testLogger)
			retrieved := FromContext(ctx, "request")
			Expect(retrieved).NotTo(BeNil())
		})
	})

	Describe("FromContext without key argument", func() {
		It("defaults to request logger", func() {
			testLogger := NewLogger(context.Background(), config.LogConfig{})
			ctx := RequestContext(context.Background(), testLogger)
			retrieved := FromContext(ctx)
			Expect(retrieved).To(Equal(testLogger))
		})
	})

	Describe("WithRequestID and RequestIDFromContext", func() {
		It("stores and retrieves request ID from context", func() {
			testID := "test-request-id-123"
			ctx := WithRequestID(context.Background(), testID)
			retrieved := RequestIDFromContext(ctx)
			Expect(retrieved).To(Equal(testID))
		})

		It("returns empty string when no request ID in context", func() {
			ctx := context.Background()
			retrieved := RequestIDFromContext(ctx)
			Expect(retrieved).To(Equal(""))
		})
	})

	Describe("With", func() {
		It("creates child logger with extra fields", func() {
			logger := NewLogger(context.Background(), config.LogConfig{})
			childLogger := logger.With(Str("custom", "field"))
			Expect(childLogger).NotTo(BeNil())
			Expect(childLogger.(*zapLogger).core()).NotTo(BeNil())
		})
	})

	Describe("HTTP request context integration", func() {
		It("stores server logger in HTTP request context", func() {
			testLogger := NewLogger(context.Background(), config.LogConfig{})
			req, _ := http.NewRequest("GET", "/test", nil)
			ctx := ServerContext(req.Context(), testLogger)
			req = req.WithContext(ctx)

			retrieved := FromContext(req.Context(), "server")
			Expect(retrieved).To(Equal(testLogger))
		})

		It("stores request logger in HTTP request context", func() {
			testLogger := NewLogger(context.Background(), config.LogConfig{})
			req, _ := http.NewRequest("GET", "/test", nil)
			ctx := RequestContext(req.Context(), testLogger)
			req = req.WithContext(ctx)

			retrieved := FromContext(req.Context(), "request")
			Expect(retrieved).To(Equal(testLogger))
		})

		It("stores request ID in HTTP request context", func() {
			testID := "http-request-id"
			req, _ := http.NewRequest("GET", "/test", nil)
			ctx := WithRequestID(req.Context(), testID)
			req = req.WithContext(ctx)

			retrieved := RequestIDFromContext(req.Context())
			Expect(retrieved).To(Equal(testID))
		})
	})

	Describe("ezapi request info integration", func() {
		It("works with ezapi request info flow", func() {
			testID := "middleware-test-id"

			reqInfo := &ezapi.AuthRequest{RequestID: testID}
			req, _ := http.NewRequest("GET", "/test", nil)
			req = ezapi.AddRequestInfo(req, reqInfo)

			reqLogger := NewLogger(context.Background(), config.LogConfig{}).With(Str("request_id", testID))
			ctx := ServerContext(req.Context(), reqLogger)
			ctx = WithRequestID(ctx, testID)
			req = req.WithContext(ctx)

			Expect(FromContext(req.Context(), "server")).NotTo(BeNil())
			Expect(RequestIDFromContext(req.Context())).To(Equal(testID))
		})
	})

	Describe("NewLogger", func() {
		It("creates logger with debug level", func() {
			cfg := config.LogConfig{Level: "debug"}
			logger := NewLogger(context.Background(), cfg)
			Expect(logger).NotTo(BeNil())
			Expect(logger.(*zapLogger).core()).NotTo(BeNil())
		})

		It("creates logger with info level", func() {
			cfg := config.LogConfig{Level: "info"}
			logger := NewLogger(context.Background(), cfg)
			Expect(logger).NotTo(BeNil())
		})

		It("creates logger with warn level", func() {
			cfg := config.LogConfig{Level: "warn"}
			logger := NewLogger(context.Background(), cfg)
			Expect(logger).NotTo(BeNil())
		})

		It("creates logger with error level", func() {
			cfg := config.LogConfig{Level: "error"}
			logger := NewLogger(context.Background(), cfg)
			Expect(logger).NotTo(BeNil())
		})

		It("creates logger with custom error syncer", func() {
			errorWriter := os.Stderr
			cfg := config.LogConfig{Level: "info"}
			logger := NewLogger(context.Background(), cfg, errorWriter)
			Expect(logger).NotTo(BeNil())
		})
	})

	Describe("NewLogger file logging", func() {
		It("writes error logs to error syncer file", func() {
			randomID := "test-" + string(rune('a'+time.Now().UnixNano()%26))
			tempDir := os.TempDir()
			errorFile := tempDir + "/error-" + randomID + ".log"
			stdoutFile := tempDir + "/stdout-" + randomID + ".log"

			stdoutWriter, _ := os.Create(stdoutFile)
			errorWriter, _ := os.Create(errorFile)

			cfg := config.LogConfig{Path: stdoutFile, Level: "info"}
			logger := NewLogger(context.Background(), cfg, errorWriter)
			Expect(logger).NotTo(BeNil())

			logger.Info("stdout-info-message")
			logger.Error("stderr-error-message")
			_ = logger.(*zapLogger).zap.Sync() // syncing /dev/stdout fails on Linux; ignore

			Expect(stdoutWriter.Close()).To(Succeed())
			Expect(errorWriter.Close()).To(Succeed())

			errorContent, err := os.ReadFile(errorFile)
			Expect(err).To(BeNil())
			Expect(string(errorContent)).To(ContainSubstring("stderr-error-message"))

			Expect(os.Remove(errorFile)).To(Succeed())
			Expect(os.Remove(stdoutFile)).To(Succeed())
		})
	})

	Describe("NewLogger stdout/stderr routing", func() {
		It("routes non-error messages (Debug, Info, Warn) to stdout only, not stderr", func() {
			// Capture stderr via a custom error syncer (a temp file).
			// Capture stdout by swapping os.Stdout with a pipe,
			// then restore after the test.
			randomID := "test-" + string(rune('a'+time.Now().UnixNano()%26))
			tempDir := os.TempDir()
			errorFile := tempDir + "/stderr-" + randomID + ".log"

			errorWriter, err := os.Create(errorFile)
			Expect(err).To(BeNil())
			defer func() {
				_ = errorWriter.Close()
				_ = os.Remove(errorFile)
			}()

			// Swap stdout with a pipe to capture what is written there.
			origStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			cfg := config.LogConfig{Level: "debug"}
			logger := NewLogger(context.Background(), cfg, errorWriter)

			logger.Debug("debug-message")
			logger.Info("info-message")
			logger.Warn("warn-message")

			// Need to sync so the pipe gets the bytes.
			_ = logger.(*zapLogger).zap.Sync()
			_ = w.Close()
			os.Stdout = origStdout

			stdoutBytes, _ := io.ReadAll(r)

			_ = errorWriter.Close()
			errorBytes, _ := os.ReadFile(errorFile)

			stdoutStr := string(stdoutBytes)
			errorStr := string(errorBytes)

			// Non-error messages must be on stdout
			Expect(stdoutStr).To(ContainSubstring("debug-message"))
			Expect(stdoutStr).To(ContainSubstring("info-message"))
			Expect(stdoutStr).To(ContainSubstring("warn-message"))

			// Non-error messages must NOT be on stderr
			Expect(errorStr).NotTo(ContainSubstring("debug-message"))
			Expect(errorStr).NotTo(ContainSubstring("info-message"))
			Expect(errorStr).NotTo(ContainSubstring("warn-message"))
		})

		It("routes error messages to stderr only, not stdout", func() {
			// Use an in-memory buffer so writes are synchronous — no fsync race.
			var errorBuf bytes.Buffer

			origStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			cfg := config.LogConfig{Level: "debug"}
			logger := NewLogger(context.Background(), cfg, &errorBuf)

			logger.Error("error-message")
			logger.Log(ErrorLevel, "error-level-message")

			_ = logger.(*zapLogger).zap.Sync()
			_ = w.Close()
			os.Stdout = origStdout

			stdoutBytes, _ := io.ReadAll(r)

			stdoutStr := string(stdoutBytes)
			errorStr := errorBuf.String()

			// Error messages must be on stderr
			Expect(errorStr).To(ContainSubstring("error-message"))
			Expect(errorStr).To(ContainSubstring("error-level-message"))

			// Error messages must NOT be on stdout
			Expect(stdoutStr).NotTo(ContainSubstring("error-message"))
			Expect(stdoutStr).NotTo(ContainSubstring("error-level-message"))
		})
	})

	Describe("StdLogger", func() {
		It("creates standard logger from zap logger", func() {
			logger := NewLogger(context.Background(), config.LogConfig{})
			stdLogger, err := StdLogger(logger, config.LogConfig{Level: "info"})
			Expect(err).To(BeNil())
			Expect(stdLogger).NotTo(BeNil())
		})
	})

	Describe("NewNop", func() {
		It("silently discards all log output", func() {
			nop := NewNop()

			nop.Debug("debug msg")
			nop.Info("info msg")
			nop.Warn("warn msg")
			nop.Error("error msg")
			nop.Log(InfoLevel, "log msg")

			Expect(nop.Zap()).NotTo(BeNil())
		})
	})

	Describe("Named", func() {
		It("creates named child logger", func() {
			logger := NewLogger(context.Background(), config.LogConfig{})
			named := logger.Named("subsystem")
			Expect(named).NotTo(BeNil())
			Expect(named.(*zapLogger).core()).NotTo(BeNil())
		})
	})

	Describe("New", func() {
		It("wraps an existing zap.Logger", func() {
			z := NewLogger(context.Background(), config.LogConfig{}).Zap()
			wrapped := New(z)
			Expect(wrapped).NotTo(BeNil())
			Expect(wrapped.Zap()).To(Equal(z))
		})
	})

	Describe("toZapLevel", func() {
		DescribeTable("converts levels correctly",
			func(level Level, expectedName string) {
				zapLevel := toZapLevel(level)
				Expect(zapLevel.String()).To(Equal(expectedName))
			},
			Entry("debug", DebugLevel, "debug"),
			Entry("info", InfoLevel, "info"),
			Entry("warn", WarnLevel, "warn"),
			Entry("error", ErrorLevel, "error"),
			Entry("panic", PanicLevel, "panic"),
			Entry("unknown defaults to info", Level(99), "info"),
		)
	})

	Describe("parseLogLevel", func() {
		It("defaults to info for unknown level", func() {
			level := parseLogLevel(config.LogConfig{Level: "unknown"})
			Expect(level.String()).To(Equal("info"))
		})
		It("parses panic level", func() {
			level := parseLogLevel(config.LogConfig{Level: "panic"})
			Expect(level.String()).To(Equal("panic"))
		})
	})

	Describe("NewLogger console format", func() {
		It("creates logger with console format", func() {
			cfg := config.LogConfig{Level: "info", Format: "console"}
			logger := NewLogger(context.Background(), cfg)
			Expect(logger).NotTo(BeNil())
			Expect(logger.(*zapLogger).core()).NotTo(BeNil())
		})
	})
})
