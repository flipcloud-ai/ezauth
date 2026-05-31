package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/flipcloud-ai/ezauth/config"
	"github.com/flipcloud-ai/ezauth/log"
	"github.com/flipcloud-ai/ezauth/pkg/server"
	ezsecret "github.com/flipcloud-ai/ezauth/pkg/server/secret"
)

// StartWithContext starts the EzAuth server with the provided context and options.
func StartWithContext(ctx context.Context, opts config.Options) error {
	logger := log.NewLogger(ctx, opts.Log)
	driver := ezsecret.New(logger, ezsecret.DefaultSecretsDir)
	if err := driver.Resolve(&opts); err != nil {
		return err
	}
	s := &server.Server{
		ServeCfg: opts.Server,
		Logger:   logger,
	}
	ctx = log.ServerContext(ctx, s.Logger)

	return s.Start(ctx, opts)
}

// Start starts the EzAuth server with a cancelable context that listens for OS signals.
func Start(opts config.Options) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigint)

	go func() {
		select {
		case <-sigint:
			cancel()
		case <-ctx.Done():
		}
	}()

	return StartWithContext(ctx, opts)
}
