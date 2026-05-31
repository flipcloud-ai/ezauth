package config_test

import (
	"context"
	"testing"

	"github.com/flipcloud-ai/ezauth/config"
	"github.com/flipcloud-ai/ezauth/log"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMainSuite(t *testing.T) {
	log.NewLogger(context.Background(), config.LogConfig{}, GinkgoWriter, GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Config test")
}
