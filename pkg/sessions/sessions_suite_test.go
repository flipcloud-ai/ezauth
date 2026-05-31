package sessions_test

import (
	"context"
	"testing"

	"github.com/flipcloud-ai/ezauth/config"
	"github.com/flipcloud-ai/ezauth/log"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSessions(t *testing.T) {
	log.NewLogger(context.Background(), config.LogConfig{}, GinkgoWriter, GinkgoWriter)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sessions Suite")
}
