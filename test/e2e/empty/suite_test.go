//go:build e2e

package empty_test

import (
	"testing"
	"time"

	"github.com/flipcloud-ai/ezauth/test/e2e/shared"
	e2eutils "github.com/flipcloud-ai/ezauth/test/e2e/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	env     *e2eutils.TestEnv
	csrfEnv *e2eutils.TestEnv
)

func TestEmpty(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Empty Suite")
}

var _ = BeforeSuite(func() {
	opts := shared.EmptyConfig()
	env = e2eutils.StartServer(opts, "empty", 10*time.Second)
	csrfEnv = e2eutils.StartServer(shared.WithCSRF(shared.EmptyConfig()), "empty-csrf", 10*time.Second)
})

var _ = AfterSuite(func() {
	if env != nil {
		env.Stop()
	}
	if csrfEnv != nil {
		csrfEnv.Stop()
	}
})

var _ = Describe("Empty config (CSRF disabled)", func() {
	Describe("Health", func() {
		shared.HealthBehaviors(func() *e2eutils.TestEnv { return env })
	})
	Describe("Session", func() {
		shared.SessionBehaviors(func() *e2eutils.TestEnv { return env })
	})
	Describe("Error pages", func() {
		shared.ErrorPageBehaviors(func() *e2eutils.TestEnv { return env })
	})
	Describe("CSRF disabled", func() {
		shared.CSRFBehaviors(func() *e2eutils.TestEnv { return env }, false)
	})
	Describe("Rate limit disabled", func() {
		shared.RateLimitBehaviors(func() *e2eutils.TestEnv { return env }, 0)
	})
})

var _ = Describe("Empty config (CSRF enabled, no TLS)", func() {
	Describe("CSRF enforced", func() {
		shared.CSRFBehaviors(func() *e2eutils.TestEnv { return csrfEnv }, true)
	})
})
