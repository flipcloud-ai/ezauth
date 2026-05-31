//go:build e2e

package standard_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/flipcloud-ai/ezauth/test/e2e/shared"
	e2eutils "github.com/flipcloud-ai/ezauth/test/e2e/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Dead upstream recovery", Ordered, func() {
	var deadEnv *e2eutils.TestEnv

	BeforeAll(func() {
		if e2eutils.ClusterMode() {
			Skip("recovery tests require a local server")
		}
		opts := shared.EmptyConfig()
		opts = shared.WithMemoryCache(opts, "10m")
		opts = shared.WithTLS(opts)
		opts = shared.WithStaticUser(opts, "test", "test1234")
		deadURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", e2eutils.FreePort()))
		Expect(err).ToNot(HaveOccurred())
		opts.Server.Upstream = deadURL
		deadEnv = e2eutils.StartServer(opts, "standard-recovery", 10*time.Second)
	})

	AfterAll(func() {
		if deadEnv != nil {
			deadEnv.Stop()
		}
	})

	It("should return 502 when upstream is unreachable", func() {
		c := e2eutils.LoginAs(deadEnv, "test", "test1234")
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, deadEnv.URL+"/", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		resp, err := c.Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusBadGateway))
	})

	It("should still return 200 for /healthz when upstream is unreachable", func() {
		resp, err := e2eutils.Client(deadEnv).Get(deadEnv.URL + "/healthz")
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
	})
})
