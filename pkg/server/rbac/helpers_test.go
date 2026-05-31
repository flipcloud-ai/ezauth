package rbac

import (
	"regexp"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func resetPathPatternCache() {
	c, _ := lru.New[string, *regexp.Regexp](pathPatternCacheSize)
	pathPatternCache = c
}

var _ = Describe("matchPath", func() {
	DescribeTable("matches path against pattern",
		func(path, pattern string, want bool) {
			got := matchPath(normalizePath(path), pattern)
			Expect(got).To(Equal(want))
		},
		Entry("exact match", "/admin/users", "/admin/users", true),
		Entry("exact mismatch", "/admin/users", "/admin/roles", false),

		Entry("path trailing slash", "/admin/users/", "/admin/users", true),
		Entry("pattern trailing slash", "/admin/users", "/admin/users/", true),
		Entry("both trailing slashes", "/admin/users/", "/admin/users/", true),

		Entry("template matches literal", "/admin/users/u1", "/admin/users/{id}", true),
		Entry("template does not match multi-segment", "/admin/users/u1/sub", "/admin/users/{id}", false),
		Entry("template matches template", "/admin/users/{id}", "/admin/users/{id}", true),
		Entry("empty template segment rejected", "/admin/users/", "/admin/users/{id}", false),

		Entry("wildcard matches subpath", "/admin/users/u1/roles", "/admin/*", true),
		Entry("wildcard matches direct child", "/admin/users", "/admin/*", true),
		Entry("wildcard matches deep", "/admin/a/b/c/d", "/admin/*", true),
		Entry("wildcard no match outside prefix", "/user/u1", "/admin/*", false),

		Entry("dot not regex wildcard", "/api/vX/users", "/api/v.0/users", false),
		Entry("dot literal match", "/api/v.0/users", "/api/v.0/users", true),
		Entry("plus literal", "/a+b/x", "/a+b/x", true),
		Entry("parens literal", "/(v1)/x", "/(v1)/x", true),
		Entry("question literal", "/v?/x", "/v?/x", true),

		Entry("anchoring: longer path rejected", "/admin/users-secret", "/admin/users", false),
		Entry("anchoring: extra prefix rejected", "x/admin/users", "/admin/users", false),
		Entry("anchoring: extra suffix rejected", "/admin/users/extra", "/admin/users", false),

		Entry("root pattern", "/", "/", true),
		Entry("root wildcard", "/anything", "/*", true),

		Entry("template then wildcard", "/admin/users/u1/roles/r1", "/admin/users/{id}/*", true),
		Entry("template then wildcard no extra", "/admin/users/u1", "/admin/users/{id}/*", false),
	)

	It("handles invalid pattern with unbalanced regex metachar", func() {
		bad := "/admin/[unclosed"
		Expect(matchPath("/admin/other", bad)).To(BeFalse())
		Expect(matchPath("/admin/[unclosed", bad)).To(BeTrue())
	})

	It("does not expand regex metacharacters in pattern", func() {
		Expect(matchPath("/admin/other", "/admin/.*")).To(BeFalse())
		Expect(matchPath("/admin/.*", "/admin/.*")).To(BeTrue())
		Expect(matchPath("prefix/admin/.*", "/admin/.*")).To(BeFalse())
	})
})

var _ = Describe("matchMethod", func() {
	DescribeTable("matches method against pattern",
		func(method, pattern string, want bool) {
			Expect(matchMethod(method, pattern)).To(Equal(want))
		},
		Entry("exact GET", "GET", "GET", true),
		Entry("case insensitive lower", "get", "GET", true),
		Entry("case insensitive upper", "GET", "get", true),
		Entry("mismatch", "GET", "POST", false),
		Entry("star wildcard", "GET", "*", true),
		Entry("ALL wildcard", "POST", "ALL", true),
		Entry("all wildcard lower", "PATCH", "all", true),
		Entry("empty method", "GET", "", false),
		Entry("empty pattern", "", "GET", false),
	)
})

var _ = Describe("normalizePath", func() {
	DescribeTable("strips trailing slashes",
		func(in, want string) {
			Expect(normalizePath(in)).To(Equal(want))
		},
		Entry("root", "/", "/"),
		Entry("empty", "", ""),
		Entry("no trailing slash", "/admin", "/admin"),
		Entry("trailing slash", "/admin/", "/admin"),
		Entry("nested trailing slash", "/admin/users/", "/admin/users"),
		Entry("double slash", "//", "/"),
	)
})

var _ = Describe("pathPatternCache", func() {
	It("caches compiled patterns after matchPath", func() {
		resetPathPatternCache()
		pattern := "/admin/cache-probe/{id}"
		_ = matchPath("/admin/cache-probe/x", pattern)
		_, ok := pathPatternCache.Get(normalizePath(pattern))
		Expect(ok).To(BeTrue())
	})

	It("is safe for concurrent access", func() {
		resetPathPatternCache()
		pattern := "/admin/concurrent/{id}"

		var wg sync.WaitGroup
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 100; j++ {
					_ = matchPath("/admin/concurrent/x", pattern)
				}
			}()
		}
		wg.Wait()
	})
})
