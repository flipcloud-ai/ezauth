package utils

import (
	"net/http"
	"net/url"
	"sync"

	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Validation functions", func() {
	Describe("IsValidName", func() {
		DescribeTable("valid names",
			func(name string, digit int) {
				Expect(IsValidName(name, digit)).To(BeTrue())
			},
			Entry("ascii with digit 16", "abc", 16),
			Entry("ascii with digit 32", "my-service", 32),
			Entry("ascii with digit 64", "provider-name", 64),
			Entry("dots and colons", "a.b:c", 16),
			Entry("digits in name", "svc01", 16),
			Entry("unicode letters", "认证服务", 32),
			Entry("unicode with digit 64", "データ-service", 64),
			Entry("single char", "a", 16),
			Entry("exactly at limit 16", "1234567890123456", 16),
			Entry("exactly at limit 32", "12345678901234567890123456789012", 32),
		)

		DescribeTable("invalid names",
			func(name string, digit int) {
				Expect(IsValidName(name, digit)).To(BeFalse())
			},
			Entry("empty string", "", 16),
			Entry("contains space", "my name", 32),
			Entry("exceeds digit 16", "12345678901234567", 16),
			Entry("exceeds digit 32", "123456789012345678901234567890123", 32),
			Entry("special char bang", "a!b", 16),
			Entry("special char slash", "a/b", 32),
		)

		DescribeTable("boundary digit values",
			func(name string, digit int, wantValid bool) {
				Expect(IsValidName(name, digit)).To(Equal(wantValid))
			},
			Entry("digit 0 is invalid", "ok", 0, false),
			Entry("digit -1 is invalid", "ok", -1, false),
			Entry("digit 129 exceeds maxNameLength", "ok", 129, false),
			Entry("digit 1 accepts single char", "a", 1, true),
			Entry("digit 1 rejects two chars", "ok", 1, false),
			Entry("digit 128 accepts long name", "ok", 128, true),
		)

		It("should use default digit 16 when no digit is provided", func() {
			Expect(IsValidName("short")).To(BeTrue())
			Expect(IsValidName("12345678901234567")).To(BeFalse())
		})

		It("should fall back to dynamic compilation for non-standard digit values", func() {
			Expect(IsValidName("abc", 8)).To(BeTrue())
			Expect(IsValidName("123456789", 8)).To(BeFalse())
		})
	})

	Describe("IsValidPermissionName", func() {
		DescribeTable("valid permission names",
			func(name string) {
				Expect(IsValidPermissionName(name, 32)).To(BeTrue())
			},
			Entry("simple ascii", "read"),
			Entry("with wildcard", "auth::*"),
			Entry("with dots", "svc.read"),
			Entry("unicode", "读取"),
		)

		DescribeTable("invalid permission names",
			func(name string) {
				Expect(IsValidPermissionName(name, 32)).To(BeFalse())
			},
			Entry("empty string", ""),
			Entry("with space", "read write"),
			Entry("exceeds 32 chars", "123456789012345678901234567890123"),
		)

		It("should accept a short name when no digit is provided (defaults to 16, hits fallback path)", func() {
			Expect(IsValidPermissionName("read")).To(BeTrue())
		})

		It("should return false for invalid digit out of range", func() {
			Expect(IsValidPermissionName("read", 0)).To(BeFalse())
			Expect(IsValidPermissionName("read", 129)).To(BeFalse())
		})

		It("should fall back to dynamic compilation for non-standard digit values", func() {
			Expect(IsValidPermissionName("abc", 8)).To(BeTrue())
			Expect(IsValidPermissionName("123456789", 8)).To(BeFalse())
		})
	})

	Describe("IsValidUsername", func() {
		DescribeTable("valid usernames",
			func(username string) {
				Expect(IsValidUsername(username)).To(BeTrue())
			},
			Entry("simple username", "alice"),
			Entry("with dot", "alice.bob"),
			Entry("with hyphen", "alice-bob"),
			Entry("with underscore", "alice_bob"),
			Entry("phone number", "+12025551234"),
			Entry("email address", "alice@example.com"),
			Entry("min length 4", "abcd"),
			Entry("max length 20", "12345678901234567890"),
		)

		DescribeTable("invalid usernames",
			func(username string) {
				Expect(IsValidUsername(username)).To(BeFalse())
			},
			Entry("with space", "alice bob"),
			Entry("too short", "ab"),
			Entry("starts with dot", ".alice"),
			Entry("ends with dot", "alice."),
			Entry("double dot", "alice..bob"),
			Entry("double hyphen", "alice--bob"),
			Entry("too long 21 chars", "123456789012345678901"),
			Entry("empty string", ""),
		)

		It("should be concurrent-safe using the pre-compiled regexp2 usernameRe", func() {
			// This test is only meaningful when run with -race (ginkgo --race).
			const goroutines = 50
			var wg sync.WaitGroup
			wg.Add(goroutines)

			type result struct {
				input string
				got   bool
				want  bool
			}
			results := make([]result, goroutines)

			cases := []struct {
				input string
				want  bool
			}{
				{"alice", true},
				{"ab", false},
				{".start", false},
				{"alice.bob", true},
				{"alice--bob", false},
				{"validuser1", true},
			}

			for i := range goroutines {
				c := cases[i%len(cases)]
				go func() {
					defer wg.Done()
					results[i] = result{
						input: c.input,
						got:   IsValidUsername(c.input),
						want:  c.want,
					}
				}()
			}
			wg.Wait()

			for _, r := range results {
				Expect(r.got).To(Equal(r.want), "IsValidUsername(%q)", r.input)
			}
		})
	})

	Describe("IsValidPassword", func() {
		DescribeTable("valid passwords",
			func(password string) {
				Expect(IsValidPassword(password)).To(BeTrue())
			},
			Entry("mixed case and digit", "Password1"),
			Entry("with special chars", "P@ssw0rd!"),
			Entry("longer password", "MySecurePass123"),
		)

		DescribeTable("invalid passwords",
			func(password string) {
				Expect(IsValidPassword(password)).To(BeFalse())
			},
			Entry("too short", "Pw1"),
			Entry("no uppercase", "password1"),
			Entry("no lowercase", "PASSWORD1"),
			Entry("no digit", "Password"),
			Entry("empty string", ""),
			Entry("disallowed special char", "Password1 "),
		)

		It("should be concurrent-safe using the pre-compiled regexp2 passwordRe", func() {
			// This test is only meaningful when run with -race (ginkgo --race).
			const goroutines = 50
			var wg sync.WaitGroup
			wg.Add(goroutines)

			type result struct {
				input string
				got   bool
				want  bool
			}
			results := make([]result, goroutines)

			cases := []struct {
				input string
				want  bool
			}{
				{"Password1", true},
				{"password1", false},
				{"PASSWORD1", false},
				{"Pw1", false},
				{"MySecurePass123", true},
			}

			for i := range goroutines {
				c := cases[i%len(cases)]
				go func() {
					defer wg.Done()
					results[i] = result{
						input: c.input,
						got:   IsValidPassword(c.input),
						want:  c.want,
					}
				}()
			}
			wg.Wait()

			for _, r := range results {
				Expect(r.got).To(Equal(r.want), "IsValidPassword(%q)", r.input)
			}
		})
	})

	Describe("IsValidPhoneNumber", func() {
		DescribeTable("valid phone numbers",
			func(phone string) {
				Expect(IsValidPhoneNumber(phone)).To(BeTrue())
			},
			Entry("US number", "+12025551234"),
			Entry("UK number", "+447911123456"),
			Entry("short number", "+1212"),
		)

		DescribeTable("invalid phone numbers",
			func(phone string) {
				Expect(IsValidPhoneNumber(phone)).To(BeFalse())
			},
			Entry("no plus prefix", "12025551234"),
			Entry("starts with +0", "+0555123456"),
			Entry("empty string", ""),
			Entry("letters", "+1abc"),
			Entry("too long", "+123456789012345678"),
		)
	})

	Describe("IsValidPath", func() {
		DescribeTable("mux template paths",
			func(path string, wantValid bool) {
				Expect(IsValidPath(path)).To(Equal(wantValid))
			},
			Entry("simple template", "/users/{uid}", true),
			Entry("template with regexp", "/users/{uid:[0-9]+}", true),
			Entry("template with query string", "/users/{uid}?q=1", false),
		)
	})

	Describe("DecodeState", func() {
		It("should return error when state has no colon separator", func() {
			_, _, err := DecodeState("nocolonatall")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid state format"))
		})

		It("should round-trip EncodeState/DecodeState with simple values", func() {
			code := "mystate"
			params := url.Values{"nonce": {"abc123"}}
			encoded := EncodeState(code, params)
			Expect(encoded).NotTo(BeEmpty())

			gotCode, gotMap, err := DecodeState(encoded)
			Expect(err).ToNot(HaveOccurred())
			Expect(gotCode).To(Equal(code))
			Expect(gotMap.Get("nonce")).To(Equal("abc123"))
		})

		It("should round-trip EncodeState/DecodeState with absolute URL redirect", func() {
			code := "abc12345"
			params := url.Values{
				"app_redirect": {"https://app.example.com:8080/path?foo=bar"},
				"provider":     {"myoidc"},
			}
			encoded := EncodeState(code, params)

			gotCode, gotMap, err := DecodeState(encoded)
			Expect(err).ToNot(HaveOccurred())
			Expect(gotCode).To(Equal(code))
			Expect(gotMap.Get("app_redirect")).To(Equal("https://app.example.com:8080/path?foo=bar"))
			Expect(gotMap.Get("provider")).To(Equal("myoidc"))
		})
	})

	Describe("IsValidEmail", func() {
		DescribeTable("valid emails",
			func(email string) {
				Expect(IsValidEmail(email)).To(BeTrue())
			},
			Entry("simple", "user@example.com"),
			Entry("with display name", "User <user@example.com>"),
			Entry("subdomain", "user@mail.example.co.uk"),
		)
		DescribeTable("invalid emails",
			func(email string) {
				Expect(IsValidEmail(email)).To(BeFalse())
			},
			Entry("no at sign", "notanemail"),
			Entry("empty", ""),
		)
	})

	Describe("Getenv", func() {
		It("should return default when env is not set", func() {
			Expect(Getenv("__XW_NOTSET_VAR__", "default")).To(Equal("default"))
		})

		It("should return env value when set", func() {
			GinkgoT().Setenv("__XW_TEST_VAR__", "hello")
			Expect(Getenv("__XW_TEST_VAR__", "default")).To(Equal("hello"))
		})
	})

	Describe("GetRequestProto / GetRequestHost / IsProxied", func() {
		It("should return URL scheme when not proxied", func() {
			req, _ := http.NewRequest("GET", "https://example.com/path", nil)
			req.Header.Set("X-Forwarded-Proto", "http")
			req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{TrustForwardedHeaders: false})
			Expect(GetRequestProto(req)).To(Equal("https"))
		})

		It("should return X-Forwarded-Proto when proxied", func() {
			req, _ := http.NewRequest("GET", "https://example.com/path", nil)
			req.Header.Set("X-Forwarded-Proto", "http")
			req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{TrustForwardedHeaders: true})
			Expect(GetRequestProto(req)).To(Equal("http"))
		})

		It("should return URL scheme when proxied but header empty", func() {
			req, _ := http.NewRequest("GET", "https://example.com/path", nil)
			req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{TrustForwardedHeaders: true})
			Expect(GetRequestProto(req)).To(Equal("https"))
		})

		It("should return req.Host when not proxied", func() {
			req, _ := http.NewRequest("GET", "http://example.com/", nil)
			req.Header.Set("X-Forwarded-Host", "other.com")
			req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{TrustForwardedHeaders: false})
			Expect(GetRequestHost(req)).To(Equal("example.com"))
		})

		It("should return X-Forwarded-Host when proxied", func() {
			req, _ := http.NewRequest("GET", "http://example.com/", nil)
			req.Header.Set("X-Forwarded-Host", "other.com")
			req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{TrustForwardedHeaders: true})
			Expect(GetRequestHost(req)).To(Equal("other.com"))
		})

		It("IsProxied returns false when reqInfo is nil", func() {
			req, _ := http.NewRequest("GET", "http://example.com/", nil)
			// No AuthRequest added → GetRequest returns zero value
			Expect(IsProxied(req)).To(BeFalse())
		})
	})
})

var _ = Describe("Random ID generators", func() {
	Describe("NewRandomUUID", func() {
		It("should return a valid UUID v4 string", func() {
			id, err := NewRandomUUID()
			Expect(err).ToNot(HaveOccurred())
			Expect(id).To(MatchRegexp(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`))
		})

		It("should return different values on subsequent calls", func() {
			id1, _ := NewRandomUUID()
			id2, _ := NewRandomUUID()
			Expect(id1).NotTo(Equal(id2))
		})
	})

	Describe("NewRandomXID", func() {
		It("should return a non-empty XID string", func() {
			Expect(NewRandomXID()).NotTo(BeEmpty())
		})

		It("should return different values on subsequent calls", func() {
			Expect(NewRandomXID()).NotTo(Equal(NewRandomXID()))
		})
	})

	Describe("NewRandomString", func() {
		DescribeTable("length and charset",
			func(n int, wantLen int, wantEmpty bool) {
				s, err := NewRandomString(n)
				Expect(err).ToNot(HaveOccurred())
				if wantEmpty {
					Expect(s).To(BeEmpty())
				} else {
					Expect(s).To(HaveLen(wantLen))
					Expect(s).To(MatchRegexp(`^[A-Za-z0-9]+$`))
				}
			},
			Entry("length 20", 20, 20, false),
			Entry("length 100 alphanumeric only", 100, 100, false),
			Entry("length 0 returns empty", 0, 0, true),
		)

		It("should return different values on subsequent calls", func() {
			s1, err := NewRandomString(32)
			Expect(err).ToNot(HaveOccurred())
			s2, err := NewRandomString(32)
			Expect(err).ToNot(HaveOccurred())
			Expect(s1).NotTo(Equal(s2))
		})
	})
})
