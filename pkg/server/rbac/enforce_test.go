package rbac

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"

	ezlog "github.com/flipcloud-ai/ezauth/log"
	"github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func newTestController() *AuthController {
	logger, _ := testutils.SetupTestLogger()
	ctx := ezlog.ServerContext(context.Background(), logger)
	ctrl, err := NewController(ctx, nil, nil, testCache(), "/ezauth", "")
	if err != nil {
		Fail("NewController: " + err.Error())
	}
	return ctrl.(*AuthController)
}

func seedUserPermissions(a *AuthController, userID string, perms []*models.Permission) {
	data, err := json.Marshal(perms)
	if err != nil {
		Fail("marshal perms: " + err.Error())
	}
	if err := a.cache.Set(context.Background(), UserPermissionCachePrefix+userID, data, CacheTTL); err != nil {
		Fail("seed cache: " + err.Error())
	}
}

func reqWithSession(method, path string, session *apis.Session) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), method, path, nil)
	info := &apis.AuthRequest{Session: session}
	return apis.AddRequestInfo(req, info)
}

var _ = Describe("EnforceRequest", func() {
	var a *AuthController

	BeforeEach(func() {
		a = newTestController()
	})

	Describe("no session", func() {
		It("rejects nil AuthRequest", func() {
			req := httptest.NewRequest("GET", "/admin/users", nil)
			allowed, err := a.EnforceRequest(req)
			Expect(allowed).To(BeFalse())
			Expect(err).To(MatchError(ErrNoSession))
		})

		It("rejects AuthRequest without session", func() {
			req := reqWithSession("GET", "/admin/users", nil)
			allowed, err := a.EnforceRequest(req)
			Expect(allowed).To(BeFalse())
			Expect(err).To(MatchError(ErrNoSession))
		})

		It("rejects session with empty subject", func() {
			req := reqWithSession("GET", "/admin/users", &apis.Session{
				Profile: apis.Profile{Subject: ""},
			})
			allowed, err := a.EnforceRequest(req)
			Expect(allowed).To(BeFalse())
			Expect(err).To(MatchError(ErrNoSession))
		})
	})

	It("rejects unsupported IDType", func() {
		session := &apis.Session{Profile: apis.Profile{Subject: "u1", IDType: "nonsense"}}
		req := reqWithSession("GET", "/admin/users", session)

		allowed, err := a.EnforceRequest(req)
		Expect(allowed).To(BeFalse())
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, ErrNoSession)).To(BeFalse())
		Expect(errors.Is(err, ErrExplicitDeny)).To(BeFalse())
	})

	It("allows when permission matches", func() {
		seedUserPermissions(a, "u1", []*models.Permission{
			{Name: "auth::user::list", Effect: true, Path: "/admin/users", Method: "GET"},
		})

		req := reqWithSession("GET", "/admin/users", &apis.Session{
			Profile: apis.Profile{Subject: "u1", IDType: apis.UserIDType},
		})
		allowed, err := a.EnforceRequest(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(allowed).To(BeTrue())
	})

	It("implicitly denies when no permission matches", func() {
		seedUserPermissions(a, "u1", []*models.Permission{
			{Name: "auth::user::list", Effect: true, Path: "/admin/users", Method: "GET"},
		})

		req := reqWithSession("GET", "/admin/roles", &apis.Session{
			Profile: apis.Profile{Subject: "u1", IDType: apis.UserIDType},
		})
		allowed, err := a.EnforceRequest(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(allowed).To(BeFalse())
	})

	Describe("explicit deny", func() {
		BeforeEach(func() {
			seedUserPermissions(a, "u1", []*models.Permission{
				{Name: "admin::*::*", Effect: true, Path: "/admin/*", Method: "ALL"},
				{Name: "auth::user::delete", Effect: false, Path: "/admin/users/{id}", Method: "DELETE"},
			})
		})

		It("wins over allow for matching method", func() {
			req := reqWithSession("DELETE", "/admin/users/42", &apis.Session{
				Profile: apis.Profile{Subject: "u1", IDType: apis.UserIDType},
			})
			allowed, err := a.EnforceRequest(req)
			Expect(allowed).To(BeFalse())
			Expect(err).To(MatchError(ErrExplicitDeny))
		})

		It("only applies to matching method", func() {
			req := reqWithSession("GET", "/admin/users/42", &apis.Session{
				Profile: apis.Profile{Subject: "u1", IDType: apis.UserIDType},
			})
			allowed, err := a.EnforceRequest(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(allowed).To(BeTrue())
		})
	})

	It("orders deny before allow regardless of permission list order", func() {
		allow := &models.Permission{Name: "a1", Effect: true, Path: "/admin/*", Method: "ALL"}
		deny := &models.Permission{Name: "d1", Effect: false, Path: "/admin/secret", Method: "GET"}

		for _, order := range [][]*models.Permission{
			{allow, deny},
			{deny, allow},
		} {
			ctrl := newTestController()
			seedUserPermissions(ctrl, "u1", order)
			req := reqWithSession("GET", "/admin/secret", &apis.Session{
				Profile: apis.Profile{Subject: "u1", IDType: apis.UserIDType},
			})
			allowed, err := ctrl.EnforceRequest(req)
			Expect(allowed).To(BeFalse())
			Expect(err).To(MatchError(ErrExplicitDeny))
		}
	})

	It("rejects path traversal via normalization", func() {
		seedUserPermissions(a, "u1", []*models.Permission{
			{Name: "admin::*::*", Effect: true, Path: "/admin/*", Method: "ALL"},
		})

		req := reqWithSession("GET", "/admin/../public", &apis.Session{
			Profile: apis.Profile{Subject: "u1", IDType: apis.UserIDType},
		})
		allowed, err := a.EnforceRequest(req)
		Expect(allowed).To(BeFalse())
		Expect(err).ToNot(HaveOccurred())
	})

	It("normalizes trailing slashes in path and permission", func() {
		seedUserPermissions(a, "u1", []*models.Permission{
			{Name: "u", Effect: true, Path: "/admin/users/", Method: "GET"},
		})

		for _, p := range []string{"/admin/users", "/admin/users/"} {
			req := reqWithSession("GET", p, &apis.Session{
				Profile: apis.Profile{Subject: "u1", IDType: apis.UserIDType},
			})
			allowed, err := a.EnforceRequest(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(allowed).To(BeTrue())
		}
	})

	DescribeTable("method wildcard ALL",
		func(method string) {
			seedUserPermissions(a, "u1", []*models.Permission{
				{Name: "u", Effect: true, Path: "/admin/users", Method: "ALL"},
			})

			req := reqWithSession(method, "/admin/users", &apis.Session{
				Profile: apis.Profile{Subject: "u1", IDType: apis.UserIDType},
			})
			allowed, err := a.EnforceRequest(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(allowed).To(BeTrue())
		},
		Entry("GET", "GET"),
		Entry("POST", "POST"),
		Entry("PATCH", "PATCH"),
		Entry("DELETE", "DELETE"),
	)

	It("does not bypass method restriction", func() {
		seedUserPermissions(a, "u1", []*models.Permission{
			{Name: "read", Effect: true, Path: "/admin/users", Method: "GET"},
		})

		req := reqWithSession("POST", "/admin/users", &apis.Session{
			Profile: apis.Profile{Subject: "u1", IDType: apis.UserIDType},
		})
		allowed, err := a.EnforceRequest(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(allowed).To(BeFalse())
	})

	It("isolates subjects — permissions do not leak", func() {
		seedUserPermissions(a, "alice", []*models.Permission{
			{Name: "a", Effect: true, Path: "/admin/*", Method: "ALL"},
		})
		seedUserPermissions(a, "bob", []*models.Permission{})

		req := reqWithSession("GET", "/admin/users", &apis.Session{
			Profile: apis.Profile{Subject: "bob", IDType: apis.UserIDType},
		})
		allowed, err := a.EnforceRequest(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(allowed).To(BeFalse())
	})

	It("treats empty IDType as user", func() {
		seedUserPermissions(a, "u1", []*models.Permission{
			{Name: "u", Effect: true, Path: "/admin/users", Method: "GET"},
		})
		req := reqWithSession("GET", "/admin/users", &apis.Session{
			Profile: apis.Profile{Subject: "u1", IDType: ""},
		})
		allowed, err := a.EnforceRequest(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(allowed).To(BeTrue())
	})

	It("implicitly denies when user has no permissions", func() {
		seedUserPermissions(a, "u1", []*models.Permission{})
		req := reqWithSession("GET", "/admin/users", &apis.Session{
			Profile: apis.Profile{Subject: "u1", IDType: apis.UserIDType},
		})
		allowed, err := a.EnforceRequest(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(allowed).To(BeFalse())
	})
})
