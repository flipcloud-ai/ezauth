package models

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var _ = Describe("RBAC Models", func() {
	Describe("TableName", func() {
		It("should return 'roles' for RoleDB", func() {
			Expect((&RoleDB{}).TableName()).To(Equal("roles"))
		})

		It("should return 'rbac_policies' for Policy", func() {
			Expect((&Policy{}).TableName()).To(Equal("rbac_policies"))
		})

		It("should return 'rbac_permissions' for Permission", func() {
			Expect((&Permission{}).TableName()).To(Equal("rbac_permissions"))
		})
	})

	Describe("Permission BeforeSave", func() {
		var db *gorm.DB

		BeforeEach(func() {
			var err error
			db, err = gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			if db != nil {
				sqlDB, _ := db.DB()
				if sqlDB != nil {
					Expect(sqlDB.Close()).To(Succeed())
				}
			}
		})

		DescribeTable("valid permissions",
			func(p *Permission) {
				err := p.BeforeSave(db)
				Expect(err).ToNot(HaveOccurred())
			},
			Entry("basic permission", &Permission{
				Name: "auth::user::read", Service: "auth", Action: "user::read", Method: "GET", Path: "/users/",
			}),
			Entry("POST method", &Permission{
				Name: "auth::user::create", Service: "auth", Action: "user::create", Method: "POST", Path: "/users/",
			}),
			Entry("PUT method", &Permission{
				Name: "auth::user::update", Service: "auth", Action: "user::update", Method: "PUT", Path: "/users/",
			}),
			Entry("DELETE method", &Permission{
				Name: "auth::user::delete", Service: "auth", Action: "user::delete", Method: "DELETE", Path: "/users/",
			}),
			Entry("PATCH method", &Permission{
				Name: "auth::user::patch", Service: "auth", Action: "user::patch", Method: "PATCH", Path: "/users/",
			}),
			Entry("HEAD method", &Permission{
				Name: "auth::user::head", Service: "auth", Action: "user::head", Method: "HEAD", Path: "/users/",
			}),
			Entry("OPTIONS method", &Permission{
				Name: "auth::user::options", Service: "auth", Action: "user::options", Method: "OPTIONS", Path: "/users/",
			}),
			Entry("path with segments", &Permission{
				Name: "api::resource::get", Service: "api", Action: "resource::get", Method: "GET", Path: "/api/v1/resources",
			}),
			Entry("Chinese permission name", &Permission{
				Name: "认证::用户::读取", Service: "认证", Action: "user::read", Method: "GET", Path: "/users/",
			}),
			Entry("Chinese service name", &Permission{
				Name: "auth::user::read2", Service: "认证服务", Action: "user::read", Method: "GET", Path: "/users/",
			}),
		)

		DescribeTable("invalid permissions",
			func(p *Permission, expectedMsg string) {
				err := p.BeforeSave(db)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(expectedMsg))
			},
			Entry("empty action", &Permission{
				Name: "auth::user::read", Service: "auth", Action: "", Method: "GET", Path: "/users/",
			}, "action cannot be empty"),
			Entry("invalid action format - no separator", &Permission{
				Name: "auth::user::read", Service: "auth", Action: "invalid", Method: "GET", Path: "/users/",
			}, "invalid action format"),
			Entry("invalid action format - single colon", &Permission{
				Name: "auth::user::read", Service: "auth", Action: "user:read", Method: "GET", Path: "/users/",
			}, "invalid action format"),
			Entry("invalid service name", &Permission{
				Name: "auth::user::read", Service: "!invalid!", Action: "user::read", Method: "GET", Path: "/users/",
			}, "invalid service format"),
			Entry("invalid permission name", &Permission{
				Name: "!invalid!", Service: "auth", Action: "user::read", Method: "GET", Path: "/users/",
			}, "invalid permission name format"),
			Entry("invalid HTTP method", &Permission{
				Name: "auth::user::read", Service: "auth", Action: "user::read", Method: "INVALID", Path: "/users/",
			}, "invalid HTTP method"),
			Entry("empty method", &Permission{
				Name: "auth::user::read", Service: "auth", Action: "user::read", Method: "", Path: "/users/",
			}, "invalid HTTP method"),
			Entry("invalid path format", &Permission{
				Name: "auth::user::read", Service: "auth", Action: "user::read", Method: "GET", Path: "not a valid path",
			}, "invalid path format"),
		)
	})

	Describe("Policy BeforeSave", func() {
		var db *gorm.DB

		BeforeEach(func() {
			var err error
			db, err = gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			if db != nil {
				sqlDB, _ := db.DB()
				if sqlDB != nil {
					Expect(sqlDB.Close()).To(Succeed())
				}
			}
		})

		DescribeTable("valid policy names",
			func(name string) {
				p := &Policy{Name: name}
				err := p.BeforeSave(db)
				Expect(err).ToNot(HaveOccurred())
			},
			Entry("simple name", "admin-policy"),
			Entry("with dots", "auth.read"),
			Entry("with colons", "auth:read"),
			Entry("alphanumeric", "policy123"),
			Entry("single char", "p"),
			Entry("Chinese policy name", "管理员策略"),
			Entry("Chinese with alphanumeric", "策略v2"),
		)

		DescribeTable("invalid policy names",
			func(name string) {
				p := &Policy{Name: name}
				err := p.BeforeSave(db)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("invalid policy name"))
			},
			Entry("empty name", ""),
			Entry("name with spaces", "admin policy"),
			Entry("too long name", "this-is-a-very-long-policy-name-that-exceeds-limit"),
		)
	})

	Describe("RoleDB BeforeSave", func() {
		var db *gorm.DB

		BeforeEach(func() {
			var err error
			db, err = gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			if db != nil {
				sqlDB, _ := db.DB()
				if sqlDB != nil {
					Expect(sqlDB.Close()).To(Succeed())
				}
			}
		})

		DescribeTable("valid role names",
			func(name string) {
				r := &RoleDB{RoleName: name}
				err := r.BeforeSave(db)
				Expect(err).ToNot(HaveOccurred())
			},
			Entry("simple name", "admin"),
			Entry("with hyphen", "super-admin"),
			Entry("with dots", "role.viewer"),
			Entry("alphanumeric", "role123"),
			Entry("single char", "r"),
			Entry("Chinese role name", "管理员"),
			Entry("Chinese with hyphen", "超级-管理员"),
		)

		DescribeTable("invalid role names",
			func(name string) {
				r := &RoleDB{RoleName: name}
				err := r.BeforeSave(db)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("invalid role name"))
			},
			Entry("empty name", ""),
			Entry("name with spaces", "super admin"),
			Entry("too long name", "this-is-a-very-long-role-name-that-exceeds-limit"),
		)
	})

	Describe("actionRe subgroup indices", func() {
		It("should have Resource at index 1 and Action at index 2", func() {
			Expect(actionRe.SubexpIndex("Resource")).To(Equal(1))
			Expect(actionRe.SubexpIndex("Action")).To(Equal(2))
		})
	})
})
