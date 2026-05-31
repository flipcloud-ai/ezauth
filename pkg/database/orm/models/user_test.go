package models

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var _ = Describe("UserDB Model", func() {
	Describe("TableName", func() {
		It("should return 'users' as table name", func() {
			Expect((&UserDB{}).TableName()).To(Equal("users"))
		})
	})

	Describe("GroupDB", func() {
		Describe("TableName", func() {
			It("should return 'groups' as table name", func() {
				Expect((&GroupDB{}).TableName()).To(Equal("groups"))
			})
		})
	})

	Describe("BeforeCreate validation", func() {
		var db *gorm.DB

		BeforeEach(func() {
			// Use SQLite for testing
			var err error
			db, err = gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			if db != nil {
				sqlDB, _ := db.DB()
				if sqlDB != nil {
					_ = sqlDB.Close()
				}
			}
		})

		Context("with valid user data", func() {
			validBirthDate := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
			validAddress := AddressDB{Country: "US"}

			It("should create user with username and email", func() {
				user := &UserDB{
					Username:  "testuser",
					Email:     "test@example.com",
					BirthDate: validBirthDate,
					Address:   validAddress,
				}
				err := user.BeforeCreate(db)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create user with email only", func() {
				user := &UserDB{
					Email:     "test@example.com",
					BirthDate: validBirthDate,
					Address:   validAddress,
				}
				err := user.BeforeCreate(db)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create user with mobile number only", func() {
				user := &UserDB{
					MobileNumber: "+1234567890",
					BirthDate:    validBirthDate,
					Address:      validAddress,
				}
				err := user.BeforeCreate(db)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create user with both email and mobile", func() {
				user := &UserDB{
					Email:        "test@example.com",
					MobileNumber: "+1234567890",
					BirthDate:    validBirthDate,
					Address:      validAddress,
				}
				err := user.BeforeCreate(db)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should auto-generate username if empty", func() {
				user := &UserDB{
					Email:     "test@example.com",
					BirthDate: validBirthDate,
					Address:   validAddress,
				}
				err := user.BeforeCreate(db)
				Expect(err).ToNot(HaveOccurred())
				Expect(user.Username).To(HavePrefix("User_"))
				Expect(len(user.Username)).To(BeNumerically(">", 5))
			})

			It("should preserve existing username", func() {
				user := &UserDB{
					Username:  "myuser",
					Email:     "test@example.com",
					BirthDate: validBirthDate,
					Address:   validAddress,
				}
				err := user.BeforeCreate(db)
				Expect(err).ToNot(HaveOccurred())
				Expect(user.Username).To(Equal("myuser"))
			})

			It("should accept valid email format", func() {
				user := &UserDB{
					Email:     "user@domain.com",
					BirthDate: validBirthDate,
					Address:   validAddress,
				}
				err := user.BeforeCreate(db)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should accept valid mobile number format", func() {
				user := &UserDB{
					MobileNumber: "+1234567890",
					BirthDate:    validBirthDate,
					Address:      validAddress,
				}
				err := user.BeforeCreate(db)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("with invalid user data", func() {
			validBirthDate := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
			validAddress := AddressDB{Country: "US"}

			It("should reject user with neither email nor mobile", func() {
				user := &UserDB{
					Username:  "testuser",
					BirthDate: validBirthDate,
					Address:   validAddress,
				}
				err := user.BeforeCreate(db)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("either email or mobile number is required"))
			})

			It("should reject user with invalid email format", func() {
				user := &UserDB{
					Email:     "invalid-email",
					BirthDate: validBirthDate,
					Address:   validAddress,
				}
				err := user.BeforeCreate(db)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("invalid email format"))
			})

			It("should reject user with invalid mobile number format", func() {
				user := &UserDB{
					MobileNumber: "123",
					BirthDate:    validBirthDate,
					Address:      validAddress,
				}
				err := user.BeforeCreate(db)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("invalid mobile number format"))
			})

			It("should reject user with empty email and empty mobile", func() {
				user := &UserDB{
					Username:     "testuser",
					Email:        "",
					MobileNumber: "",
					BirthDate:    validBirthDate,
					Address:      validAddress,
				}
				err := user.BeforeCreate(db)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("either email or mobile number is required"))
			})

			It("should reject user with spaces only in email", func() {
				user := &UserDB{
					Email:     "   ",
					BirthDate: validBirthDate,
					Address:   validAddress,
				}
				err := user.BeforeCreate(db)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("invalid email format"))
			})

			It("should reject user with spaces only in mobile", func() {
				user := &UserDB{
					MobileNumber: "   ",
					BirthDate:    validBirthDate,
					Address:      validAddress,
				}
				err := user.BeforeCreate(db)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("invalid mobile number format"))
			})
		})

		Context("with username validation", func() {
			validBirthDate := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
			validAddress := AddressDB{Country: "US"}

			DescribeTable("valid usernames",
				func(username string) {
					user := &UserDB{
						Username:  username,
						Email:     "test@example.com",
						BirthDate: validBirthDate,
						Address:   validAddress,
					}
					err := user.BeforeCreate(db)
					Expect(err).ToNot(HaveOccurred())
					Expect(user.Username).To(Equal(username))
				},
				Entry("simple alphanumeric", "user123"),
				Entry("with underscore", "user_name"),
				Entry("with hyphen", "user-name"),
				Entry("with dot", "user.name"),
				Entry("mixed special chars", "user_name.test"),
				Entry("minimum length 4 chars", "user"),
				Entry("maximum length 20 chars", "exactly20characters"),
				Entry("alphanumeric only", "User123"),
			)

			DescribeTable("invalid usernames",
				func(username string) {
					user := &UserDB{
						Username:  username,
						Email:     "test@example.com",
						BirthDate: validBirthDate,
						Address:   validAddress,
					}
					err := user.BeforeCreate(db)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("invalid username format"))
				},
				Entry("too short - 3 chars", "usr"),
				Entry("too long - 21 chars", "thisisaverylongusername"),
				Entry("with spaces", "user name"),
				Entry("with special chars only", "!!!"),
				Entry("consecutive underscores", "user__name"),
				Entry("consecutive hyphens", "user--name"),
				Entry("consecutive dots", "user..name"),
				Entry("starting with underscore", "_username"),
				Entry("starting with hyphen", "-username"),
				Entry("starting with dot", ".username"),
				Entry("ending with underscore", "username_"),
				Entry("ending with hyphen", "username-"),
				Entry("ending with dot", "username."),
			)
		})
	})
})

var _ = Describe("UserDB BeforeCreate edge cases", func() {
	It("rejects birth date older than 150 years", func() {
		tx := &gorm.DB{Config: &gorm.Config{}}
		user := &UserDB{
			Email:     "old@test.com",
			Password:  "Test1234",
			BirthDate: time.Date(1800, 1, 1, 0, 0, 0, 0, time.UTC),
			Address:   AddressDB{Country: "US"},
		}
		err := user.BeforeCreate(tx)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("birth date is invalid"))
	})
})
