package pgx

import (
	"context"
	"fmt"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gorm.io/gorm"

	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
)

var _ = Describe("User CRUD Operations", func() {
	var db *PGxDB
	var mock sqlmock.Sqlmock
	testBirthDate := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	BeforeEach(func() {
		db, mock = newMockPGxDB()
	})

	Describe("AddUser", func() {
		It("rejects user without birth_date", func() {
			user := &models.UserDB{ID: uuid.New(), Email: "nopass@example.com", Password: "Test1234", BirthDate: time.Time{}, Address: models.AddressDB{Country: "US"}}
			err := db.AddUser(context.Background(), user)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("birth date"))
		})

		It("rejects user without email or mobile number", func() {
			user := &models.UserDB{ID: uuid.New(), Username: "testuser", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
			err := db.AddUser(context.Background(), user)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("either email or mobile number is required"))
		})

		It("creates valid user with email", func() {
			mock.ExpectQuery(`INSERT INTO "users"`).
				WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))

			user := &models.UserDB{ID: uuid.New(), Email: "test1@example.com", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
			err := db.AddUser(context.Background(), user)
			Expect(err).ToNot(HaveOccurred())
			Expect(user.PasswordSalt).ToNot(BeEmpty())
		})

		It("creates valid user with mobile number", func() {
			mock.ExpectQuery(`INSERT INTO "users"`).
				WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))

			user := &models.UserDB{ID: uuid.New(), MobileNumber: "+1234567890", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
			err := db.AddUser(context.Background(), user)
			Expect(err).ToNot(HaveOccurred())
		})

		It("rejects invalid email format", func() {
			user := &models.UserDB{ID: uuid.New(), Email: "invalid-email", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
			err := db.AddUser(context.Background(), user)
			Expect(err).To(HaveOccurred())
		})

		It("returns ErrConflict on duplicate email", func() {
			pgErr := &pgconn.PgError{Code: "23505"}
			mock.ExpectQuery(`INSERT INTO "users"`).
				WillReturnError(fmt.Errorf("%w: duplicate key", pgErr))

			user := &models.UserDB{ID: uuid.New(), Email: "dup@example.com", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
			err := db.AddUser(context.Background(), user)
			Expect(err).To(Equal(ezdb.ErrConflict))
		})

		It("returns ErrConflict on duplicate username", func() {
			pgErr := &pgconn.PgError{Code: "23505"}
			mock.ExpectQuery(`INSERT INTO "users"`).
				WillReturnError(fmt.Errorf("%w: duplicate key", pgErr))

			user := &models.UserDB{ID: uuid.New(), Username: "duplicateuser", Email: "user2@example.com", Password: "Test1234", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
			err := db.AddUser(context.Background(), user)
			Expect(err).To(Equal(ezdb.ErrConflict))
		})

		It("rejects empty password", func() {
			user := &models.UserDB{ID: uuid.New(), Email: "testerror@example.com", Password: "", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
			err := db.AddUser(context.Background(), user)
			Expect(err).To(HaveOccurred())
		})

		It("rejects invalid password", func() {
			user := &models.UserDB{ID: uuid.New(), Email: "testerror@example.com", Password: "short", BirthDate: testBirthDate, Address: models.AddressDB{Country: "US"}}
			err := db.AddUser(context.Background(), user)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("GetUser", func() {
		It("returns user by id with password redacted", func() {
			userID := uuid.New()
			mock.ExpectQuery(`SELECT \* FROM "users" WHERE id = \$1`).
				WithArgs(userID.String(), 1).
				WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "password_salt", "first_name", "birth_date", "country"}).
					AddRow(userID, "testuser", "test@example.com", "hashed", "salt", "", testBirthDate, "US"))
			// Preload queries
			for range 4 {
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows(nil))
			}

			user, err := db.GetUser(context.Background(), userID.String())
			Expect(err).ToNot(HaveOccurred())
			Expect(user.Email).To(Equal("test@example.com"))
			Expect(user.Password).To(BeEmpty())
		})

		It("returns ErrNoRecord for non-existent user", func() {
			mock.ExpectQuery(`SELECT \* FROM "users"`).
				WithArgs(sqlmock.AnyArg(), 1).
				WillReturnError(gorm.ErrRecordNotFound)

			_, err := db.GetUser(context.Background(), uuid.New().String())
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})
	})

	Describe("UpdateUser", func() {
		It("updates user fields by id", func() {
			userID := uuid.New()
			mock.ExpectExec(`UPDATE "users" SET`).
				WithArgs("Jane", testBirthDate, userID.String()).
				WillReturnResult(sqlmock.NewResult(1, 1))

			err := db.UpdateUser(context.Background(), &models.UserDB{ID: userID, FirstName: "Jane", BirthDate: testBirthDate})
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns ErrNoRecord for non-existent user", func() {
			userID := uuid.New()
			mock.ExpectExec(`UPDATE "users" SET`).
				WithArgs("Jane", testBirthDate, userID.String()).
				WillReturnResult(sqlmock.NewResult(0, 0))

			err := db.UpdateUser(context.Background(), &models.UserDB{ID: userID, FirstName: "Jane", BirthDate: testBirthDate})
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})

		It("returns ErrOperation on DB error", func() {
			userID := uuid.New()
			mock.ExpectExec(`UPDATE "users" SET`).
				WithArgs("Jane", testBirthDate, userID.String()).
				WillReturnError(fmt.Errorf("connection refused"))

			err := db.UpdateUser(context.Background(), &models.UserDB{ID: userID, FirstName: "Jane", BirthDate: testBirthDate})
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})

	Describe("DeleteUser", func() {
		It("deletes user by id", func() {
			userID := uuid.New()
			mock.ExpectExec(`DELETE FROM "users" WHERE id = \$1`).
				WithArgs(userID.String()).
				WillReturnResult(sqlmock.NewResult(1, 1))

			err := db.DeleteUser(context.Background(), userID.String())
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns ErrNoRecord for non-existent user", func() {
			mock.ExpectExec(`DELETE FROM "users" WHERE id = \$1`).
				WithArgs(sqlmock.AnyArg()).
				WillReturnResult(sqlmock.NewResult(0, 0))

			err := db.DeleteUser(context.Background(), uuid.New().String())
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})

		It("returns ErrOperation on DB error", func() {
			mock.ExpectExec(`DELETE FROM "users"`).
				WithArgs(sqlmock.AnyArg()).
				WillReturnError(fmt.Errorf("connection refused"))

			err := db.DeleteUser(context.Background(), uuid.New().String())
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})

	Describe("ListUsers", func() {
		It("lists users with pagination", func() {
			mock.ExpectQuery(`SELECT \* FROM "users"`).
				WithArgs(2, 1).
				WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email"}).
					AddRow(uuid.New(), "user2", "user2@example.com").
					AddRow(uuid.New(), "user3", "user3@example.com"))
			// Preload Groups queries
			mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows(nil))
			mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows(nil))

			users, err := db.ListUsers(context.Background(), 2, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(users).To(HaveLen(2))
		})

		It("applies default limit of 30 when limit is 0", func() {
			mock.ExpectQuery(`SELECT \* FROM "users"`).
				WithArgs(30).
				WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email"}).
					AddRow(uuid.New(), "u1", "u1@example.com"))
			mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows(nil))
			mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows(nil))

			users, err := db.ListUsers(context.Background(), 0, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(users).To(HaveLen(1))
		})

		It("returns empty list when no users exist", func() {
			mock.ExpectQuery(`SELECT \* FROM "users"`).
				WithArgs(10).
				WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email"}))

			users, err := db.ListUsers(context.Background(), 10, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(users).To(BeEmpty())
		})

		It("returns ErrOperation on DB error", func() {
			mock.ExpectQuery(`SELECT \* FROM "users"`).
				WithArgs(10, 0).
				WillReturnError(fmt.Errorf("connection refused"))

			_, err := db.ListUsers(context.Background(), 10, 0)
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})

	Describe("ResetPassword", func() {
		var userID = uuid.New()

		It("resets password successfully", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "users" WHERE id = \$1.*FOR UPDATE`).
				WithArgs(userID.String(), 1).
				WillReturnRows(sqlmock.NewRows([]string{"id", "username", "password", "password_salt", "email", "birth_date", "country"}).
					AddRow(userID, "testuser", "oldhash", "oldsalt", "test@example.com", testBirthDate, "US"))
			mock.ExpectExec(`UPDATE "users" SET`).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), userID.String()).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mock.ExpectCommit()

			err := db.ResetPassword(context.Background(), userID.String(), "NewPass123")
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns ErrNoRecord for non-existent user", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "users".*FOR UPDATE`).
				WithArgs(sqlmock.AnyArg(), 1).
				WillReturnError(gorm.ErrRecordNotFound)
			mock.ExpectRollback()

			err := db.ResetPassword(context.Background(), uuid.New().String(), "NewPass123")
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})

		It("rejects invalid new password", func() {
			err := db.ResetPassword(context.Background(), userID.String(), "short")
			Expect(err).To(HaveOccurred())
		})

		It("returns ErrOperation on DB error during update", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "users" WHERE id = \$1.*FOR UPDATE`).
				WithArgs(userID.String(), 1).
				WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "birth_date", "country"}).
					AddRow(userID, "testuser", "test@example.com", testBirthDate, "US"))
			mock.ExpectExec(`UPDATE "users" SET`).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), userID.String()).
				WillReturnError(fmt.Errorf("connection refused"))
			mock.ExpectRollback()

			err := db.ResetPassword(context.Background(), userID.String(), "NewPass123")
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})

	Describe("UserLogin", func() {
		It("returns ErrNoRecord for non-existent user", func() {
			mock.ExpectQuery(`SELECT .* FROM "users" WHERE.*`).
				WithArgs("nonexistent", "nonexistent", 1).
				WillReturnError(gorm.ErrRecordNotFound)

			_, err := db.UserLogin(context.Background(), "nonexistent", "Test1234")
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})

		It("returns ErrOperation on DB error", func() {
			mock.ExpectQuery(`SELECT .* FROM "users" WHERE.*`).
				WithArgs("testuser", "testuser", 1).
				WillReturnError(fmt.Errorf("connection refused"))

			_, err := db.UserLogin(context.Background(), "testuser", "Test1234")
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})
})
