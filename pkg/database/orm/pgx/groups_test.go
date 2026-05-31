package pgx

import (
	"context"
	"fmt"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gorm.io/gorm"

	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
)

var _ = Describe("Group CRUD Operations", func() {
	var db *PGxDB
	var mock sqlmock.Sqlmock

	BeforeEach(func() {
		db, mock = newMockPGxDB()
	})

	Describe("AddGroup", func() {
		It("creates a group", func() {
			mock.ExpectQuery(`INSERT INTO "groups"`).
				WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))

			err := db.AddGroup(context.Background(), &models.GroupDB{ID: uuid.New(), GroupName: "test-group"})
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns ErrConflict on duplicate name", func() {
			pgErr := &pgconn.PgError{Code: "23505"}
			mock.ExpectQuery(`INSERT INTO "groups"`).
				WillReturnError(fmt.Errorf("%w: duplicate key", pgErr))

			err := db.AddGroup(context.Background(), &models.GroupDB{ID: uuid.New(), GroupName: "admins"})
			Expect(err).To(Equal(ezdb.ErrConflict))
		})

		It("rejects empty group name", func() {
			err := db.AddGroup(context.Background(), &models.GroupDB{ID: uuid.New(), GroupName: ""})
			Expect(err).To(HaveOccurred())
		})

		It("rejects group name with spaces", func() {
			err := db.AddGroup(context.Background(), &models.GroupDB{ID: uuid.New(), GroupName: "invalid name"})
			Expect(err).To(HaveOccurred())
		})

		It("rejects group name exceeding 32 chars", func() {
			err := db.AddGroup(context.Background(), &models.GroupDB{ID: uuid.New(), GroupName: "this-name-is-way-too-long-for-validation"})
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("GetGroup", func() {
		It("returns group by name with preloaded roles and users", func() {
			mock.ExpectQuery(`SELECT \* FROM "groups" WHERE name = \$1`).
				WithArgs("admins", 1).
				WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).
					AddRow(uuid.New(), "admins"))
			mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows(nil))
			mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows(nil))

			group, err := db.GetGroup(context.Background(), "admins")
			Expect(err).ToNot(HaveOccurred())
			Expect(group.GroupName).To(Equal("admins"))
		})

		It("returns ErrNoRecord for non-existent group", func() {
			mock.ExpectQuery(`SELECT \* FROM "groups"`).
				WithArgs("nonexistent", 1).
				WillReturnError(gorm.ErrRecordNotFound)

			_, err := db.GetGroup(context.Background(), "nonexistent")
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})

		It("returns ErrOperation on DB error", func() {
			mock.ExpectQuery(`SELECT \* FROM "groups"`).
				WithArgs("test", 1).
				WillReturnError(fmt.Errorf("connection refused"))

			_, err := db.GetGroup(context.Background(), "test")
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})

	Describe("UpdateGroup", func() {
		It("renames group", func() {
			mock.ExpectExec(`UPDATE "groups" SET`).
				WithArgs("new-name", sqlmock.AnyArg(), "old-name").
				WillReturnResult(sqlmock.NewResult(1, 1))

			err := db.UpdateGroup(context.Background(), "old-name", &models.GroupDB{GroupName: "new-name"})
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns ErrNoRecord for non-existent group", func() {
			mock.ExpectExec(`UPDATE "groups" SET`).
				WithArgs("renamed", sqlmock.AnyArg(), "nonexistent").
				WillReturnResult(sqlmock.NewResult(0, 0))

			err := db.UpdateGroup(context.Background(), "nonexistent", &models.GroupDB{GroupName: "renamed"})
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})

		It("returns ErrOperation on DB error", func() {
			mock.ExpectExec(`UPDATE "groups" SET`).
				WithArgs("renamed", sqlmock.AnyArg(), "test").
				WillReturnError(fmt.Errorf("connection refused"))

			err := db.UpdateGroup(context.Background(), "test", &models.GroupDB{GroupName: "renamed"})
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})

	Describe("DeleteGroup", func() {
		It("deletes existing group", func() {
			mock.ExpectExec(`DELETE FROM "groups" WHERE name = \$1`).
				WithArgs("to-delete").
				WillReturnResult(sqlmock.NewResult(1, 1))

			err := db.DeleteGroup(context.Background(), "to-delete")
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns ErrNoRecord for non-existent group", func() {
			mock.ExpectExec(`DELETE FROM "groups" WHERE name = \$1`).
				WithArgs("nonexistent").
				WillReturnResult(sqlmock.NewResult(0, 0))

			err := db.DeleteGroup(context.Background(), "nonexistent")
			Expect(err).To(Equal(ezdb.ErrNoRecord))
		})

		It("returns ErrOperation on DB error", func() {
			mock.ExpectExec(`DELETE FROM "groups"`).
				WithArgs("test").
				WillReturnError(fmt.Errorf("connection refused"))

			err := db.DeleteGroup(context.Background(), "test")
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})

	Describe("ListGroups", func() {
		It("lists all groups ordered by name", func() {
			mock.ExpectQuery(`SELECT \* FROM "groups" ORDER BY name LIMIT \$1`).
				WithArgs(10).
				WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).
					AddRow(uuid.New(), "alpha").
					AddRow(uuid.New(), "beta").
					AddRow(uuid.New(), "gamma"))

			groups, err := db.ListGroups(context.Background(), 10, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(groups).To(HaveLen(3))
		})

		It("respects pagination", func() {
			mock.ExpectQuery(`SELECT \* FROM "groups" ORDER BY name LIMIT \$1 OFFSET \$2`).
				WithArgs(2, 1).
				WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).
					AddRow(uuid.New(), "beta").
					AddRow(uuid.New(), "gamma"))

			groups, err := db.ListGroups(context.Background(), 2, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(groups).To(HaveLen(2))
		})

		It("returns empty list when no groups exist", func() {
			mock.ExpectQuery(`SELECT \* FROM "groups"`).
				WithArgs(10).
				WillReturnRows(sqlmock.NewRows([]string{"id", "name"}))

			groups, err := db.ListGroups(context.Background(), 10, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(groups).To(BeEmpty())
		})

		It("applies default limit when limit is 0", func() {
			mock.ExpectQuery(`SELECT \* FROM "groups" ORDER BY name LIMIT \$1`).
				WithArgs(30).
				WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).
					AddRow(uuid.New(), "test"))

			groups, err := db.ListGroups(context.Background(), 0, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(groups).To(HaveLen(1))
		})

		It("returns ErrOperation on DB error", func() {
			mock.ExpectQuery(`SELECT \* FROM "groups"`).
				WithArgs(10).
				WillReturnError(fmt.Errorf("connection refused"))

			_, err := db.ListGroups(context.Background(), 10, 0)
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})

	Describe("AddUserToGroup", func() {
		It("returns error when group not found", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "groups" WHERE name = \$1`).
				WithArgs("nonexistent", 1).
				WillReturnError(gorm.ErrRecordNotFound)
			mock.ExpectRollback()

			err := db.AddUserToGroup(context.Background(), "nonexistent", []string{uuid.New().String()})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("group nonexistent not found"))
		})

		It("returns error when user not found", func() {
			groupID := uuid.New()

			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "groups" WHERE name = \$1`).
				WithArgs("admins", 1).
				WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(groupID, "admins"))
			mock.ExpectQuery(`SELECT \* FROM "users" WHERE id IN \(\$1\)`).
				WithArgs(sqlmock.AnyArg()).
				WillReturnRows(sqlmock.NewRows([]string{"id", "username"}))
			mock.ExpectRollback()

			err := db.AddUserToGroup(context.Background(), "admins", []string{uuid.New().String()})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
		})

		It("returns ErrOperation on DB error", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "groups" WHERE name = \$1`).
				WithArgs("admins", 1).
				WillReturnError(fmt.Errorf("connection refused"))
			mock.ExpectRollback()

			err := db.AddUserToGroup(context.Background(), "admins", []string{uuid.New().String()})
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})

	Describe("RemoveUserFromGroup", func() {
		It("returns error when group not found", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "groups" WHERE name = \$1`).
				WithArgs("nonexistent", 1).
				WillReturnError(gorm.ErrRecordNotFound)
			mock.ExpectRollback()

			err := db.RemoveUserFromGroup(context.Background(), "nonexistent", []string{uuid.New().String()})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("group nonexistent not found"))
		})

		It("returns error when user not found", func() {
			groupID := uuid.New()

			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "groups" WHERE name = \$1`).
				WithArgs("admins", 1).
				WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(groupID, "admins"))
			mock.ExpectQuery(`SELECT \* FROM "users" WHERE id IN \(\$1\)`).
				WithArgs(sqlmock.AnyArg()).
				WillReturnRows(sqlmock.NewRows([]string{"id", "username"}))
			mock.ExpectRollback()

			err := db.RemoveUserFromGroup(context.Background(), "admins", []string{uuid.New().String()})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
		})

		It("returns ErrOperation on DB error", func() {
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT \* FROM "groups" WHERE name = \$1`).
				WithArgs("admins", 1).
				WillReturnError(fmt.Errorf("connection refused"))
			mock.ExpectRollback()

			err := db.RemoveUserFromGroup(context.Background(), "admins", []string{uuid.New().String()})
			Expect(err).To(Equal(ezdb.ErrOperation))
		})
	})
})
