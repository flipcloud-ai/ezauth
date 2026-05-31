package database_test

import (
	"context"

	"github.com/flipcloud-ai/ezauth/pkg/database"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Database", func() {
	Describe("Init", func() {
		It("should return ErrNotImplemented", func() {
			db := &database.Database{}
			err := db.Init(context.Background())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("not implemented"))
		})
	})

	Describe("Manager", func() {
		It("should return the embedded *gorm.DB", func() {
			gormDB, _, err := testutils.MockSQLPool()
			Expect(err).ToNot(HaveOccurred())
			Expect(gormDB).ToNot(BeNil())

			db := &database.Database{DB: gormDB}
			result := db.Manager()
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(gormDB))
		})
	})

	Describe("Migrate", func() {
		It("should be callable without panicking on a properly initialised struct", func() {
			gormDB, _, err := testutils.MockSQLPool()
			Expect(err).ToNot(HaveOccurred())
			Expect(gormDB).ToNot(BeNil())

			db := &database.Database{DB: gormDB, Logger: nil}
			// AutoMigrate will fail with sqlmock since no real database is available
			// but it should not panic — it returns an error from the mock.
			err = db.Migrate(context.Background())
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("drop_unused_columns via Migrate", func() {
		It("should be callable without panicking when enabled", func() {
			gormDB, _, err := testutils.MockSQLPool()
			Expect(err).ToNot(HaveOccurred())
			Expect(gormDB).ToNot(BeNil())

			db := &database.Database{DB: gormDB, DropUnusedColumns: true}
			// Migrate with DropUnusedColumns enabled should hit sqlmock and fail,
			// but should not panic.
			err = db.Migrate(context.Background())
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("Errors", func() {
		It("NewDatabaseError creates error with code and message", func() {
			err := database.NewDatabaseError(500, database.ErrNeedInit)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("database need initialization"))
		})

		It("Unwrap returns the underlying GeneralError", func() {
			err := database.ErrNoRecord
			unwrapped := err.Unwrap()
			Expect(unwrapped).ToNot(BeNil())
		})

		It("sentinel errors have expected codes", func() {
			Expect(database.ErrConflict.Error()).To(ContainSubstring("record conflicts"))
			Expect(database.ErrNoDatabase.Error()).To(ContainSubstring("database does not exist"))
			Expect(database.ErrInvalidCreds.Error()).To(ContainSubstring("invalid credentials"))
		})
	})
})
