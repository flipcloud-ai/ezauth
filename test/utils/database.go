package utils

import (
	"fmt"

	"github.com/DATA-DOG/go-sqlmock"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// MockDBStruct holds a GORM DB handle and its associated sqlmock for test assertions.
type MockDBStruct struct {
	DB   *gorm.DB
	Mock sqlmock.Sqlmock
}

// MockSQLPool creates an in-memory sqlmock-backed GORM database for unit tests.
func MockSQLPool() (*gorm.DB, sqlmock.Sqlmock, error) {
	mockdb, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		return nil, nil, fmt.Errorf("an error '%s' was not expected when opening a stub database connection", err)
	}
	// Open GORM with the properly configured sql.DB backed by pgxpool
	gormDB, err := gorm.Open(
		postgres.New(postgres.Config{
			Conn:       mockdb,
			DriverName: "postgres",
		}),
		&gorm.Config{},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("open gorm connection: %w", err)
	}
	return gormDB, mock, nil
}
