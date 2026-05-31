package database

import (
	"net/http"

	ezerror "github.com/flipcloud-ai/ezauth/pkg/error"
)

// DatabaseErr wraps a GeneralError for database-layer failures.
//
//nolint:revive // established API name; renaming would be a breaking change
type DatabaseErr struct {
	ezerror.GeneralError
}

// ErrNeedInit is returned when a database operation is attempted before initialization.
var ErrNeedInit = &DatabaseErr{GeneralError: ezerror.GeneralError{Code: http.StatusInternalServerError, Err: "database need initialization"}}

// ErrOperation is returned when a database operation fails.
var ErrOperation = &DatabaseErr{GeneralError: ezerror.GeneralError{Code: http.StatusInternalServerError, Err: "operation failure"}}

// ErrNoRecord is returned when a requested record does not exist.
var ErrNoRecord = &DatabaseErr{GeneralError: ezerror.GeneralError{Code: http.StatusNotFound, Err: "record not found"}}

// ErrConflict is returned when an insert would violate a uniqueness constraint.
var ErrConflict = &DatabaseErr{GeneralError: ezerror.GeneralError{Code: http.StatusConflict, Err: "record conflicts with existing one"}}

// ErrNotImplemented is returned by unimplemented database methods.
var ErrNotImplemented = &DatabaseErr{GeneralError: ezerror.GeneralError{Code: http.StatusInternalServerError, Err: "not implemented"}}

// ErrNoDatabase is returned when the target database does not exist.
var ErrNoDatabase = &DatabaseErr{GeneralError: ezerror.GeneralError{Code: http.StatusInternalServerError, Err: "database does not exist"}}

// ErrInvalidCreds is returned when user credentials do not match.
var ErrInvalidCreds = &DatabaseErr{GeneralError: ezerror.GeneralError{Code: http.StatusUnauthorized, Err: "invalid credentials"}}

// NewDatabaseError creates a new DatabaseErr with the given HTTP status code and error.
func NewDatabaseError(code int, err error) *DatabaseErr {
	return &DatabaseErr{GeneralError: ezerror.GeneralError{Code: code, Err: err.Error()}}
}

func (e *DatabaseErr) Error() string {
	return e.Err
}

func (e *DatabaseErr) Unwrap() error {
	return &e.GeneralError
}
