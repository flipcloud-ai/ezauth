package rbac

import (
	"net/http"

	ezerror "github.com/flipcloud-ai/ezauth/pkg/error"
)

// RBACErr wraps a GeneralError with an HTTP status code for RBAC-specific failures.
//
//nolint:revive // established API name; renaming would be a breaking change
type RBACErr struct {
	ezerror.GeneralError
}

// ErrOperation is returned when an RBAC database operation fails.
var ErrOperation = &RBACErr{GeneralError: ezerror.GeneralError{Code: http.StatusInternalServerError, Err: "operation failure"}}

// ErrSystemResource is returned when attempting to modify or delete a system-owned resource.
var ErrSystemResource = &RBACErr{GeneralError: ezerror.GeneralError{Code: http.StatusForbidden, Err: "system resource cannot be modified or deleted"}}

// ErrExplicitDeny is returned when a policy explicitly denies the requested action.
var ErrExplicitDeny = &RBACErr{GeneralError: ezerror.GeneralError{Code: http.StatusForbidden, Err: "explicit deny"}}

// ErrNoSession is returned when the request has no valid session for RBAC evaluation.
var ErrNoSession = &RBACErr{GeneralError: ezerror.GeneralError{Code: http.StatusUnauthorized, Err: "no session"}}

func (e *RBACErr) Error() string {
	return e.Err
}

func (e *RBACErr) Unwrap() error {
	return &e.GeneralError
}
