package ezerror

import (
	"encoding/json"
	"net/http"
)

// GeneralError is the standard error response body for all admin API endpoints.
// @Description Standard error response returned on 4xx and 5xx errors. Contains a numeric code and a human-readable error message.
type GeneralError struct {
	Code int    `json:"code"`
	Err  string `json:"error"`
}

func (e *GeneralError) Error() string {
	return e.Err
}

// JSON writes the error as a JSON-encoded HTTP response with the error's status code.
func (e *GeneralError) JSON(rw http.ResponseWriter) {
	b, err := json.Marshal(e)
	if err != nil {
		b = []byte("{}")
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(e.Code)
	_, _ = rw.Write(b)
}

// NewError constructs a GeneralError with the given HTTP status code and optional message.
func NewError(code int, messages ...string) *GeneralError {
	err := http.StatusText(code)
	if len(messages) > 0 {
		err = messages[0]
	}
	return &GeneralError{
		Err:  err,
		Code: code,
	}
}
