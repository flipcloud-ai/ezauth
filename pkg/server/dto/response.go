package dto

// ErrorResponse is the unified JSON error response body for all admin API and
// gateway endpoints. For the /verify endpoint, Authenticated is set to false on
// error for backward compatibility with external gateways (nginx, Kong, Envoy).
// @Description Unified error response with numeric code and human-readable message.
type ErrorResponse struct {
	Code          int    `json:"code"`
	Error         string `json:"error"`
	Authenticated *bool  `json:"authenticated,omitempty"`
}

// SuccessResponse is the unified JSON success response for all non-creation CRUD
// endpoints. It wraps the payload in a data field alongside a human-readable
// message, matching the format already used by creation endpoints (201).
// @Description Unified success response with message and optional data payload.
type SuccessResponse struct {
	Message string `json:"message"`
	Data    any    `json:"data"`
}

// VerifyResponse is the JSON body for GET /ezauth/verify. It is used by external
// gateway auth_request integration (nginx, Kong, Envoy).
type VerifyResponse struct {
	Authenticated bool     `json:"authenticated"`
	User          string   `json:"user"`
	Subject       string   `json:"subject"`
	Email         string   `json:"email"`
	Groups        []string `json:"groups"`
	IDType        string   `json:"id_type"`
}

// AuthSuccessResponse is the JSON body for auth-only login/callback success
// responses.
type AuthSuccessResponse struct {
	Code   int    `json:"code"`
	Status string `json:"status"`
	User   string `json:"user"`
}
