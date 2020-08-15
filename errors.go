package recaptcha

import (
	"encoding/json"
	"errors"
)

// UserError is error type used for user generated errors
type UserError struct {
	message string
}

// Error returns the error message
func (err UserError) Error() string {
	return err.message
}

var (
	// ErrBadRequest is produced when the request is invalid or malformed
	ErrBadRequest = errors.New("the request is invalid or malformed")
	// ErrInvalidInputResponse is produced when the user's response is invalid
	ErrInvalidInputResponse = &UserError{message: "the response parameter is invalid or malformed"}
	// ErrInvalidInputSecret is produced when the secret is invalid or malformed
	ErrInvalidInputSecret = errors.New("the secret parameter is invalid or malformed")
	// ErrTimeoutOrDuplicate is produced when user requests the verification of an already verified or expired captcha
	ErrTimeoutOrDuplicate = &UserError{message: "the response is no longer valid: either is too old or has been used previously"}
)

// Errors allows to have a custom json unmarshalling implementation for a errors slice
type Errors []error

// UnmarshalJSON transforms a JSON array into an Errors type
// "invalid-input-response", "invalid-input-response", "invalid-input-secret"," missing-input-secret" and "bad-request" are transformed into it's global errors counterpart
func (errs *Errors) UnmarshalJSON(b []byte) error {
	var errorStrings []string
	if err := json.Unmarshal(b, &errorStrings); err != nil {
		return err
	}
	result := make([]error, len(errorStrings))

	for i, errString := range errorStrings {
		var err error
		switch errString {
		case "invalid-input-response":
			fallthrough
		case "missing-input-response":
			err = ErrInvalidInputResponse
		case "timeout-or-duplicate":
			err = ErrTimeoutOrDuplicate
		case "invalid-input-secret":
			fallthrough
		case "missing-input-secret":
			err = ErrInvalidInputSecret
		case "bad-request":
			err = ErrBadRequest
		default:
			err = errors.New(errString)
		}
		result[i] = err
	}
	*errs = result
	return nil
}
