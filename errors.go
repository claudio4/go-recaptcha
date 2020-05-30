package recaptcha

import (
	"encoding/json"
	"errors"
)

//UserError is used to declare the user fault.
type UserError struct {
	message string
}

//Error returns the error message
func (err *UserError) Error() string {
	return err.message
}

//nolint
var (
	ErrBadRequest           = errors.New("the request is invalid or malformed")
	ErrInvalidInputResponse = &UserError{message: "the response parameter is invalid or malformed"}
	ErrInvalidInputSecret   = errors.New("the secret parameter is invalid or malformed")
	ErrTimeoutOrDuplicate   = &UserError{message: "the response is no longer valid: either is too old or has been used previously"}
)

//Errors allows to have a custom json unmarshalling implementation for a errors slice
type Errors []error

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
