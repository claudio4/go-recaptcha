package recaptcha_test

import (
	"errors"

	"github.com/claudio4/go-recaptcha"
)

const secret = "AAAAAAAA"

func allowUser()                 {}
func printErrorToUser(err error) {}

func Example() {
	// Get user's response
	userResp := "abc"
	// user IP (optional)
	userIP := "127.0.0.1"

	resp := recaptcha.Verify(secret, userResp, userIP)
	if len(resp.Errors) != 0 {
		userErr := recaptcha.UserError{}
		for _, err := range resp.Errors {
			if errors.As(err, &userErr) {
				// Error is user's fault
				printErrorToUser(&userErr)
			} else {
				// Error is the app fault
				panic(err)
			}
		}
		return
	}
	if !resp.Success {
		printErrorToUser(errors.New("Invalid captcha"))
		return
	}
	allowUser()
}
