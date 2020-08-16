# Go Recaptcha
[![Build Status](https://claudio4.visualstudio.com/go-recaptcha/_apis/build/status/claudio4.go-recaptcha?branchName=master)](https://claudio4.visualstudio.com/go-recaptcha/_build/latest?definitionId=1&branchName=master)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/claudio4/go-recaptcha/blob/master/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/claudio4/go-recaptcha)](https://goreportcard.com/report/github.com/claudio4/go-recaptcha)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/claudio4/go-recaptcha)](https://pkg.go.dev/github.com/claudio4/go-recaptcha?tab=doc)

Google's Recaptcha API in Go!
### features:
:white_check_mark: No external dependencies

:white_check_mark: Well-tested

:white_check_mark: As simple as the original API

:white_check_mark: Thread-Safe


### Known bugs
None at the moment!

### Example
```go
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
```
