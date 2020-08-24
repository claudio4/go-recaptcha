// Package recaptcha procides a direct port of the Google's Recaptcha API
package recaptcha

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPClient is the client used by lib, normally you don't need to modify it
// but it can be modified to alter the tiemout, to reuse another client, etc.
// Remember http.Client is thread-safe by default
var HTTPClient = &http.Client{Timeout: 10 * time.Second}

const verifyURL = "https://www.google.com/recaptcha/api/siteverify"

// Response represents the reCAPTCHA v2/Invisible reCAPTCHA verification Response
type Response struct {
	// Wether the user captcha response is valid or not
	Success bool `json:"success"`
	// timestamp of the challenge load (ISO format yyyy-MM-dd'T'HH:mm:ssZZ)
	ChallengeTimeStamp string `json:"challenge_ts"`
	// Errors, the user errors are represented by the UserError type, all Recaptcha are present as global variables in this package
	// Other technical errors can be contained in this slice as for example, connection errors
	Errors Errors `json:"error-codes"`
}

// ResponseV3 represents the reCAPTCHA v3 verification response
type ResponseV3 struct {
	Response
	// the score for the request (0.0 - 1.0)
	Score float64 `json:"score"`
	// Read more at https://developers.google.com/recaptcha/docs/v3#actions
	Action string `json:"action"`
}

// Verify verifies if the an usesr's Recaptcha v2/Invisible response is valid (same as VerifyWithContext with context.Background())
// Parameters:
//  - secret The Recaptcha API secret key
//  - resp The user response token provided by the reCAPTCHA client-side integration on your site
//  - remoteIP (optional) the user's IP, if provided Recaptcha will check if the user resolved the captcha with same IP
func Verify(secret, resp, remoteIP string) (response Response) {
	return VerifyWithContext(context.Background(), secret, resp, remoteIP)
}

// Verify verifies if the an usesr's Recaptcha v2/Invisible response is valid
// Parameters:
//  - ctx Provides context for cancelation
//  - secret The Recaptcha API secret key
//  - resp The user response token provided by the reCAPTCHA client-side integration on your site
//  - remoteIP (optional) the user's IP, if provided Recaptcha will check if the user resolved the captcha with same IP
func VerifyWithContext(ctx context.Context, secret, resp, remoteIP string) (response Response) {
	err := verify(ctx, secret, resp, remoteIP, &response)
	if err != nil {
		response.Errors = []error{err}
	}
	return response
}

// VerifyV3 verifies if the an usesr's Recaptcha v3 response is valid (same as VerifyV3WithContext with context.Background())
// Parameters:
//  - secret The Recaptcha API secret key
//  - resp The user response token provided by the reCAPTCHA client-side integration on your site
//  - remoteIP (optional) The user's IP address, if provided Recaptcha will check if the user resolved the captcha with same IP
func VerifyV3(secret, resp, remoteIP string) (response ResponseV3) {
	return VerifyV3WithContext(context.Background(), secret, resp, remoteIP)
}

// VerifyV3WithContext verifies if the an usesr's Recaptcha v3 response is valid
// Parameters:
//  - ctx Provides context for cancelation
//  - secret The Recaptcha API secret key
//  - resp The user response token provided by the reCAPTCHA client-side integration on your site
//  - remoteIP (optional) The user's IP address, if provided Recaptcha will check if the user resolved the captcha with same IP
func VerifyV3WithContext(ctx context.Context, secret, resp, remoteIP string) (response ResponseV3) {
	err := verify(ctx, secret, resp, remoteIP, &response)
	if err != nil {
		response.Errors = []error{err}
	}
	return response
}

// ParseTimeStamp transforms a Recaptcha ChallengeTimeStamp string into a time.Time
func ParseTimeStamp(ts string) (time.Time, error) {
	return time.Parse(time.RFC3339, ts)
}

func verify(ctx context.Context, secret, resp, remoteIP string, result interface{}) error {
	if secret == "" {
		return ErrInvalidInputSecret
	}
	if resp == "" {
		return ErrInvalidInputResponse
	}

	data := url.Values{}
	data.Set("secret", secret)
	data.Set("response", resp)
	if remoteIP != "" {
		data.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	response, err := HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if contentType := response.Header.Get("Content-Type"); !strings.Contains(contentType, "application/json") {
		return fmt.Errorf("Unexpected response Content-Type: %s", contentType)
	}

	bodyContent, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("unexpected response code %d, with content: %s", response.StatusCode, bodyContent)
	}
	err = json.Unmarshal(bodyContent, result)
	if err != nil {
		return fmt.Errorf("Error unmarshalling the response body: %w", err)
	}
	return nil
}
