package recaptcha

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

const verifyURL = "https://www.google.com/recaptcha/api/siteverify"

//Response represents the reCAPTCHA v2/Invisible reCAPTCHA verification Response
type Response struct {
	Success            bool    `json:"success"`
	ChallengeTimeStamp string  `json:"challenge_ts"`
	Errors             Errors  `json:"error-codes"`
}

//ResponseV3 represents the reCAPTCHA v3 verification response
type ResponseV3 struct {
	Response
	Score    float64 `json:"score"`
	Action   string  `json:"action"`
}

//Verify
func Verify(secret, resp, remoteIP string) (response Response) {
	err := verify(secret, resp, remoteIP, &response)
	if err != nil {
		response.Errors = []error{err}
	}
	return response
}

func VerifyV3(secret, resp, remoteIP string) (response ResponseV3) {
	err := verify(secret, resp, remoteIP, &response)
	if err != nil {
		response.Errors = []error{err}
	}
	return response
}

var client = &http.Client{Timeout: 10 * time.Second}

func verify(secret, resp, remoteIP string, result interface{}) error {
	if secret == "" {
		return ErrInvalidInputSecret
	}
	if resp == "" {
		return ErrInvalidInputResponse
	}

	data := url.Values{}
	data.Add("secret", secret)
	data.Add("response", resp)
	if remoteIP != "" {
		data.Add("remoteip", remoteIP)
	}
	response, err := client.PostForm(verifyURL, data)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	bodyContent, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("unable to the response body")
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("unexpected response code %d, with content: %s", response.StatusCode, bodyContent)
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "application/json; charset=utf-8" {
		return fmt.Errorf("Unexpected response Content-Type: %s", contentType)
	}
	err = json.Unmarshal(bodyContent, result)
	if err != nil {
		return fmt.Errorf("Error unmarshalling the response body: %s", err.Error())
	}
	return nil
}

