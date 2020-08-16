package recaptcha_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/claudio4/go-recaptcha"
	"gopkg.in/h2non/gock.v1"
)

const (
	apiBase     = "https://www.google.com"
	apiEndPoint = "/recaptcha/api/siteverify"
	apiSecret   = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"
	gResponse   = "ABCDEF"
	clientIP    = "127.0.0.1"
	jsonCT      = "application/json; charset=utf-8"
)

func verifyV3(secret, resp, remoteIP string) recaptcha.Response {
	return (recaptcha.VerifyV3(secret, resp, remoteIP)).Response
}

type verify func(secret, resp, remoteIP string) recaptcha.Response

func TestVerifySuccess(t *testing.T) {
	t.Run("V2", testVerifySuccess(recaptcha.Verify))
	t.Run("V3", testVerifySuccess(verifyV3))
}
func testVerifySuccess(verify verify) func(t *testing.T) {
	return func(t *testing.T) {
		defer gock.Off()
		gock.New(apiBase).
			Post(apiEndPoint).
			Reply(200).
			AddHeader("Content-Type", jsonCT).
			BodyString(`{"success": true, "challenge_ts": "2019-10-20T16:09:06Z"}`)
		resp := verify(apiSecret, gResponse, "")
		if len(resp.Errors) != 0 {
			t.Errorf("the errors array should be empty but it contains: %+v", resp.Errors)
		}
		if !resp.Success {
			t.Error("response.Success should be true but it was not")
		}
		if resp.ChallengeTimeStamp != "2019-10-20T16:09:06Z" {
			t.Errorf("the timestamp has an unexpected value of %s", resp.ChallengeTimeStamp)
		}
	}
}

func TestRequestBody(t *testing.T) {
	t.Run("V2", testRequestBody(recaptcha.Verify))
	t.Run("V3", testRequestBody(verifyV3))
}

func testRequestBody(verify verify) func(t *testing.T) {
	return func(t *testing.T) {
		t.Run("without remoteIP", func(t *testing.T) {
			defer gock.Off()
			gock.New(apiBase).
				Post(apiEndPoint).
				AddMatcher(testRequestBodyMatecher(t, false)).
				Reply(200).
				AddHeader("Content-Type", jsonCT).
				BodyString(`{"success": true}`)
			verify(apiSecret, gResponse, "")
		})
		t.Run("with remoteIP", func(t *testing.T) {
			defer gock.Off()
			gock.New(apiBase).
				Post(apiEndPoint).
				AddMatcher(testRequestBodyMatecher(t, true)).
				Reply(200).
				AddHeader("Content-Type", jsonCT).
				BodyString(`{"success": true}`)
			verify(apiSecret, gResponse, clientIP)
		})
	}
}

func testRequestBodyMatecher(t *testing.T, useIP bool) gock.MatchFunc {
	t.Helper()
	return func(req *http.Request, ereq *gock.Request) (bool, error) {
		if contentType := req.Header.Get("Content-Type"); contentType != "application/x-www-form-urlencoded" {
			t.Errorf("the content type should be application/x-www-form-urlencoded, but %s was found", contentType)
		}
		if err := req.ParseForm(); err != nil {
			t.Fatalf("error parsing the form: %s", err.Error())
		}
		if secrect := req.Form.Get("secret"); secrect != apiSecret {
			if secrect != "" {
				t.Errorf("the secret should be %s, but %s was found", apiSecret, secrect)
			} else {
				t.Errorf("the secret should be %s, but it was empty", apiSecret)
			}
		}
		if response := req.Form.Get("response"); response != gResponse {
			if response != "" {
				t.Errorf("the response should be %s, but %s was found", gResponse, response)
			} else {
				t.Errorf("the response should be %s, but it was empty", gResponse)
			}
		}
		remoteIP := req.Form.Get("remoteip")
		if useIP {
			if remoteIP != clientIP {
				if remoteIP != "" {
					t.Errorf("the remoteIP should be %s, but %s was found", clientIP, remoteIP)
				} else {
					t.Errorf("the remoteIP should be %s, but it was empty", clientIP)
				}

			}
		} else {
			if remoteIP != "" {
				t.Errorf("the remoteIP should be empty, but %s was found", remoteIP)
			}
		}
		return true, nil
	}
}

func TestErrInvalidInputResponse(t *testing.T) {
	t.Run("V2", testErrInvalidInputResponse(recaptcha.Verify))
	t.Run("V3", testErrInvalidInputResponse(verifyV3))
}

func testErrInvalidInputResponse(verify verify) func(t *testing.T) {
	return func(t *testing.T) {
		t.Run("empty response", func(t *testing.T) {
			defer gock.Off()
			gock.DisableNetworking()
			resp := verify(apiSecret, "", "")
			errInvalidInputResponseHelper(t, resp)
		})
		t.Run("invalid response", func(t *testing.T) {
			defer gock.Off()
			gock.New(apiBase).
				Post(apiEndPoint).
				Reply(200).
				AddHeader("Content-Type", jsonCT).
				BodyString(`{"success": false, "error-codes": ["invalid-input-response"]}`)
			resp := verify(apiSecret, gResponse, "")
			errInvalidInputResponseHelper(t, resp)
		})
		t.Run("missing response", func(t *testing.T) {
			defer gock.Off()
			gock.New(apiBase).
				Post(apiEndPoint).
				Reply(200).
				AddHeader("Content-Type", jsonCT).
				BodyString(`{"success": false, "error-codes": ["missing-input-response"]}`)
			resp := verify(apiSecret, gResponse, "")
			errInvalidInputResponseHelper(t, resp)
		})
	}
}

func errInvalidInputResponseHelper(t *testing.T, resp recaptcha.Response) {
	t.Helper()
	if length := len(resp.Errors); length > 0 {
		if length != 1 {
			t.Errorf("the errors array should only contain one error but it contains: %+v", resp.Errors)
		}
		if resp.Errors[0] != recaptcha.ErrInvalidInputResponse {
			t.Errorf("the errors array should contain ErrInvalidInputResponse but it contains: %+v", resp.Errors)
		}
	} else {
		t.Error("the errors array should contain ErrInvalidInputResponse but it was empty")
	}
	if resp.Success {
		t.Error("response.Success should be false but it was not")
	}
}

func TestErrInvalidInputSecret(t *testing.T) {
	t.Run("V2", testErrInvalidInputSecret(recaptcha.Verify))
	t.Run("V3", testErrInvalidInputSecret(verifyV3))
}

func testErrInvalidInputSecret(verify verify) func(t *testing.T) {
	return func(t *testing.T) {
		t.Run("empty key", func(t *testing.T) {
			defer gock.Off()
			gock.DisableNetworking()
			resp := verify("", gResponse, "")
			errInvalidInputSecretHelper(t, resp)
		})
		t.Run("invalid key", func(t *testing.T) {
			defer gock.Off()
			gock.New(apiBase).
				Post(apiEndPoint).
				Reply(200).
				AddHeader("Content-Type", jsonCT).
				BodyString(`{"success": false, "error-codes": ["invalid-input-secret"]}`)
			resp := verify(apiSecret, gResponse, "")
			errInvalidInputSecretHelper(t, resp)
		})
		t.Run("missing key", func(t *testing.T) {
			defer gock.Off()
			gock.New(apiBase).
				Post(apiEndPoint).
				Reply(200).
				AddHeader("Content-Type", jsonCT).
				BodyString(`{"success": false, "error-codes": ["missing-input-secret"]}`)
			resp := verify(apiSecret, gResponse, "")
			errInvalidInputSecretHelper(t, resp)
		})
	}
}

func errInvalidInputSecretHelper(t *testing.T, resp recaptcha.Response) {
	t.Helper()
	if length := len(resp.Errors); length > 0 {
		if length != 1 {
			t.Errorf("the errors array should only contain one error but it contains: %+v", resp.Errors)
		}
		if resp.Errors[0] != recaptcha.ErrInvalidInputSecret {
			t.Errorf("the errors array should contain ErrInvalidInputSecret but it contains: %+v", resp.Errors)
		}
	} else {
		t.Error("the errors array should contain ErrInvalidInputSecret but it was empty")
	}
	if resp.Success {
		t.Error("response.Success should be false but it was not")
	}
}

func TestErrBadRequest(t *testing.T) {
	t.Run("V2", testErrBadRequest(recaptcha.Verify))
	t.Run("V3", testErrBadRequest(verifyV3))
}

func testErrBadRequest(verify verify) func(t *testing.T) {
	return func(t *testing.T) {
		defer gock.Off()
		gock.New(apiBase).
			Post(apiEndPoint).
			Reply(200).
			AddHeader("Content-Type", jsonCT).
			BodyString(`{"success": false, "error-codes": ["bad-request"]}`)
		resp := verify(apiSecret, gResponse, "")

		if length := len(resp.Errors); length > 0 {
			if length != 1 {
				t.Errorf("the errors array should only contain one error but it contains: %+v", resp.Errors)
			}
			if resp.Errors[0] != recaptcha.ErrBadRequest {
				t.Errorf("the errors array should contain ErrBadRequest but it contains: %+v", resp.Errors)
			}
		} else {
			t.Error("the errors array should contain ErrBadRequest but it was empty")
		}
		if resp.Success {
			t.Error("response.Success should be false but it was not")
		}
	}
}

func TestErrTimeoutOrDuplicate(t *testing.T) {
	t.Run("V2", testErrTimeoutOrDuplicate(recaptcha.Verify))
	t.Run("V3", testErrTimeoutOrDuplicate(verifyV3))
}

func testErrTimeoutOrDuplicate(verify verify) func(t *testing.T) {
	return func(t *testing.T) {
		defer gock.Off()
		gock.New(apiBase).
			Post(apiEndPoint).
			Reply(200).
			AddHeader("Content-Type", jsonCT).
			BodyString(`{"success": false, "error-codes": ["timeout-or-duplicate"]}`)
		resp := verify(apiSecret, gResponse, "")

		if length := len(resp.Errors); length > 0 {
			if length != 1 {
				t.Errorf("the errors array should only contain one error but it contains: %+v", resp.Errors)
			}
			if resp.Errors[0] != recaptcha.ErrTimeoutOrDuplicate {
				t.Errorf("the errors array should contain ErrTimeoutOrDuplicate but it contains: %+v", resp.Errors)
			}
		} else {
			t.Error("the errors array should contain ErrTimeoutOrDuplicate but it was empty")
		}
		if resp.Success {
			t.Error("response.Success should be false but it was not")
		}
	}
}

func TestUnknownAPIError(t *testing.T) {
	t.Run("V2", testUnknownAPIError(recaptcha.Verify))
	t.Run("V3", testUnknownAPIError(verifyV3))
}

func testUnknownAPIError(verify verify) func(t *testing.T) {
	return func(t *testing.T) {
		defer gock.Off()
		gock.New(apiBase).
			Post(apiEndPoint).
			Reply(200).
			AddHeader("Content-Type", jsonCT).
			BodyString(`{"success": false, "error-codes": ["a-new-error-code"]}`)
		resp := verify(apiSecret, gResponse, "")

		if length := len(resp.Errors); length > 0 {
			if length != 1 {
				t.Errorf("the errors array should only contain one error but it contains: %+v", resp.Errors)
			}
			if resp.Errors[0].Error() != "a-new-error-code" {
				t.Errorf("the errors array should contain an error with the \"a-new-error-code\" message but it contains: %+v", resp.Errors)
			}
		} else {
			t.Error("the errors array should contain an error with the \"a-new-error-code\" message but it was empty")
		}
		if resp.Success {
			t.Error("response.Success should be false but it was not")
		}
	}
}

func TestMultiError(t *testing.T) {
	t.Run("V2", testMultiError(recaptcha.Verify))
	t.Run("V3", testMultiError(verifyV3))
}

func testMultiError(verify verify) func(t *testing.T) {
	return func(t *testing.T) {
		defer gock.Off()
		gock.New(apiBase).
			Post(apiEndPoint).
			Reply(200).
			AddHeader("Content-Type", jsonCT).
			BodyString(`{"success": false, "error-codes": ["invalid-input-response", "invalid-input-secret"]}`)
		resp := verify(apiSecret, gResponse, "")

		if length := len(resp.Errors); length > 0 {
			if length != 2 {
				t.Errorf("the errors array should contain two error but it contains: %+v", resp.Errors)
			}
			if resp.Errors[0] != recaptcha.ErrInvalidInputResponse || resp.Errors[1] != recaptcha.ErrInvalidInputSecret {
				t.Errorf("the errors array should contain ErrInvalidInputResponse and ErrInvalidInputSecret but it constains: %+v", resp.Errors)
			}
		} else {
			t.Error("the errors array should contain two errors but it was empty")
		}
		if resp.Success {
			t.Error("response.Success should be false but it was not")
		}
	}
}

func TestUnexpectedError(t *testing.T) {
	t.Run("V2", testUnexpectedError(recaptcha.Verify))
	t.Run("V3", testUnexpectedError(verifyV3))
}

func testUnexpectedError(verify verify) func(t *testing.T) {
	return func(t *testing.T) {
		defer gock.Off()
		gock.New(apiBase).
			Post(apiEndPoint).
			Reply(200).
			AddHeader("Content-Type", jsonCT).
			BodyString(`{"success": "chocolate"}`)
		resp := verify(apiSecret, gResponse, "")

		if length := len(resp.Errors); length > 0 {
			if length != 1 {
				t.Errorf("the errors array should only contain one error but it contains: %+v", resp.Errors)
			}
			if !strings.Contains(resp.Errors[0].Error(), "Error unmarshalling the response body: json: cannot unmarshal string") {
				t.Errorf("the errors array should contain an error with the \"Error unmarshalling the response body: json: cannot unmarshal string\" message but it contains: %+v", resp.Errors)
			}
		} else {
			t.Error("the errors array should contain an error but it was empty")
		}
		if resp.Success {
			t.Error("response.Success should be false but it was not")
		}
	}
}

func TestV3ScoreAndAction(t *testing.T) {
	defer gock.Off()
	gock.New(apiBase).
		Post(apiEndPoint).
		Reply(200).
		AddHeader("Content-Type", jsonCT).
		BodyString(`{"success": true, "score": 0.8, "action": "test", "challenge_ts": "2019-10-20T16:09:06Z"}`)
	resp := recaptcha.VerifyV3(apiSecret, gResponse, "")
	if len(resp.Errors) != 0 {
		t.Errorf("the errors array should be empty but it contains: %+v", resp.Errors)
	}
	if !resp.Success {
		t.Error("response.Success should be true but it was not")
	}
	if resp.ChallengeTimeStamp != "2019-10-20T16:09:06Z" {
		t.Errorf("the timestamp has an unexpected value of %s", resp.ChallengeTimeStamp)
	}
	if resp.Score != 0.8 {
		t.Errorf("response.Success should be 0.8 but it was %f", resp.Score)
	}

	if resp.Action != "test" {
		t.Errorf("response.Success should be \"test\" but it was %s", resp.Action)
	}
}

func TestParseTimeStamp(t *testing.T) {
	tsStr := "2020-08-16T12:18:29Z"
	ts, err := recaptcha.ParseTimeStamp(tsStr)
	if err != nil {
		t.Errorf("unexpected error occurred: %w", err)
	}
	expectedTS := time.Date(2020, 8, 16, 12, 18, 29, 0, time.UTC)
	if !ts.Equal(expectedTS) {
		t.Errorf("The date was expected to be \"%v\" but got \"%v\"", expectedTS, ts)
	}
}
