package csrf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

/**
  TODO: Remove repeated code :)
*/
var emptyMap = make(map[string]string)

func TestShouldSetDefaults(t *testing.T) {
	// given
	var nextHandler http.Handler

	// when
	cookieCSRF := CookieCSRF()
	config := cookieCSRF(nextHandler)

	// then
	if actual, ok := config.(csrfConfig); ok {
		if actual.HeaderName != "X-XSRF-TOKEN" ||
			actual.NextHandler != nextHandler ||
			actual.SkipUserAgents != nil ||
			actual.CookieOpts.Secure != true ||
			actual.CookieOpts.CookiePath != "/" ||
			actual.CookieOpts.HttpOnly != false ||
			actual.CookieOpts.MaxAge != 43200 ||
			actual.CookieOpts.CookieName != "XSRF-TOKEN" {
			t.Error("expected CSRF config is different than config.")
		}
	} else {
		t.Error("Cannot cast config to csrfConfig")
	}
}

func TestShouldSetDefaultWithChangedOptions(t *testing.T) {
	// given
	var nextHandler http.Handler

	// when
	cookieCSRF := CookieCSRF(Secure(false), MaxAge(10), CookieName("ASD"), HeaderName("XASD"), SkipUserAgents("Test"))
	config := cookieCSRF(nextHandler)

	if actual, ok := config.(csrfConfig); ok {
		if actual.HeaderName != "XASD" ||
			actual.NextHandler != nextHandler ||
			!reflect.DeepEqual(actual.SkipUserAgents, []string{"Test"}) ||
			actual.CookieOpts.Secure != false ||
			actual.CookieOpts.CookiePath != "/" ||
			actual.CookieOpts.HttpOnly != false ||
			actual.CookieOpts.MaxAge != 10 ||
			actual.CookieOpts.CookieName != "ASD" {
			t.Error("expected CSRF config is different than config.")
		}
	} else {
		t.Error("Cannot cast config to csrfConfig")
	}
}

func TestSkippingMiddlewareWhenNonBrowser(t *testing.T) {
	// given
	nextHandler := mockHandler{}
	csrfHandler := CookieCSRF(SkipUserAgents("Test"))(&nextHandler)

	headers := make(map[string]string)
	headers["User-Agent"] = "Test"

	req, rr := reqAndResponses(t, "POST", headers, emptyMap)
	handler := http.HandlerFunc(csrfHandler.ServeHTTP)

	// when
	handler.ServeHTTP(rr, req)

	// then
	if !nextHandler.WasInvoked {
		t.Error("Next handler method was not invoked when it should have been.")
	}
}

func TestShouldNotInvokeNextHandlerWhenNonBrowserAndNoSkipping(t *testing.T) {
	// given
	nextHandler, csrfHandler := newCSRFHandler()

	req, rr := reqAndResponses(t, "POST", emptyMap, emptyMap)
	handler := http.HandlerFunc(csrfHandler.ServeHTTP)

	// when
	handler.ServeHTTP(rr, req)

	// then
	if nextHandler.WasInvoked {
		t.Error("Next handler method was invoked when it should not have been.")
	}
}

func TestShouldSkipWhenGetMethod(t *testing.T) {
	// given
	nextHandler, csrfHandler := newCSRFHandler()

	req, rr := reqAndResponses(t, "GET", emptyMap, emptyMap)
	handler := http.HandlerFunc(csrfHandler.ServeHTTP)

	// when
	handler.ServeHTTP(rr, req)

	// then
	if !nextHandler.WasInvoked {
		t.Error("Next handler method was not invoked when it should have been.")
	}
}

func TestShouldNotInvokeNextHandlerWhenIsBrowserAndNoCSRFHeaderIsFound(t *testing.T) {
	// given
	nextHandler := mockHandler{}
	// bonus: we skip non browsers, effectively checking if it enters the check, which it should
	csrfHandler := CookieCSRF()(&nextHandler)

	headers := make(map[string]string)
	headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.90 Mobile Safari/537.36"

	req, rr := reqAndResponses(t, "POST", headers, emptyMap)
	handler := http.HandlerFunc(csrfHandler.ServeHTTP)

	// when
	handler.ServeHTTP(rr, req)

	// then
	if nextHandler.WasInvoked {
		t.Error("Next handler method was invoked when it should not have been.")
	}
	if rr.Result().StatusCode != http.StatusForbidden {
		t.Error(fmt.Sprintf("Status should be forbidden, was %s.", rr.Result().Status))
	}
	bytes := make([]byte, 100)
	closer := rr.Result().Body
	defer closer.Close()

	if read, err := closer.Read(bytes); err == nil {
		body := string(bytes[0 : read-1])
		if body != "Missing CSRF cookie." {
			t.Error(fmt.Sprintf("Body should be 'Missing CSRF cookie.', was '%s'", body))
		}
	} else {
		t.Error("Could not read response body!")
	}
}

func TestShouldNotInvokeNextHandlerWhenIsBrowserAndNoXSRFHeaderIsFound(t *testing.T) {
	// given
	nextHandler := mockHandler{}
	// bonus: we skip non browsers, effectively checking if it enters the check, which it should
	csrfHandler := CookieCSRF(SkipUserAgents("Test"))(&nextHandler)

	headers := make(map[string]string)
	headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.90 Mobile Safari/537.36"

	cookies := make(map[string]string)
	cookies["XSRF-TOKEN"] = "SOMETHING"

	req, rr := reqAndResponses(t, "POST", headers, cookies)
	handler := http.HandlerFunc(csrfHandler.ServeHTTP)

	// when
	handler.ServeHTTP(rr, req)

	// then
	if nextHandler.WasInvoked {
		t.Error("Next handler method was invoked when it should not have been.")
	}
	if rr.Result().StatusCode != http.StatusForbidden {
		t.Error(fmt.Sprintf("Status should be forbidden, was %s.", rr.Result().Status))
	}
	bytes := make([]byte, 100)
	closer := rr.Result().Body
	defer closer.Close()

	if read, err := closer.Read(bytes); err == nil {
		body := string(bytes[0 : read-1])
		if body != "XSRF-TOKEN and X-XSRF-TOKEN values do not match." {
			t.Error(fmt.Sprintf("Body should be 'XSRF-TOKEN and X-XSRF-TOKEN values do not match.', was '%s'", body))
		}
	} else {
		t.Error("Could not read response body!")
	}
}

func TestShouldNotInvokeNextHandlerWhenIsBrowserAndNoCSRFHeaderAndCookiesDoNotMatch(t *testing.T) {
	// given
	nextHandler := mockHandler{}
	// bonus: we skip non browsers, effectively checking if it enters the check, which it should
	csrfHandler := CookieCSRF(SkipUserAgents("Test"))(&nextHandler)

	headers := make(map[string]string)
	headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.90 Mobile Safari/537.36"
	headers["X-XSRF-TOKEN"] = "SOMETHING WHICH IS DIFFERENT FROM COOKIE"

	cookies := make(map[string]string)
	cookies["XSRF-TOKEN"] = "SOMETHING"

	req, rr := reqAndResponses(t, "POST", headers, cookies)
	handler := http.HandlerFunc(csrfHandler.ServeHTTP)

	// when
	handler.ServeHTTP(rr, req)

	// then
	if nextHandler.WasInvoked {
		t.Error("Next handler method was invoked when it should not have been.")
	}
	if rr.Result().StatusCode != http.StatusForbidden {
		t.Error(fmt.Sprintf("Status should be forbidden, was %s.", rr.Result().Status))
	}
	bytes := make([]byte, 100)
	closer := rr.Result().Body
	defer closer.Close()

	if read, err := closer.Read(bytes); err == nil {
		body := string(bytes[0 : read-1])
		if body != "XSRF-TOKEN and X-XSRF-TOKEN values do not match." {
			t.Error(fmt.Sprintf("Body should be 'XSRF-TOKEN and X-XSRF-TOKEN values do not match.', was '%s'", body))
		}
	} else {
		t.Error("Could not read response body!")
	}
}

func TestShouldSuccessfullyInvokeNextHandlerWhenIsBrowserAndCSRFHeaderAndCookiesMatch(t *testing.T) {
	// given
	nextHandler := mockHandler{}
	// bonus: we skip non browsers, effectively checking if it enters the check, which it should
	csrfHandler := CookieCSRF(SkipUserAgents(""))(&nextHandler)

	headers := make(map[string]string)
	headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.90 Mobile Safari/537.36"
	headers["X-XSRF-TOKEN"] = "SOMETHING"

	cookies := make(map[string]string)
	cookies["XSRF-TOKEN"] = "SOMETHING"

	req, rr := reqAndResponses(t, "POST", headers, cookies)
	handler := http.HandlerFunc(csrfHandler.ServeHTTP)

	// when
	handler.ServeHTTP(rr, req)

	// then
	if !nextHandler.WasInvoked {
		t.Error("Next handler method was not invoked when it should have been.")
	}
	bytes := make([]byte, 100)
	closer := rr.Result().Body
	defer closer.Close()

	if _, err := closer.Read(bytes); err == nil {
		t.Error("Could read response body, when we should not have written anything!")
	}
}

func reqAndResponses(t *testing.T, method string, headers map[string]string, cookies map[string]string) (*http.Request, *httptest.ResponseRecorder) {
	req, err := http.NewRequest(method, "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	for key, value := range cookies {
		req.AddCookie(&http.Cookie{Name: key, Value: value})
	}

	rr := httptest.NewRecorder()
	return req, rr
}

func newCSRFHandler() (*mockHandler, http.Handler) {
	mockHandler := &mockHandler{}
	csrfHandler := CookieCSRF()(mockHandler)

	return mockHandler, csrfHandler
}

type mockHandler struct {
	WasInvoked bool
}

func (mh *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mh.WasInvoked = true
}
