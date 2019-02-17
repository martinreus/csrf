package csrf

import (
    "net/http"
)


// Inspired by gorilla mux's csrf protection implementation :)

type csrf struct {
    // defaults to CSRF-Token
    CookieName string
    // Header name which the client of the JSON Api needs to set when sending a request for non-idempotent methods.
    // Defaults to X-CSRF-Token
    HeaderName string
    // defaultAge sets the default MaxAge for cookies.
    DefaultAge  int
    NextHandler http.Handler
    Secure      bool
}

var (
    // Idempotent (safe) methods as defined by RFC7231 section 4.2.2.
    safeMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}
)

func CookieCSRF(options ...Option) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        csrfInstance := &csrf{
            CookieName:  "CSRF-Token",
            HeaderName:  "X-CSRF-Token",
            DefaultAge:  3600 * 12,
            Secure: true,
            NextHandler: next,
        }

        // override default values with ones set by user
        for _, option := range options {
            option(csrfInstance)
        }

        return csrfInstance
    }
}

func (csrfInstance *csrf) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // check if request method requires CSRF token to be checked
    if !contains(safeMethods, r.Method) {
        // if it doesn't, simply set a new CSRF-Token Cookie in the response headers.
        // For each request, create a new CSRF-Token, so that we mitigate BREACH attacks.
        csrfInstance.generateCookie(w)
        csrfInstance.NextHandler.ServeHTTP(w, r)
        return
    } else {
        // if it does, check if user has a CSRF-Token Cookie and its corresponding X-CSRF-Token header value.
        // Check if they match. If so, call the next handler in chain. If it doesn't, deny access.

    }





    // generate new CSRF-Cookie, to prevent BREACH attack

}

func (csrfInstance *csrf) generateCookie(w http.ResponseWriter) {
    http.SetCookie(w, &http.Cookie{
        Secure: csrfInstance.Secure,
        HttpOnly: false, // always false, should be read by the client
    })
}