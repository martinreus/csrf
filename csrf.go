package csrf

import (
    "fmt"
    "github.com/google/uuid"
    "net/http"
)

type cookieOpts struct {
    // Cookie name. Defaults to CSRF-Token
    CookieName string
    CookiePath string
    HttpOnly   bool
    Secure     bool
    MaxAge     int
}

type csrf struct {
    CookieOpts cookieOpts
    // Header name which the client of the JSON Api needs to set when sending a request for non-idempotent methods.
    // Defaults to X-CSRF-Token
    HeaderName string
    // defaultAge sets the default MaxAge for cookies.
    NextHandler http.Handler
}

var (
    // Idempotent (safe) methods as defined by RFC7231 section 4.2.2.
    safeMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}
)

func CookieCSRF(options ...Option) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        csrfInstance := &csrf{
            CookieOpts: cookieOpts{
                CookieName: "CSRF-Token",
                MaxAge:     3600 * 12,
                Secure:     true,  // always transmit sensible data only over TLS connections!
                HttpOnly:   false, // should be readable by the client, so that it can be set in the headers of a request. Be sure to protect against XSS attacks
                CookiePath: "/",
            },
            HeaderName:  "X-CSRF-Token",
            NextHandler: next,
        }

        // override default values with ones set by user
        for _, option := range options {
            option(csrfInstance)
        }

        return csrfInstance
    }
}

func (instance *csrf) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // check if request method requires CSRF token to be checked
    if !contains(safeMethods, r.Method) {
        // if it does, check if user has a CSRF-Token Cookie and its corresponding X-CSRF-Token header value.
        // Check if they match. If so, call the next handler in chain. If it doesn't, deny access.
        backendSetCookie, err := r.Cookie(instance.CookieOpts.CookieName)
        if err != nil || backendSetCookie == nil || backendSetCookie.Value == "" {
            http.Error(w, "Missing CSRF cookie.", http.StatusForbidden)
            return
        }

        frontEndHeaderValue := r.Header.Get(instance.HeaderName)
        // checks if CSRF value set by the user in the front end matches with the cookie set by the backend
        if !(frontEndHeaderValue == "" || backendSetCookie.Value == frontEndHeaderValue) {
            // if it doesn't, write unauthorized
            http.Error(w,
                fmt.Sprintf("%s and %s values do not match.",
                    instance.CookieOpts.CookieName, instance.HeaderName),
                http.StatusForbidden)
            return
        }
    }

    // For each request create a new CSRF-Token in order to mitigate BREACH attacks.
    instance.writeNewCSRFCookie(w)
    instance.NextHandler.ServeHTTP(w, r)
}

/**
  Writes a new CSRF Cookie with a randomly generated UUID.
*/
func (instance *csrf) writeNewCSRFCookie(w http.ResponseWriter) {
    cookieOpts := instance.CookieOpts

    http.SetCookie(w, &http.Cookie{
        Secure:   cookieOpts.Secure,
        HttpOnly: cookieOpts.HttpOnly, // should be readable by the client side.
        Path:     cookieOpts.CookiePath,
        MaxAge:   cookieOpts.MaxAge,
        Name:     cookieOpts.CookieName,
        Value:    uuid.New().String(),
    })
}
