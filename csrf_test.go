package csrf

import (
    "encoding/json"
    "fmt"
    "net/http"
    "testing"
)

func TestShouldSetDefaults(t *testing.T) {
    // given
    var nextHandler http.Handler
    expected := csrfConfig{CookieOpts: cookieOpts{
            CookieName: "XSRF-TOKEN",
            CookiePath: "/",
            HttpOnly: false,
            MaxAge: 43200,
            Secure: true,
        },
        HeaderName: "X-XSRF-TOKEN",
        NextHandler: nextHandler,
    }
    expectedBytes, _ := json.Marshal(expected)

    // when
    cookieCSRF := CookieCSRF()
    config := cookieCSRF(nextHandler)
    configBytes, _ := json.Marshal(config)

    // then
    if config != expected {
        t.Error(fmt.Sprintf("expected CSRF config is different than config. \n Expected: %s \n Generated: %s", string(expectedBytes), string(configBytes)))
    }
}

func TestShouldSetDefaultWithChangedOptions(t *testing.T) {
    // given
    var nextHandler http.Handler
    expected := csrfConfig{CookieOpts: cookieOpts{
            CookieName: "ASD",
            CookiePath: "/",
            HttpOnly: false,
            MaxAge: 10,
            Secure: false,
        },
        HeaderName: "XASD",
        NextHandler: nextHandler,
    }
    expectedBytes, _ := json.Marshal(expected)

    // when
    cookieCSRF := CookieCSRF(Secure(false), MaxAge(10), CookieName("ASD"), HeaderName("XASD"))
    config := cookieCSRF(nextHandler)
    configBytes, _ := json.Marshal(config)

    // then
    if config != expected {
        t.Error(fmt.Sprintf("expected CSRF config is different than config. \n Expected: %s \n Generated: %s", string(expectedBytes), string(configBytes)))
    }
}

