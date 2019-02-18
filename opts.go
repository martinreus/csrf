package csrf

type Option func(*csrf)

/**
  Configure the token name to use when setting the Set-Cookie header.
  Defaults to CSRF-Token
 */
func CookieName(name string) Option {
    return func(c *csrf) {
        c.CookieOpts.CookieName = name
    }
}

/**
  Configure the CSRF-Token cookie max age.
  Defaults to 12 hours
*/
func MaxAge(age int) Option {
    return func(c *csrf) {
        c.CookieOpts.MaxAge = age
    }
}

/**
  Configure if the cookie should only be set over TLS connections.
  Defaults to true
*/
func Secure(secure bool) Option {
    return func(c *csrf) {
        c.CookieOpts.Secure = secure
    }
}

/**
  Configure the header name to be set by the client application, for which the value should match the cookie sent by the server.
  Defaults to X-CSRF-Token.
*/
func HeaderName(headerName string) Option {
    return func(c *csrf) {
        c.HeaderName = headerName
    }
}

