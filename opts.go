package csrf

type Option func(*csrf)

/**
  Configure the token name to use when setting the Set-Cookie header.
 */
func CookieName(name string) Option {
    return func(c *csrf) {
        c.CookieName = name
    }
}

func DefaultAge(age int) Option {
    return func(c *csrf) {
        c.DefaultAge = age
    }
}