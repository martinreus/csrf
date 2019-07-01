## CSRF Protection middleware for Go

This library implements a very lean CSRF filter for go applications, focused on REST API's.

If you want to protect your backend with a more complete version, which is able to issue CSRF tokens that may be used in HTML rendering in the backend, see https://github.com/gorilla/csrf, which inspired this one. 

### HOW TO USE
#### Backend

```go
package main

import (
    "github.com/gorilla/mux"
    "github.com/martinreus/csrf"
)

func main() {
    r := mux.NewRouter()
    csrfMiddleware := csrf.CookieCSRF()

    api := r.PathPrefix("/api").Subrouter()
    api.Use(csrfMiddleware)
    api.HandleFunc("/user/{id}", GetUser).Methods("GET")
    api.HandleFunc("/user/{id}", UpdateUser).Methods("POST")

    http.ListenAndServe(":8000", r)
}

func GetUser(w http.ResponseWriter, r *http.Request) {...}

func UpdateUser(w http.ResponseWriter, r *http.Request) {...}
```

#### Front end
Just read the value received in cookie "XSRF-TOKEN" and send it in a header named "X-XSRF-TOKEN" of a new request.

Hint: nothing needs to be done for Angular apps, as angular already handles this automatically for us ;)

### TODO

- Tests!!!!!!! Help is welcome =D
- Generate HMAC token instead of purely UUID generated one. This is to prevent clients generating and setting Cookies on the fly. Does not however solve XSS attacks, which still have to be prevented by the front end framework of your choice.

### I WANT TO HELP
Yes, please

