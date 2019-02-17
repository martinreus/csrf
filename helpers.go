package csrf

// contains is a helper function to check if a string exists in a slice - e.g.
// whether a HTTP method exists in a list of safe methods.
func contains(vals []string, s string) bool {
    for _, v := range vals {
        if v == s {
            return true
        }
    }

    return false
}