package ctxflow

// SetHelperArgs sets helper id's argument count in the transformer's table
// and returns a function that restores it.
func SetHelperArgs(id int, n byte) (restore func()) {
	old := helperArgs
	b := []byte(helperArgs)
	b[id] = '0' + n
	helperArgs = string(b)
	return func() { helperArgs = old }
}
