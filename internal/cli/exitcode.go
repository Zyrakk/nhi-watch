package cli

import "fmt"

// ExitCodeError is an error that carries a specific process exit code.
// The main function should check for this and call os.Exit with the code.
type ExitCodeError struct {
	Code    int
	Message string
}

func (e *ExitCodeError) Error() string {
	return e.Message
}

// NewExitCodeError creates an ExitCodeError with the given code and formatted message.
func NewExitCodeError(code int, format string, args ...interface{}) *ExitCodeError {
	return &ExitCodeError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}
