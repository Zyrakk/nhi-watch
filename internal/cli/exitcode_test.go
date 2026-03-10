package cli

import (
	"errors"
	"testing"
)

func TestExitCodeError_Error(t *testing.T) {
	e := NewExitCodeError(2, "FAIL: %d findings", 5)
	if e.Error() != "FAIL: 5 findings" {
		t.Errorf("got %q", e.Error())
	}
	if e.Code != 2 {
		t.Errorf("expected code 2, got %d", e.Code)
	}
}

func TestExitCodeError_ErrorsAs(t *testing.T) {
	e := NewExitCodeError(2, "test")
	var wrapped error = e
	var target *ExitCodeError
	if !errors.As(wrapped, &target) {
		t.Error("errors.As should match ExitCodeError")
	}
	if target.Code != 2 {
		t.Errorf("expected code 2, got %d", target.Code)
	}
}
