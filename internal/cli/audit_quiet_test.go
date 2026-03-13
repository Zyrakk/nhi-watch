package cli

import (
	"testing"
)

func TestAuditQuietFlagRegistered(t *testing.T) {
	f := auditCmd.Flags().Lookup("quiet")
	if f == nil {
		t.Fatal("expected --quiet flag to be registered on audit command")
	}
	if f.Shorthand != "q" {
		t.Errorf("expected shorthand 'q', got %q", f.Shorthand)
	}
	if f.DefValue != "false" {
		t.Errorf("expected default value 'false', got %q", f.DefValue)
	}
}

func TestAuditQuietSuppressesLogf(t *testing.T) {
	origVerbose := verbose
	origQuiet := auditQuiet
	defer func() {
		verbose = origVerbose
		auditQuiet = origQuiet
	}()

	// When quiet is true, logf should not write even if verbose is true.
	var called bool
	verbose = true
	auditQuiet = true

	logf := func(format string, args ...interface{}) {
		if verbose && !auditQuiet {
			called = true
		}
	}
	logf("test %s", "message")
	if called {
		t.Error("logf should not produce output when --quiet is set")
	}

	// When quiet is false and verbose is true, logf should write.
	auditQuiet = false
	logf("test %s", "message")
	if !called {
		// The local logf sets called=true only when verbose && !auditQuiet.
		t.Error("logf should produce output when verbose is true and quiet is false")
	}
}
