package cli

import (
	"bytes"
	"testing"
)

func TestVersionInfoString(t *testing.T) {
	originalVersion := Version
	originalCommit := Commit
	originalBuildDate := BuildDate
	t.Cleanup(func() {
		Version = originalVersion
		Commit = originalCommit
		BuildDate = originalBuildDate
	})

	Version = "v1.2.3"
	Commit = "abc1234"
	BuildDate = "2026-03-08T00:00:00Z"

	got := versionInfoString()
	want := "version=v1.2.3 commit=abc1234 buildDate=2026-03-08T00:00:00Z"
	if got != want {
		t.Fatalf("versionInfoString() = %q, want %q", got, want)
	}
}

func TestRefreshRootVersion(t *testing.T) {
	originalVersion := Version
	originalCommit := Commit
	originalBuildDate := BuildDate
	originalRootVersion := rootCmd.Version
	t.Cleanup(func() {
		Version = originalVersion
		Commit = originalCommit
		BuildDate = originalBuildDate
		rootCmd.Version = originalRootVersion
	})

	Version = "v9.9.9"
	Commit = "deadbee"
	BuildDate = "2026-03-08T12:34:56Z"
	refreshRootVersion()

	want := "version=v9.9.9 commit=deadbee buildDate=2026-03-08T12:34:56Z"
	if rootCmd.Version != want {
		t.Fatalf("rootCmd.Version = %q, want %q", rootCmd.Version, want)
	}
}

func TestPrintVersionInfo(t *testing.T) {
	originalVersion := Version
	originalCommit := Commit
	originalBuildDate := BuildDate
	t.Cleanup(func() {
		Version = originalVersion
		Commit = originalCommit
		BuildDate = originalBuildDate
	})

	Version = "v0.4.0"
	Commit = "beef123"
	BuildDate = "2026-03-08T09:10:11Z"

	var buf bytes.Buffer
	printVersionInfo(&buf)

	want := "version=v0.4.0 commit=beef123 buildDate=2026-03-08T09:10:11Z\n"
	if buf.String() != want {
		t.Fatalf("printVersionInfo() = %q, want %q", buf.String(), want)
	}
}
