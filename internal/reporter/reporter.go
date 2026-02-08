// Package reporter handles output generation for NHI-Watch scans.
//
// Phase 0: Stub — structure only.
//
// Future phases will implement:
//   - Table output (terminal-friendly, default)
//   - JSON output (machine-readable, pipeable to jq)
//   - YAML output (for GitOps integration)
//   - HTML report (for sharing with management / auditors)
//   - SARIF output (for GitHub Security tab integration)
//   - Summary view (type counts, risk distribution)
//   - Detail view (full NHI inventory with metadata)
package reporter
