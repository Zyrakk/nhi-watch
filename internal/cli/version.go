package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func versionInfoString() string {
	return fmt.Sprintf("version=%s commit=%s buildDate=%s", Version, Commit, BuildDate)
}

func refreshRootVersion() {
	rootCmd.Version = versionInfoString()
}

func printVersionInfo(w io.Writer) {
	fmt.Fprintln(w, versionInfoString())
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the NHI-Watch version",
	Run: func(cmd *cobra.Command, args []string) {
		printVersionInfo(cmd.OutOrStdout())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
