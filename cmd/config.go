package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show current configuration",
		Aliases: []string{"c"},
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("%-20s %s\n", "API URL:", cfg.APIURL)
			fmt.Printf("%-20s %s\n", "Auth User:", cfg.Auth.Username)
			fmt.Printf("%-20s %s\n", "Indexer URL:", cfg.Indexer.URL)
			fmt.Printf("%-20s %s\n", "Indexer User:", cfg.Indexer.Username)
			fmt.Printf("%-20s %v\n", "Insecure TLS:", cfg.Insecure)
		},
	}
	return cmd
}
