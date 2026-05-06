package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/0xbbuddha/wazuh-cli/cmd"
)

var version = "dev"

func main() {
	fs := flag.NewFlagSet("wazuh-cli", flag.ExitOnError)
	server := fs.String("server", "", "Wazuh manager URL (overrides config)")
	user := fs.String("user", "", "API username (overrides config)")
	password := fs.String("password", "", "API password (overrides config)")
	insecure := fs.Bool("insecure", false, "Skip TLS certificate verification")
	ver := fs.Bool("version", false, "Print version and exit")
	_ = fs.Parse(os.Args[1:])

	if *ver {
		fmt.Printf("wazuh-cli %s\n", version)
		os.Exit(0)
	}

	cmd.RunREPL(version, cmd.StartupFlags{
		Server:   *server,
		User:     *user,
		Password: *password,
		Insecure: *insecure,
	})
}
