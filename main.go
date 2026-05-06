package main

import (
	"flag"
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
	_ = fs.Parse(os.Args[1:])

	cmd.RunREPL(version, cmd.StartupFlags{
		Server:   *server,
		User:     *user,
		Password: *password,
		Insecure: *insecure,
	})
}
