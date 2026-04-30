package main

import "github.com/0xbbuddha/wazuh-cli/cmd"

var version = "dev"

func main() {
	cmd.Execute(version)
}
