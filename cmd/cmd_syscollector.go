package cmd

import (
	"flag"
	"fmt"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func handleSyscollector(args []string) {
	if len(args) == 0 {
		handleHelp([]string{"syscollector"})
		return
	}
	switch args[0] {
	case "hardware":
		scHardware(args[1:])
	case "os":
		scOS(args[1:])
	case "packages":
		scPackages(args[1:])
	case "ports":
		scPorts(args[1:])
	case "processes":
		scProcesses(args[1:])
	case "netaddr":
		scNetAddr(args[1:])
	default:
		printUnknownSub("syscollector", args[0])
	}
}

func scHardware(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: syscollector hardware <agent_id> [-o json]"))
		return
	}
	fs := flag.NewFlagSet("syscollector hardware", flag.ContinueOnError)
	outFmt := fs.String("o", "table", "Output format: table or json")
	agentID := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return
	}
	output.Format = *outFmt

	sc := api.NewSyscollectorAPI(managerClient)
	hw, err := sc.Hardware(agentID)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(hw)
		return
	}
	fmt.Println("CPU:")
	output.Field("  Name", hw.CPU.Name)
	output.Field("  Cores", fmt.Sprintf("%d", hw.CPU.Cores))
	output.Field("  MHz", fmt.Sprintf("%.0f", hw.CPU.Mhz))
	fmt.Println("RAM:")
	output.Field("  Total (kB)", fmt.Sprintf("%d", hw.RAM.Total))
	output.Field("  Free (kB)", fmt.Sprintf("%d", hw.RAM.Free))
	output.Field("  Usage (%)", fmt.Sprintf("%d", hw.RAM.Usage))
	fmt.Println("Scan:")
	output.Field("  ID", fmt.Sprintf("%d", hw.Scan.ID))
	output.Field("  Time", hw.Scan.Time)
}

func scOS(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: syscollector os <agent_id> [-o json]"))
		return
	}
	fs := flag.NewFlagSet("syscollector os", flag.ContinueOnError)
	outFmt := fs.String("o", "table", "Output format: table or json")
	agentID := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return
	}
	output.Format = *outFmt

	sc := api.NewSyscollectorAPI(managerClient)
	info, err := sc.OS(agentID)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(info)
		return
	}
	output.Field("Hostname", info.Hostname)
	output.Field("OS Name", info.Os.Name)
	output.Field("Version", info.Os.Version)
	output.Field("Platform", info.Os.Platform)
	output.Field("Codename", info.Os.Codename)
	output.Field("Architecture", info.Architecture)
	output.Field("Kernel", info.Release)
}

func scPackages(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: syscollector packages <agent_id> [--search S] [--limit N]"))
		return
	}
	fs := flag.NewFlagSet("syscollector packages", flag.ContinueOnError)
	search := fs.String("search", "", "Filter packages by name")
	limit := fs.Int("limit", 500, "Maximum number of results")
	outFmt := fs.String("o", "table", "Output format: table or json")
	agentID := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return
	}
	output.Format = *outFmt

	sc := api.NewSyscollectorAPI(managerClient)
	pkgs, total, err := sc.Packages(agentID, *search, *limit)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(pkgs)
		return
	}
	output.ShowCount(len(pkgs), total, "packages")
	t := output.NewTable("NAME", "VERSION", "ARCH", "VENDOR", "FORMAT")
	for _, p := range pkgs {
		t.Row(p.Name, p.Version, p.Architecture, p.Vendor, p.Format)
	}
	t.Flush()
}

func scPorts(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: syscollector ports <agent_id> [--limit N]"))
		return
	}
	fs := flag.NewFlagSet("syscollector ports", flag.ContinueOnError)
	limit := fs.Int("limit", 500, "Maximum number of results")
	outFmt := fs.String("o", "table", "Output format: table or json")
	agentID := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return
	}
	output.Format = *outFmt

	sc := api.NewSyscollectorAPI(managerClient)
	ports, total, err := sc.Ports(agentID, *limit)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(ports)
		return
	}
	output.ShowCount(len(ports), total, "ports")
	t := output.NewTable("PROTO", "LOCAL", "STATE", "PID", "PROCESS")
	for _, p := range ports {
		t.Row(p.Protocol, fmt.Sprintf("%s:%d", p.Local.IP, p.Local.Port),
			p.State, fmt.Sprintf("%d", p.PID), p.Process)
	}
	t.Flush()
}

func scProcesses(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: syscollector processes <agent_id> [--limit N]"))
		return
	}
	fs := flag.NewFlagSet("syscollector processes", flag.ContinueOnError)
	limit := fs.Int("limit", 500, "Maximum number of results")
	outFmt := fs.String("o", "table", "Output format: table or json")
	agentID := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return
	}
	output.Format = *outFmt

	sc := api.NewSyscollectorAPI(managerClient)
	procs, total, err := sc.Processes(agentID, *limit)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(procs)
		return
	}
	output.ShowCount(len(procs), total, "processes")
	t := output.NewTable("PID", "PPID", "USER", "STATE", "NAME", "CMD")
	for _, p := range procs {
		t.Row(p.PID, fmt.Sprintf("%d", p.PPID), p.Euser, p.State, p.Name, output.Truncate(p.Cmd, 40))
	}
	t.Flush()
}

func scNetAddr(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: syscollector netaddr <agent_id> [-o json]"))
		return
	}
	fs := flag.NewFlagSet("syscollector netaddr", flag.ContinueOnError)
	outFmt := fs.String("o", "table", "Output format: table or json")
	agentID := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return
	}
	output.Format = *outFmt

	sc := api.NewSyscollectorAPI(managerClient)
	addrs, err := sc.NetAddr(agentID)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(addrs)
		return
	}
	t := output.NewTable("IFACE", "PROTO", "ADDRESS", "NETMASK", "BROADCAST")
	for _, a := range addrs {
		t.Row(a.Iface, a.Proto, a.Address, a.Netmask, a.Broadcast)
	}
	t.Flush()
}
