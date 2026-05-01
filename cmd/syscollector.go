package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func newSyscollectorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "syscollector",
		Short:   "System inventory for an agent",
		Aliases: []string{"s"},
	}

	// hardware
	cmd.AddCommand(&cobra.Command{
		Use:   "hardware <agent_id>",
		Short: "Show hardware info (CPU, RAM)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			sc := api.NewSyscollectorAPI(managerClient)
			hw, err := sc.Hardware(args[0])
			if err != nil {
				die(err)
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
		},
	})

	// os
	cmd.AddCommand(&cobra.Command{
		Use:   "os <agent_id>",
		Short: "Show OS information",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			sc := api.NewSyscollectorAPI(managerClient)
			info, err := sc.OS(args[0])
			if err != nil {
				die(err)
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
		},
	})

	// packages
	var (
		search string
		limit  int
	)
	pkgCmd := &cobra.Command{
		Use:   "packages <agent_id>",
		Short: "List installed packages",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			sc := api.NewSyscollectorAPI(managerClient)
			pkgs, total, err := sc.Packages(args[0], search, limit)
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(pkgs)
				return
			}
			fmt.Printf("Showing %d of %d packages\n\n", len(pkgs), total)
			t := output.NewTable("NAME", "VERSION", "ARCH", "VENDOR", "FORMAT")
			for _, p := range pkgs {
				t.Row(p.Name, p.Version, p.Architecture, p.Vendor, p.Format)
			}
			t.Flush()
		},
	}
	pkgCmd.Flags().StringVar(&search, "search", "", "Filter packages by name")
	pkgCmd.Flags().IntVar(&limit, "limit", 500, "Maximum number of results")
	cmd.AddCommand(pkgCmd)

	// ports
	var portsLimit int
	portsCmd := &cobra.Command{
		Use:   "ports <agent_id>",
		Short: "List open / listening ports",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			sc := api.NewSyscollectorAPI(managerClient)
			ports, total, err := sc.Ports(args[0], portsLimit)
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(ports)
				return
			}
			fmt.Printf("Showing %d of %d ports\n\n", len(ports), total)
			t := output.NewTable("PROTO", "LOCAL", "STATE", "PID", "PROCESS")
			for _, p := range ports {
				t.Row(p.Protocol, fmt.Sprintf("%s:%d", p.Local.IP, p.Local.Port),
					p.State, fmt.Sprintf("%d", p.PID), p.Process)
			}
			t.Flush()
		},
	}
	portsCmd.Flags().IntVar(&portsLimit, "limit", 500, "Maximum number of results")
	cmd.AddCommand(portsCmd)

	// processes
	var procLimit int
	procCmd := &cobra.Command{
		Use:   "processes <agent_id>",
		Short: "List running processes",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			sc := api.NewSyscollectorAPI(managerClient)
			procs, total, err := sc.Processes(args[0], procLimit)
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(procs)
				return
			}
			fmt.Printf("Showing %d of %d processes\n\n", len(procs), total)
			t := output.NewTable("PID", "PPID", "USER", "STATE", "NAME", "CMD")
			for _, p := range procs {
				t.Row(p.PID, fmt.Sprintf("%d", p.PPID),
					p.Euser, p.State, p.Name, output.Truncate(p.Cmd, 40))
			}
			t.Flush()
		},
	}
	procCmd.Flags().IntVar(&procLimit, "limit", 500, "Maximum number of results")
	cmd.AddCommand(procCmd)

	// netaddr
	cmd.AddCommand(&cobra.Command{
		Use:   "netaddr <agent_id>",
		Short: "Show network addresses",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			sc := api.NewSyscollectorAPI(managerClient)
			addrs, err := sc.NetAddr(args[0])
			if err != nil {
				die(err)
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
		},
	})

	return cmd
}
