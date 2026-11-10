package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/ltchurik/mcp-jail/internal/doctor"
	"github.com/ltchurik/mcp-jail/internal/lock"
)

// cmdDoctor reports what this host can do: native sandbox, user
// namespaces, docker/podman, state directory. Exit 1 when no sandbox at
// all is usable.
func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print as JSON")
	fs.Usage = usage
	if err := fs.Parse(args); err != nil {
		return err
	}
	r := doctor.Run(doctor.RealHost(lock.Dir()), version)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return err
		}
	} else {
		fmt.Printf("mcp-jail %s on %s/%s\n", r.Version, r.OS, r.Arch)
		for _, c := range r.Checks {
			fmt.Printf("%-8s %-16s %s\n", c.Status, c.Name, c.Detail)
			if c.Hint != "" {
				fmt.Printf("%-8s %-16s -> %s\n", "", "", c.Hint)
			}
		}
		fmt.Printf("%-8s %s\n", "summary", r.Summary)
	}
	if !r.Usable {
		return exitCode(1)
	}
	return nil
}
