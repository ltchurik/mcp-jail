//go:build linux

package egress

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

const (
	prCapAmbient         = 47
	prCapAmbientClearAll = 4
)

// runServer starts the MCP server. The shim holds no capability: it binds
// :53/:80/:443 as our normal uid because the jail's network namespace treats
// no port as privileged (see sandbox.buildLinux). The server is still started
// in a nested user namespace with our ids mapped onto themselves, so it sees
// its usual ids and owns its usual files but shares nothing else with the
// shim's namespace; mapping one's own id needs no capability.
func runServer(argv []string, uid, gid int) (int, error) {
	// Ambient capabilities, should the jail ever hand some down, would
	// otherwise survive execve.
	_, _, _ = syscall.Syscall(syscall.SYS_PRCTL, prCapAmbient, prCapAmbientClearAll, 0)

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: uid, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: gid, HostID: os.Getgid(), Size: 1}},
		Pdeathsig:   syscall.SIGKILL,
	}
	if err := cmd.Start(); err != nil {
		return 1, err
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sig {
			_ = cmd.Process.Signal(s)
		}
	}()
	err := cmd.Wait()
	signal.Stop(sig)
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}
