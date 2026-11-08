//go:build unix

package plugin

import (
	"fmt"
	"os"
	"syscall"
)

// checkPrivateDir verifies that dir is owned by the current user and not
// writable by anyone else.
func checkPrivateDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of %s", dir)
	}
	if int(st.Uid) != os.Getuid() || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("agent socket directory %s must be owned by the current user and not writable by others", dir)
	}
	return nil
}
