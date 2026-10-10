//go:build !windows

package flock

import (
	"errors"
	"os"
	"syscall"
)

// lockFile takes an exclusive flock without blocking. flock locks belong to
// the open file, so two opens of the same path conflict even in one process.
func lockFile(file *os.File) error {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) // #nosec G115 -- fd fits in int
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return errBusy
	}
	return err
}
