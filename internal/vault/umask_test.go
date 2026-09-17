//go:build unix

package vault

import "syscall"

func syscallUmask(mask int) int { return syscall.Umask(mask) }
