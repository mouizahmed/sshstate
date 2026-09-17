package cli

import (
	"bytes"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func openPTY(t *testing.T) (*os.File, string) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	t.Cleanup(func() { master.Close() })
	if err := unix.IoctlSetInt(int(master.Fd()), unix.TIOCPTYGRANT, 0); err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	if err := unix.IoctlSetInt(int(master.Fd()), unix.TIOCPTYUNLK, 0); err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	var name [128]byte
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, master.Fd(), uintptr(unix.TIOCPTYGNAME), uintptr(unsafe.Pointer(&name[0]))); errno != 0 {
		t.Skipf("no pseudo-terminal available: %v", errno)
	}
	path := string(name[:bytes.IndexByte(name[:], 0)])
	held, err := os.OpenFile(path, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	t.Cleanup(func() { held.Close() })
	return master, path
}
