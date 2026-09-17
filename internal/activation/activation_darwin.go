//go:build darwin && cgo

package activation

/*
#include <launch.h>
#include <stdlib.h>
#include <errno.h>
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

func listenerFiles(name string) ([]*os.File, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	var fds *C.int
	var count C.size_t
	if rc := C.launch_activate_socket(cname, &fds, &count); rc != 0 {
		if rc == C.int(C.ESRCH) {
			return nil, nil
		}
		return nil, fmt.Errorf("launch_activate_socket(%q): errno %d", name, int(rc))
	}
	defer C.free(unsafe.Pointer(fds))

	if count == 0 {
		return nil, nil
	}
	slice := unsafe.Slice((*C.int)(fds), int(count))
	out := make([]*os.File, 0, int(count))
	for i, fd := range slice {
		out = append(out, os.NewFile(uintptr(fd), fmt.Sprintf("launchd-%s-%d", name, i)))
	}
	return out, nil
}

func available() bool {
	_, ok := os.LookupEnv("XPC_SERVICE_NAME")
	return ok
}
