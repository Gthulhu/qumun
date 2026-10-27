// SPDX-License-Identifier: Apache-2.0

package schedbridge

// Cgo cannot be imported from _test.go; these helpers support syscall tests.

/*
#include <errno.h>
#include <stdint.h>
#include <unistd.h>

struct qumun_read_args {
    int fd;
    int error;
    unsigned char value;
};

void qumun_read_byte(void *opaque) {
    struct qumun_read_args *args = opaque;
    ssize_t ret;
    do {
        ret = read(args->fd, &args->value, 1);
    } while (ret < 0 && errno == EINTR);
    args->error = ret == 1 ? 0 : (ret < 0 ? errno : EPIPE);
}

void qumun_getpid(void *opaque) {
    *(int64_t *)opaque = getpid();
}
*/
import "C"

import (
	"syscall"
	"unsafe"
)

// These helpers exercise syscall scheduling without BPF privileges.
func readByte(fd int) (byte, error) {
	args := C.struct_qumun_read_args{fd: C.int(fd)}
	CallSyscall(unsafe.Pointer(C.qumun_read_byte), unsafe.Pointer(&args))
	if args.error != 0 {
		return 0, syscall.Errno(args.error)
	}
	return byte(args.value), nil
}

func callGetpid() int64 {
	var pid int64
	CallSyscall(unsafe.Pointer(C.qumun_getpid), unsafe.Pointer(&pid))
	return pid
}

func cgoGetpid() int64 {
	return int64(C.getpid())
}
