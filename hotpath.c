// SPDX-License-Identifier: Apache-2.0

#include "hotpath.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

void c_select_cpu_wrapper(void *opaque) {
    struct qumun_select_args *args = opaque;
    union bpf_attr attr = {};
    attr.test.prog_fd = args->fd;
    attr.test.ctx_in = (uintptr_t)&args->context;
    attr.test.ctx_size_in = sizeof(args->context);
    int ret = syscall(__NR_bpf, BPF_PROG_TEST_RUN, &attr, sizeof(attr));
    /* Match cilium/ebpf's single-run EINTR handling: do not run it twice. */
    args->error = ret < 0 && errno != EINTR ? -errno : 0;
    args->retval = attr.test.retval;
}

void c_dispatch_task_wrapper(void *opaque) {
    struct qumun_dispatch_args *args = opaque;
    if (!args->ring) {
        args->error = -EINVAL;
        return;
    }

    /* Never use reserve_blocking: the fast call must not wait while holding P. */
    void *entry = user_ring_buffer__reserve(args->ring, sizeof(args->data));
    if (!entry) {
        args->error = -errno;
        return;
    }
    memcpy(entry, args->data, sizeof(args->data));
    user_ring_buffer__submit(args->ring, entry);
    args->error = 0;
}

struct user_ring_buffer *qumun_dispatch_open(int fd, int *error) {
    struct user_ring_buffer *ring = user_ring_buffer__new(fd, NULL);
    *error = ring ? 0 : -errno;
    return ring;
}

void qumun_dispatch_close(struct user_ring_buffer *ring) {
    user_ring_buffer__free(ring);
}
