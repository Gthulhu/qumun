// SPDX-License-Identifier: Apache-2.0

#ifndef QUMUN_HOTPATH_H
#define QUMUN_HOTPATH_H

#include <stddef.h>
#include <stdint.h>

struct user_ring_buffer;

struct qumun_cpu_context {
    int32_t pid;
    int32_t cpu;
    uint64_t flags;
};

struct qumun_select_args {
    int32_t fd;
    int32_t error;
    uint32_t retval;
    uint32_t reserved;
    struct qumun_cpu_context context;
};

struct qumun_dispatch_args {
    struct user_ring_buffer *ring;
    int32_t error;
    uint32_t reserved;
    unsigned char data[64];
};

enum {
    QUMUN_SELECT_ALIGN = _Alignof(struct qumun_select_args),
    QUMUN_SELECT_FD = offsetof(struct qumun_select_args, fd),
    QUMUN_SELECT_ERROR = offsetof(struct qumun_select_args, error),
    QUMUN_SELECT_RETVAL = offsetof(struct qumun_select_args, retval),
    QUMUN_SELECT_RESERVED = offsetof(struct qumun_select_args, reserved),
    QUMUN_SELECT_CONTEXT = offsetof(struct qumun_select_args, context),
    QUMUN_CONTEXT_ALIGN = _Alignof(struct qumun_cpu_context),
    QUMUN_CONTEXT_PID = offsetof(struct qumun_cpu_context, pid),
    QUMUN_CONTEXT_CPU = offsetof(struct qumun_cpu_context, cpu),
    QUMUN_CONTEXT_FLAGS = offsetof(struct qumun_cpu_context, flags),
    QUMUN_DISPATCH_ALIGN = _Alignof(struct qumun_dispatch_args),
    QUMUN_DISPATCH_RING = offsetof(struct qumun_dispatch_args, ring),
    QUMUN_DISPATCH_ERROR = offsetof(struct qumun_dispatch_args, error),
    QUMUN_DISPATCH_RESERVED = offsetof(struct qumun_dispatch_args, reserved),
    QUMUN_DISPATCH_DATA = offsetof(struct qumun_dispatch_args, data),
};

void c_select_cpu_wrapper(void *opaque);
void c_dispatch_task_wrapper(void *opaque);
struct user_ring_buffer *qumun_dispatch_open(int fd, int *error);
void qumun_dispatch_close(struct user_ring_buffer *ring);

#endif
