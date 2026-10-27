// SPDX-License-Identifier: Apache-2.0

#ifndef QUMUN_SCHEDBRIDGE_H
#define QUMUN_SCHEDBRIDGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct qumun_call_args {
    void *address;
    uint64_t value;
    uint64_t result;
};

enum {
    QUMUN_ARGS_ALIGN = _Alignof(struct qumun_call_args),
    QUMUN_ADDRESS_OFFSET = offsetof(struct qumun_call_args, address),
    QUMUN_VALUE_OFFSET = offsetof(struct qumun_call_args, value),
    QUMUN_RESULT_OFFSET = offsetof(struct qumun_call_args, result),
};

_Static_assert(sizeof(unsigned long long) == sizeof(uint64_t), "BSS counter width");
_Static_assert(sizeof(bool) == 1, "BPF boolean width");

void qumun_load_u64(void *opaque);
void qumun_load_u32(void *opaque);
void qumun_store_u64(void *opaque);
void qumun_store_u32(void *opaque);
void qumun_store_bool(void *opaque);
void qumun_sub_u64(void *opaque);

uint64_t qumun_cgo_load_u64(const void *address);

#endif
