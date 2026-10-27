// SPDX-License-Identifier: Apache-2.0

#include "bridge.h"
#include <string.h>

uint64_t qumun_cgo_load_u64(const void *address) {
    uint64_t value;
    memcpy(&value, address, sizeof(value));
    return value;
}

void qumun_load_u64(void *opaque) {
    struct qumun_call_args *args = opaque;
    args->result = qumun_cgo_load_u64(args->address);
}

void qumun_load_u32(void *opaque) {
    struct qumun_call_args *args = opaque;
    uint32_t value;
    memcpy(&value, args->address, sizeof(value));
    args->result = value;
}

void qumun_store_u64(void *opaque) {
    struct qumun_call_args *args = opaque;
    memcpy(args->address, &args->value, sizeof(args->value));
}

void qumun_store_u32(void *opaque) {
    struct qumun_call_args *args = opaque;
    uint32_t value = args->value;
    memcpy(args->address, &value, sizeof(value));
}

void qumun_store_bool(void *opaque) {
    struct qumun_call_args *args = opaque;
    bool value = args->value != 0;
    memcpy(args->address, &value, sizeof(value));
}

void qumun_sub_u64(void *opaque) {
    struct qumun_call_args *args = opaque;
    /* Preserve wrapper.c's conditional atomic subtraction, not a saturating CAS. */
    if (qumun_cgo_load_u64(args->address) >= args->value)
        __sync_fetch_and_sub((unsigned long long *)args->address, args->value);
}
