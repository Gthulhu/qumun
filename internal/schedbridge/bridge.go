// SPDX-License-Identifier: Apache-2.0

// Package schedbridge calls callback-free C wrappers on g0. Call is for bounded
// memory operations; CallSyscall includes runtime bookkeeping for syscalls.
package schedbridge

/*
#include "bridge.h"
*/
import "C"

import "unsafe"

//go:linkname asmcgocall runtime.asmcgocall
//go:noescape
func asmcgocall(fn, arg unsafe.Pointer) int32

//go:linkname cgocall runtime.cgocall
//go:noescape
func cgocall(fn, arg unsafe.Pointer) int32

// Call invokes a bounded C wrapper. fn must be a C ABI function accepting one
// void pointer, with no blocking, allocation, or callbacks into Go.
func Call(fn, arg unsafe.Pointer) {
	asmcgocall(fn, arg)
}

// CallSyscall invokes a C wrapper through runtime.cgocall, which uses
// asmcgocall with syscall, GC, and signal bookkeeping. Unlike Call, it lets the
// runtime reclaim P if the syscall blocks. fn must not call Go or retain arg.
func CallSyscall(fn, arg unsafe.Pointer) {
	cgocall(fn, arg)
}

var (
	loadUint64Fn  = unsafe.Pointer(C.qumun_load_u64)
	loadUint32Fn  = unsafe.Pointer(C.qumun_load_u32)
	storeUint64Fn = unsafe.Pointer(C.qumun_store_u64)
	storeUint32Fn = unsafe.Pointer(C.qumun_store_u32)
	storeBoolFn   = unsafe.Pointer(C.qumun_store_bool)
	subUint64Fn   = unsafe.Pointer(C.qumun_sub_u64)
)

// All fields must remain pointer-free except address, which may point only to
// pointer-free memory. C must neither retain these pointers nor call back to Go.
type callArgs struct {
	address unsafe.Pointer
	value   uint64
	result  uint64
}

// Check both directions so any ABI size, alignment, or offset mismatch fails
// compilation rather than corrupting memory.
var (
	_ [unsafe.Sizeof(callArgs{}) - C.sizeof_struct_qumun_call_args]byte
	_ [C.sizeof_struct_qumun_call_args - unsafe.Sizeof(callArgs{})]byte
	_ [unsafe.Alignof(callArgs{}) - C.QUMUN_ARGS_ALIGN]byte
	_ [C.QUMUN_ARGS_ALIGN - unsafe.Alignof(callArgs{})]byte
	_ [unsafe.Offsetof(callArgs{}.address) - C.QUMUN_ADDRESS_OFFSET]byte
	_ [C.QUMUN_ADDRESS_OFFSET - unsafe.Offsetof(callArgs{}.address)]byte
	_ [unsafe.Offsetof(callArgs{}.value) - C.QUMUN_VALUE_OFFSET]byte
	_ [C.QUMUN_VALUE_OFFSET - unsafe.Offsetof(callArgs{}.value)]byte
	_ [unsafe.Offsetof(callArgs{}.result) - C.QUMUN_RESULT_OFFSET]byte
	_ [C.QUMUN_RESULT_OFFSET - unsafe.Offsetof(callArgs{}.result)]byte
)

func LoadUint64(address unsafe.Pointer) uint64 {
	args := callArgs{address: address}
	asmcgocall(loadUint64Fn, unsafe.Pointer(&args))
	return args.result
}

func LoadUint32(address unsafe.Pointer) uint32 {
	args := callArgs{address: address}
	asmcgocall(loadUint32Fn, unsafe.Pointer(&args))
	return uint32(args.result)
}

func StoreUint64(address unsafe.Pointer, value uint64) {
	args := callArgs{address: address, value: value}
	asmcgocall(storeUint64Fn, unsafe.Pointer(&args))
}

func StoreUint32(address unsafe.Pointer, value uint32) {
	args := callArgs{address: address, value: uint64(value)}
	asmcgocall(storeUint32Fn, unsafe.Pointer(&args))
}

func StoreBool(address unsafe.Pointer, value bool) {
	args := callArgs{address: address}
	if value {
		args.value = 1
	}
	asmcgocall(storeBoolFn, unsafe.Pointer(&args))
}

func SubUint64(address unsafe.Pointer, value uint64) {
	args := callArgs{address: address, value: value}
	asmcgocall(subUint64Fn, unsafe.Pointer(&args))
}

// cgoLoadUint64 is the standard-Cgo reference for the benchmark. The direct
// path calls the same C load through qumun_load_u64, without runtime.cgocall.
func cgoLoadUint64(address unsafe.Pointer) uint64 {
	return uint64(C.qumun_cgo_load_u64(address))
}
