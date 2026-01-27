# Architecture configuration (default: x86_64, can override with ARCH=arm64)
# 
# Usage: 
#   make build              # Build for x86_64 (default)
#   make build ARCH=arm64   # Build for ARM64 (requires cross-compilation tools)
#
# ARM64 cross-compilation requirements:
#   1. Install cross-compiler: sudo apt-get install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
#   2. Install ARM64 dev libraries: sudo apt-get install libelf-dev:arm64 zlib1g-dev:arm64 libzstd-dev:arm64
#   3. May need to configure dpkg for multi-arch: sudo dpkg --add-architecture arm64
#
ARCH ?= x86_64

# Architecture-specific settings
ifeq ($(ARCH),arm64)
    ARCH_DEFINE = -D__TARGET_ARCH_arm64
    ARCH_CPU_FLAGS = -mcpu=v3
    ARCH_SCHED_INCLUDE = -I scx/scheds/include/arch/aarch64
    ARCH_INCLUDE_DIR = aarch64-linux-gnu
    GOARCH_ENV = CGO_ENABLED=1 GOARCH=arm64
    CGO_CC = aarch64-linux-gnu-gcc
    LIBBPF_CC = aarch64-linux-gnu-gcc
else
    ARCH_DEFINE = -D__TARGET_ARCH_x86
    ARCH_CPU_FLAGS = -mcpu=v3
    ARCH_SCHED_INCLUDE = -I scx/scheds/include/arch/x86
    ARCH_INCLUDE_DIR = x86_64-linux-gnu
    GOARCH_ENV = 
    CGO_CC = clang
    LIBBPF_CC = gcc
endif

OUTPUT = output
LIBBPF_SRC = $(abspath libbpf/src)
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a)
LIBBPF_OBJDIR = $(abspath ./$(OUTPUT)/libbpf)
LIBBPF_DESTDIR = $(abspath ./$(OUTPUT))


TARGET = ebpf/main
BPF_TARGET = ${TARGET:=.bpf}
BPF_C = ${BPF_TARGET:=.c}
BPF_OBJ = ${BPF_C:.c=.o}

BASEDIR = $(abspath .)
OUTPUT = output
LIBBPF_INCLUDE_UAPI = $(abspath ./libbpf/include/uapi)
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a)
LIBBPF_OBJDIR = $(abspath ./$(OUTPUT)/libbpf)
LIBBPF_DESTDIR = $(abspath ./$(OUTPUT))
CLANG_BPF_SYS_INCLUDES := `shell $(CLANG) -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }'`
CGOFLAG = $(GOARCH_ENV) CC=$(CGO_CC) CGO_CFLAGS="-I$(BASEDIR) -I$(BASEDIR)/$(OUTPUT)" CGO_LDFLAGS="-lelf -lz $(LIBBPF_OBJ) -lzstd $(BASEDIR)/libwrapper.a"

.PHONY: build
build: clean $(BPF_OBJ) libbpf libbpf-uapi wrapper
	$(CGOFLAG) go build -ldflags "-w -s" main.go

test: build
	@echo "Running scheduler test..."
	@chmod +x scripts/test_scheduler.sh
	@vng -r v6.12.2 -- bash scripts/test_scheduler.sh

.PHONY: libbpf-uapi
libbpf-uapi: $(LIBBPF_SRC)
	UAPIDIR=$(LIBBPF_DESTDIR) \
		$(MAKE) -C $(LIBBPF_SRC) install_uapi_headers

.PHONY: libbpf
libbpf: $(LIBBPF_SRC) $(wildcard $(LIBBPF_SRC)/*.[ch])
	$(MAKE) -C $(LIBBPF_SRC) clean
	CC="$(LIBBPF_CC)" CFLAGS="-g -O2 -Wall -fpie" \
	   $(MAKE) -C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_OBJDIR) \
		DESTDIR=$(LIBBPF_DESTDIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install
	$(eval STATIC=-extldflags -static)

dep:
	git clone https://github.com/libbpf/libbpf.git && \
	cd libbpf/src && \
	git checkout 09b9e83 && \
	make && \
	sudo make install && \
	cd - && \
	git clone -b feat/skel https://github.com/Gthulhu/libbpfgo.git

$(BPF_OBJ): ebpf/%.o:ebpf/%.c
	$(CGO_CC) \
		-O2 -g -Wall -target bpf \
		$(ARCH_DEFINE) $(ARCH_CPU_FLAGS) -mlittle-endian \
		-idirafter $(shell clang -print-resource-dir)/include -idirafter /usr/local/include -idirafter /usr/include/$(ARCH_INCLUDE_DIR) -idirafter /usr/include \
		-I scx/scheds/vmlinux -I scx/build/libbpf/src/usr/include -I scx/build/libbpf/include/uapi -I scx/scheds/include $(ARCH_SCHED_INCLUDE) -I scx/scheds/include/bpf-compat -I scx/scheds/include/lib \
		-Wno-compare-distinct-pointer-types \
		-c $< -o $@

wrapper:
	bpftool gen skeleton ebpf/main.bpf.o > main.skeleton.h
	$(CGO_CC) -g -O2 -Wall -fPIC -c wrapper.c -o wrapper.o
	ar rcs libwrapper.a wrapper.o

clean:
	rm libwrapper.a || true
	rm *.skeleton.h || true
	rm *.ll *.o || true
	rm main || true