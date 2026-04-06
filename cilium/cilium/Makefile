GO ?= go
CLANG ?= clang
APP ?= bin/cf-allow-http
OBJ ?= dist/http_guard_xdp.o
MULTIARCH ?= $(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || $(CLANG) -print-multiarch 2>/dev/null || echo x86_64-linux-gnu)
BPF_CPPFLAGS ?= -I/usr/include/$(MULTIARCH)
BPF_CFLAGS ?= -O2 -g -Wall -Werror -target bpf

.PHONY: all build-bpf build-go fmt clean run

all: build-bpf build-go

build-bpf: $(OBJ)

build-go: $(APP)

$(OBJ): bpf/http_guard_xdp.c | dist
	$(CLANG) $(BPF_CPPFLAGS) $(BPF_CFLAGS) -c $< -o $@

$(APP): | bin
	$(GO) build -o $(APP) ./cmd/cf-allow-http

fmt:
	$(GO) fmt ./...

clean:
	rm -f $(OBJ) $(APP)

run: all
	sudo $(APP) -iface=$(IFACE) -obj=$(OBJ)

bin:
	mkdir -p $@

dist:
	mkdir -p $@
