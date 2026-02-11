.ONESHELL:

BINARIES ?= tpm_attestor_server tpm_attestor_agent get_tpm_pubhash
OSES ?= linux windows
ARCHITECTURES ?= amd64 arm64
VERSION ?= develop
DOCKER_REGISTRY ?= ghcr.io
DOCKER_REPOSITORY_PREFIX ?= spiffe/spire-tpm-plugin
BUILD_DIR ?= ./build
RELEASES_DIR ?= ./releases
PLATFORMS ?= $(foreach os, $(OSES), $(foreach architecture, $(ARCHITECTURES), --platform $(os)/$(architecture)))

BUILD_TARGETS := $(foreach binary, $(BINARIES), $(foreach os, $(OSES), $(foreach architecture, $(ARCHITECTURES), $(binary)-$(os)-$(architecture))))
RELEASE_TARGETS := $(foreach build, $(BUILD_TARGETS), $(build)-release)
DOCKER_TARGETS := $(foreach binary, $(BINARIES), $(binary)-docker)

target_words = $(subst -, ,$@)
target_os = $(word 2, $(target_words))
target_ext = $(if $(filter windows,$(target_os)),.exe,)
target_architecture = $(word 3, $(target_words))
target_binary = $(word 1, $(target_words))

target_binary_hyphens = $(subst _,-,$(target_binary))

build: $(BUILD_TARGETS)
$(BUILD_TARGETS):
	CGO_ENABLED=0 GOOS=$(target_os) GOARCH=$(target_architecture) go build -ldflags="-s -w -extldflags -static" -o $(BUILD_DIR)/$(target_os)/$(target_architecture)/$(target_binary)$(target_ext) cmd/$(target_binary)/main.go

test:
	go test ./...

release: $(RELEASE_TARGETS)
$(RELEASE_TARGETS):
	mkdir -p releases
	tar -cvzf $(RELEASES_DIR)/spire_tpm_plugin_$(target_binary)_$(target_os)_$(target_architecture)_$(VERSION).tar.gz -C $(BUILD_DIR)/$(target_os)/$(target_architecture) $(target_binary)$(target_ext)

docker: $(DOCKER_TARGETS)
$(DOCKER_TARGETS):
	docker build $(PLATFORMS) --build-arg BINARY=$(target_binary) -t $(DOCKER_REGISTRY)/$(DOCKER_REPOSITORY_PREFIX)-$(target_binary_hyphens):$(VERSION) . --push

docker-build:
	CGO_ENABLED=0 GOOS=$(TARGETOS) GOARCH=$(TARGETARCH) go build -ldflags="-s -w -extldflags -static" -o ${BINARY} cmd/${BINARY}/main.go

clean:
	rm -rf $(BUILD_DIR) $(RELEASES_DIR)

.PHONY: $(BUILD_TARGETS) $(RELEASE_TARGETS) $(DOCKER_TARGETS) build test release docker clean
