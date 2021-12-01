SCRIPT=swift_finder
APP=./cmd/egiSwiftFinder
BIN_DIR=./build
BIN_NAME=egiSwiftFinder
BIN=$(BIN_DIR)/$(BIN_NAME)
LINUX_OS=linux
MAC_OS=darwin
ARCH=amd64
LDFLAGS='-X main.version=$(shell git describe --tags)'
BUILDFLAGS=-v -ldflags $(LDFLAGS)

.PHONY: build build-%
build: build-$(LINUX_OS)
build-%:
	@mkdir -p $(BIN_DIR)
	GOOS=$* GOARCH=$(ARCH) \
		 go build $(BUILDFLAGS) -o $(BIN) $(APP)

.PHONY: install install-%
install: install-$(LINUX_OS)
install-%:
	GOOS=$* GOARCH=$(ARCH) \
		 go install $(BUILDFLAGS) $(APP)

.PHONY: tarball-%
.NOTPARALLEL: tarballs
tarballs: tarball-$(LINUX_OS) tarball-$(MAC_OS)
tarball-%: build-% $(SCRIPT)
	@cp -f $(SCRIPT) $(BIN_DIR)
	tar -czvf $(BIN)-$*-$(ARCH).tar.gz -C $(BIN_DIR) $(SCRIPT) $(BIN_NAME)

.PHONY: lint
lint:
	golangci-lint run

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
