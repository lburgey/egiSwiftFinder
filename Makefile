SCRIPT=swift_finder
BIN_DIR=build
BIN_NAME=egiSwiftFinder
BIN=$(BIN_DIR)/$(BIN_NAME)
WINDOWS_OS=windows
LINUX_OS=linux
MAC_OS=darwin
ARCH=amd64
LDFLAGS='-X main.version=$(shell git describe --tags)'

$(BIN): $(BIN_DIR)
	GOOS=$(LINUX_OS) GOARCH=$(ARCH) \
		 go build -v -o $(BIN) -ldflags $(LDFLAGS) ./cmd

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

.PHONY: tarball
tarball: $(BIN) $(SCRIPT)
	cp -f $(SCRIPT) $(BIN_DIR)
	tar -czvf $(BIN)-$(LINUX_OS)-$(ARCH).tar.gz -C $(BIN_DIR) $(SCRIPT) $(BIN_NAME)

.PHONY: lint
lint:
	golangci-lint run

clean:
	rm -rf $(BIN_DIR)
