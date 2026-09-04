.PHONY: all build test clean install cross-compile

BINARY_NAME=sketchy
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.Version=${VERSION}"

all: build

build:
	cd go && go build ${LDFLAGS} -o ../${BINARY_NAME} .

# The scanner exits with the number of issues it found, so detecting
# something is a NON-ZERO exit. Running the binary bare under make therefore
# fails the build on success, which is why this target pipes its output and
# asserts on counts instead. It also depends on build, since the previous
# version invoked ./sketchy without ever creating it.
test: build
	cd go && go test ./...
	@echo "smoke: known-malicious sample must produce HIGH findings"
	@n=$$(./${BINARY_NAME} -json -high-only go/testdata/samples/test_malicious.py | grep -c '"risk": "HIGH RISK"' || true); \
	 [ "$$n" -gt 0 ] || { echo "  FAIL: expected HIGH findings on the malicious sample, got none"; exit 1; }; \
	 echo "  ok ($$n HIGH findings)"
	@echo "smoke: benign agent config must produce none"
	@n=$$(./${BINARY_NAME} -json go/testdata/ai-agents/negative | grep -c '"name":' || true); \
	 [ "$$n" -eq 0 ] || { echo "  FAIL: expected 0 findings on the benign sample, got $$n"; exit 1; }; \
	 echo "  ok"
	@echo "All tests passed."

clean:
	cd go && go clean
	rm -f ${BINARY_NAME}
	rm -f ${BINARY_NAME}-*

install: build
	sudo mv ${BINARY_NAME} /usr/local/bin/

cross-compile:
	@echo "Building for multiple platforms..."
	# macOS AMD64
	cd go && GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o ../${BINARY_NAME}-darwin-amd64 .
	# macOS ARM64 (M1/M2)
	cd go && GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o ../${BINARY_NAME}-darwin-arm64 .
	# Linux AMD64
	cd go && GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o ../${BINARY_NAME}-linux-amd64 .
	# Linux ARM64
	cd go && GOOS=linux GOARCH=arm64 go build ${LDFLAGS} -o ../${BINARY_NAME}-linux-arm64 .
	# Windows AMD64
	cd go && GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o ../${BINARY_NAME}-windows-amd64.exe .
	# Windows ARM64
	cd go && GOOS=windows GOARCH=arm64 go build ${LDFLAGS} -o ../${BINARY_NAME}-windows-arm64.exe .
	@echo "Cross-compilation complete!"

release: cross-compile
	@echo "Creating release archives..."
	tar czf ${BINARY_NAME}-darwin-amd64.tar.gz ${BINARY_NAME}-darwin-amd64
	tar czf ${BINARY_NAME}-darwin-arm64.tar.gz ${BINARY_NAME}-darwin-arm64
	tar czf ${BINARY_NAME}-linux-amd64.tar.gz ${BINARY_NAME}-linux-amd64
	tar czf ${BINARY_NAME}-linux-arm64.tar.gz ${BINARY_NAME}-linux-arm64
	zip ${BINARY_NAME}-windows-amd64.zip ${BINARY_NAME}-windows-amd64.exe
	zip ${BINARY_NAME}-windows-arm64.zip ${BINARY_NAME}-windows-arm64.exe
	@echo "Release archives created!"

run:
	-./${BINARY_NAME} go/testdata/samples/

run-high:
	-./${BINARY_NAME} -high-only go/testdata/samples/

help:
	@echo "Available targets:"
	@echo "  make build         - Build for current platform"
	@echo "  make test          - Run tests"
	@echo "  make clean         - Clean build artifacts"
	@echo "  make install       - Install to /usr/local/bin"
	@echo "  make cross-compile - Build for all platforms"
	@echo "  make release       - Create release archives"
	@echo "  make run           - Run on test directory"
	@echo "  make run-high      - Run on test directory (high risk only)"