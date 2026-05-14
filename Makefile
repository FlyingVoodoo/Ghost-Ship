# Makefile for running tests and building the C++ streamer locally

.PHONY: test test-fast test-full build-clib

# Run Go unit tests quickly (no cgo streamer)
test-fast:
	go test ./... -v

# Build C++ streamer and run Go tests with cgo_streamer enabled
test-full: build-clib
	go test ./... -v -tags cgo_streamer

build-clib:
	cd clib && rm -rf build && mkdir -p build && cd build && cmake .. && cmake --build . -- -j$(shell nproc || echo 2)

test: test-fast
