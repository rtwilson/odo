.PHONY: build test install-linux

build:
	mkdir -p bin
	go build -trimpath -o bin/odo ./cmd/odo

test:
	go test ./...

install-linux:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "install-linux needs root privileges. Run: sudo make install-linux"; \
		exit 1; \
	fi
	scripts/install-linux.sh
