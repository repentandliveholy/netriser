.PHONY: all build release test clean

all: build

build:
	./build.sh

release:
	./scripts/build-release.sh

test:
	go test ./...

clean:
	rm -rf -- bin
