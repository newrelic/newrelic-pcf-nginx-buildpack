# Define variables
GO_MOD_TIDY := go mod tidy
GO_MOD_VENDOR := go mod vendor
BUILD_SCRIPT := ./scripts/build.sh
TILE_GEN_SCRIPT := python3 tile-gen.py
PACKAGE_SCRIPT := ./scripts/package.sh --cached
TILE_BUILD := tile build

# Define targets
.PHONY: all pre compile generate_tile package build clean

all: pre compile generate_tile package build

pre:
	$(GO_MOD_TIDY)
	$(GO_MOD_VENDOR)

compile:
	$(BUILD_SCRIPT)

generate_tile:
	$(TILE_GEN_SCRIPT)

package:
	$(PACKAGE_SCRIPT)

build:
	$(TILE_BUILD)

clean:
	rm -rf ./build/*.zip
	rm -f ./bin/finalize
	rm -f ./bin/varify
	rm -f ./bin/supply
	rm -rf ./product
	rm -rf ./release

# Optional: Define individual steps
pre-step: pre
compile-step: compile
generate_tile-step: generate_tile
package-step: package
build-step: build
clean-step: clean

