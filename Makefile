# Top-level Makefile.
#
# The original C + Go targets are kept under `legacy_*` for reference;
# default targets now build the Rust workspace.

CARGO ?= cargo
RUST_DIR := rust
TARGET ?=

CARGO_FLAGS := --manifest-path $(RUST_DIR)/Cargo.toml --release
ifneq ($(TARGET),)
CARGO_FLAGS += --target $(TARGET)
endif

.PHONY: all build test clean install \
        legacy_all legacy_clean legacy_install legacy_test \
        go go_test go_clean go_install \
        c c_test c_clean c_install

all: build

build:
	$(CARGO) build $(CARGO_FLAGS)

test:
	$(CARGO) test $(CARGO_FLAGS) --workspace

clean:
	$(CARGO) clean --manifest-path $(RUST_DIR)/Cargo.toml

install: build
	@./install.sh

# ---------------------------------------------------------------------------
# Legacy Go + C build targets, kept for the migration window.
# ---------------------------------------------------------------------------
legacy_all: go c
legacy_clean: go_clean c_clean
legacy_install: go_install c_install
legacy_test: go_test c_test

go:
	$(MAKE) -C go

go_test:
	$(MAKE) -C go test

go_clean:
	$(MAKE) -C go clean

go_install:
	$(MAKE) -C go install

c:
	$(MAKE) -C c

c_test:
	$(MAKE) -C c test

c_clean:
	$(MAKE) -C c clean

c_install:
	$(MAKE) -C c install
