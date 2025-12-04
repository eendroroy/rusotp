# This file is licensed under the Affero General Public License version 3 or
# any later version.
#
# See the file LICENSE for details.

CARGO ?= cargo
RUSTUP ?= rustup
ARTIFACT_DIR ?= target/artifact

PLATFORMS := \
	 x86_64-unknown-linux-gnu:librusotp.so \
	 x86_64-apple-darwin:librusotp.dylib \
	 x86_64-pc-windows-gnu:rusotp.dll

.PHONY: build release

default: build

platform:
	@for entry in $(PLATFORMS); do \
		target=$${entry%%:*}; \
		if ! $(RUSTUP) target list --installed | grep -q "$$target"; then \
			$(RUSTUP) target add $$target; \
		fi; \
	done

build: platform
	@for entry in $(PLATFORMS); do \
		target=$${entry%%:*}; \
		echo "Building for target - $$target"; \
		$(CARGO) build --target $$target; \
	done


release: platform
	@for entry in $(PLATFORMS); do \
		target=$${entry%%:*}; \
		lib=$${entry#*:}; \
		echo "Building for target - $$target"; \
		$(CARGO) build --release --target $$target; \
		echo "Packaging artifacts - $(ARTIFACT_DIR)/$$target.zip"; \
		mkdir -p $(ARTIFACT_DIR)/$$target; \
		if [ -f target/$$target/release/$$lib ]; then cp target/$$target/release/$$lib $(ARTIFACT_DIR)/$$target/; fi; \
		cp contrib/rusotp.hpp $(ARTIFACT_DIR)/$$target/ 2>/dev/null || true; \
		( cd $(ARTIFACT_DIR) && zip -r $$target.zip $$target/* && rm -rf $$target) >/dev/null 2>&1; \
	done
