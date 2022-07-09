# ----------------------------------------------------------------------------
SHELL = bash

.PHONY: build
build:
	@echo "Building checksec"
	./hack/build.sh

.PHONY: test
test:
	./tests/test-checksec.sh
