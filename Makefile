SHELL = bash

.PHONY: build
build:
	@echo "Building checksec"
	./hack/build.sh

.PHONY: test
test:
	./tests/test-checksec.sh

.PHONY: build-image
build-image:
	docker build -t slimm609/checksec .

.PHONY: go
go:
	goreleaser build --snapshot --clean
