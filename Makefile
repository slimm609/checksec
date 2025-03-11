SHELL = bash
VERSION ?= 3.0.2

.PHONY: test
test:
	./tests/test-checksec.sh

.PHONY: build-image
build-image:
	docker build -t slimm609/checksec .

.PHONY: build
build:
	goreleaser build --snapshot --clean

.PHONY: release
release:
	git tag $(VERSION) -m "release of $(VERSION)"
	goreleaser release --clean
