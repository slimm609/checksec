SHELL = bash

.PHONY: build
build:
	@echo "Building checksec"
	./hack/build.sh

.PHONY: test
test:
	./tests/test-checksec.sh

.PHONY: compose-test
compose-test: go
	docker-compose build
	docker-compose run

.PHONY: go
go:
	goreleaser build --snapshot --clean
