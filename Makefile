SHELL = bash
VERSION ?= 3.1.0

.PHONY: test
test:
	./tests/test-checksec.sh

.PHONY: coverage
coverage:
	go test ./pkg/... -coverpkg=./pkg/... -coverprofile=coverage.out -covermode=count
	go tool cover -func=coverage.out

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
