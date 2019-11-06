test:
	go test -short ./...

test-long:
	go test -v -race ./...

bench:
	go test -v -run=XXX -bench=. ./...

lint:
	@golangci-lint run \
		--enable-all \
		--disable=lll \
		--disable=gocyclo \
		--disable=prealloc \
		--disable=interfacer \
		--disable=unparam \
		--disable=gocritic \
		--disable=dupl \
		--disable=errcheck \
		--disable=gochecknoglobals \
		--disable=funlen \
		--disable=gocognit \
		--disable=godox \
		--disable=wsl \
		--skip-dirs=internal \
		./...

.PHONY: test test-long bench lint
