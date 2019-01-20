ldflags = -X 'main.githash=`git rev-parse --short HEAD`' \
          -X 'main.builddate=`date`'

# all builds a binary with the current commit hash
all:
	go install -ldflags "$(ldflags)" ./...

# dev builds a binary with dev constants
dev:
	go install -ldflags "$(ldflags)" -tags='dev' ./...

test:
	go test -v ./...

bench:
	go test -v -run=XXX -bench=. ./...

lint:
	@gometalinter --disable-all \
		--enable=ineffassign \
		--enable=gofmt \
		--enable=golint \
		--enable=maligned \
		--enable=staticcheck \
		--enable=misspell \
		--enable=structcheck \
		--enable=unconvert \
		--enable=varcheck \
		--enable=vet \
		--skip=internal \
		./...
