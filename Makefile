ldflags = -X 'main.version=0.1.0' \
          -X 'main.githash=`git rev-parse --short HEAD`' \
          -X 'main.goversion=`go version`' \
          -X 'main.builddate=`date`'

# all builds a binary with the current commit hash
all:
	go install -ldflags "$(ldflags)" ./...

# dev builds a binary with dev constants
dev:
	go install -ldflags "$(ldflags)" -tags='dev' ./...

lint:
	@gometalinter --disable-all \
		--enable=ineffassign \
		--enable=gofmt \
		--enable=golint \
		--enable=maligned \
		--enable=megacheck \
		--enable=misspell \
		--enable=structcheck \
		--enable=unconvert \
		--enable=varcheck \
		--enable=vet \
		./...
