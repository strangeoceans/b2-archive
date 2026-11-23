PREFIX =.

build:
	go build ./cmd/b2-archive.go
install:
	mkdir -p $(PREFIX)/bin
	mv b2-archive $(PREFIX)/bin
