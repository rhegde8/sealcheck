.PHONY: build test vet demo lab clean

build:
	go build -trimpath -o bin/sealcheck ./cmd/sealcheck

test:
	go test -race ./...

vet:
	go vet ./...

demo: build
	./bin/sealcheck demo --out out/demo

lab: build
	./lab/run.sh

clean:
	rm -rf bin
