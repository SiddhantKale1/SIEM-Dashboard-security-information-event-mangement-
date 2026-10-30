.PHONY: build run test sandbox clean

build:
	@mkdir -p bin
	go build -o bin/siem-server ./cmd/server
	go build -o bin/siem-agent ./cmd/agent
	@echo "Build successful: bin/siem-server and bin/siem-agent"

run: build
	./bin/siem-server

test:
	go test -v ./tests

sandbox:
	go run ./cmd/sandbox

clean:
	rm -rf bin/ siem_data/
