.PHONY: test build bench demo fixtures

test:
	go test ./...

build:
	go build -o permittrace ./cmd/permittrace

bench: build
	./permittrace bench

demo: build
	./permittrace demo --out permittrace-report.html

fixtures: build
	./permittrace generate fixtures
