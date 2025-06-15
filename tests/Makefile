.PHONY: test lint perf fmt

test:
	go test ./tests/... -run Test
	pytest -q

perf:
	k6 run tests/performance/k6/load.js

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .