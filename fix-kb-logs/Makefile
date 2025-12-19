build:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o fix-kb-logs-amd64 main.go
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o fix-kb-logs-arm64 main.go
	upx --best fix-kb-logs-amd64
	upx --best fix-kb-logs-arm64
