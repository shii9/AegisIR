#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist/linux-amd64/python dist/linux-arm64/python
for arch in amd64 arm64; do
	GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "dist/linux-${arch}/aegisir" ./cmd/aegisir
	cp python/engine.py "dist/linux-${arch}/python/engine.py"
	tar -C "dist/linux-${arch}" -czf "dist/aegisir-linux-${arch}.tar.gz" aegisir python
done
(cd dist && sha256sum aegisir-linux-*.tar.gz > SHA256SUMS.txt)
echo "Packaging complete in dist/"
