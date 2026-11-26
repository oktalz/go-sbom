# Packages the release binaries, so the image runs the attested binary.
# Local build: put go-sbom_<VERSION>_linux_<arch> in dist/ first.
# distroless static: CA certificates for the Go proxy and registries, no shell.
FROM gcr.io/distroless/static-debian13:nonroot
ARG TARGETARCH
ARG VERSION
# --chmod: workflow artifacts lose the executable bit.
COPY --chmod=0755 dist/go-sbom_${VERSION}_linux_${TARGETARCH} /usr/local/bin/go-sbom
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/go-sbom"]
