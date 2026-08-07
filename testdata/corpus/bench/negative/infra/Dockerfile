# Hardened: pinned base, non-root, no remote ADD, no curl|sh, no secret ENV.
FROM gcr.io/distroless/static-debian12:nonroot
USER 65532
COPY app /app
ENTRYPOINT ["/app"]
