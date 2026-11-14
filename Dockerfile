# The release image: the static release binary on a minimal base. Built by the
# release workflow from binaries it has already built (dist/httpmon-linux-*).
#
#   docker run --rm -p 8080:8080 -v httpmon:/home/nonroot/.config/httpmon \
#     ghcr.io/hxddh/https-traffic-inspector proxy --listen 0.0.0.0
FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETARCH
COPY dist/httpmon-linux-${TARGETARCH} /usr/local/bin/httpmon
ENV HTTPMON_HOME=/home/nonroot/.config/httpmon
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/httpmon"]
CMD ["help"]
