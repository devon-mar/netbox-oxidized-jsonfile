FROM gcr.io/distroless/cc-debian12
ARG TARGETARCH
COPY bin/netbox-oxidized-jsonfile-$TARGETARCH /netbox-oxidized-jsonfile
ENTRYPOINT ["/netbox-oxidized-jsonfile", "run"]
