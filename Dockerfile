# Two stages: it builds with the official Go image and copies a single static
# binary into an empty image. The final image has no shell, no package
# manager, and no libc -- there is nothing inside to update and nothing to
# exploit apart from the program itself.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /lost-phone-relay .
# An empty /data with the correct owner. A 'scratch' image has no shell to
# do a chown at boot, so the directory has to come with its owner already set
# -- and a NAMED Docker volume inherits that owner when it is created. Without
# this, the container starts unprivileged and cannot write its own
# certificate: "permission denied", and the relay serves nothing.
RUN mkdir -p /data-vacio

FROM scratch
COPY --from=build /lost-phone-relay /lost-phone-relay
COPY --from=build --chown=10001:10001 /data-vacio /data
# Runs unprivileged. The only place it writes is /data, which is mounted.
#
# If instead of a named volume you mount a directory of your own, you will
# have to grant it:  chown -R 10001:10001 ./data
#
# And that volume has to PERSIST: it is where the TLS certificate the relay
# generates the first time lives. With an ephemeral volume a new one would be
# generated on every container boot, and then the phone -- which pins the
# certificate when pairing -- would stop connecting after each 'docker compose
# up', with nothing explaining why.
USER 10001:10001
VOLUME /data
EXPOSE 8080
ENV LOST_PHONE_DATA=/data LOST_PHONE_ADDR=:8080
ENTRYPOINT ["/lost-phone-relay"]
