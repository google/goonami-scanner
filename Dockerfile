FROM ubuntu:latest AS builder

# Install required OS-level dependencies.
RUN apt-get update \
 && apt-get install -y ca-certificates git golang protoc-gen-go \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf /usr/share/doc && rm -rf /usr/share/man \
 && apt-get clean

# Copy the source code and ensure permissions are set.
RUN mkdir -p /goonami/src /goonami/bin
COPY . /goonami/src/
RUN chown -R 1000:1000 /goonami

# We drop our privileges to build the binary.
USER 1000
WORKDIR /goonami/src

# Run tests
RUN go test ./...

# Build the binary
RUN go build -o /goonami/bin/goonami main.go

# Copy the configuration and modify it to find fingerprints in the Docker image.
RUN cp /goonami/src/config.textproto /goonami/config.textproto
RUN ln -s /goonami/src/plugins/fingerprint/webidentity/fingerprints /goonami/fingerprints \
  && sed -i 's%"plugins/fingerprint/webidentity/fingerprints"%"/goonami/fingerprints"%g' /goonami/config.textproto

FROM ubuntu:latest AS release

# Ensure ca-certificates are up to date.
RUN apt-get update && apt-get install -y ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf /usr/share/doc && rm -rf /usr/share/man \
 && apt-get clean

COPY --from=builder /goonami /goonami
RUN chown -R 1000:1000 /goonami

# Note: By default, Goonami uses nmap with connect mode and does not require
# root permissions. If you change the configuration, you might have to also
# change this Dockerfile.
#
# Drop permissions and set working directory.
USER 1000

# Add goonami to the PATH
ENV PATH="${PATH}:/goonami/bin"
WORKDIR /goonami
