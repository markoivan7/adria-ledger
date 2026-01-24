# Build Stage
FROM alpine:3.19 AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache curl xz tar

# Download and install Zig 0.13.0
# Download and install Zig 0.13.0 for aarch64 (Apple Silicon / ARM Linux)
RUN curl -L -o zig.tar.xz https://ziglang.org/download/0.13.0/zig-linux-aarch64-0.13.0.tar.xz && \
    tar -xf zig.tar.xz && \
    mv zig-linux-aarch64-0.13.0 /usr/local/zig && \
    rm zig.tar.xz

# Add Zig to PATH
ENV PATH="/usr/local/zig:${PATH}"

# Copy source code
COPY . .

# Build the project (ReleaseSafe for performance + safety)
WORKDIR /app/core-sdk
RUN zig build -Doptimize=ReleaseSafe

# Runtime Stage
FROM alpine:3.19

WORKDIR /app

# Create data directories
RUN mkdir -p /app/data /app/logs

# Copy binary from builder
COPY --from=builder /app/core-sdk/zig-out/bin/adria_server /usr/local/bin/adria_server
COPY --from=builder /app/core-sdk/zig-out/bin/apl /usr/local/bin/apl

# Expose ports
# 10800: UDP Discovery
# 10801: TCP P2P
# 10802: TCP API
EXPOSE 10800/udp 10801 10802

# Default command
CMD ["adria_server"]
