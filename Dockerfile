# Stage 1: Build C++ Backend
FROM gcc:13 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY CMakeLists.txt ./
COPY include/ ./include/
COPY src/ ./src/
COPY tests/ ./tests/

RUN cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc -static-libstdc++"
RUN cmake --build build --target onyx_server

# Stage 2: Minimal Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/build/onyx_server /app/onyx_server
COPY databases/ /app/databases/

EXPOSE 8080

ENV PORT=8080
ENV ONYX_DB_DIR=databases

CMD ["/app/onyx_server"]
