# Authentication Service GRPC Rust

## Overview

**Stack**

- Rust
- GRPC Tonic http/2 and web http/1
- Protobuf transport
- Using scrypt to hash the passwords
- Using JWT to sign a token

## Setup and needed dependencies

### Mac

- `brew install bloomrpc` (for testing the API)
- `brew install docker`
- `brew install docker-compose`
- `brew install rustup`

### Linux (with pacman)

- `pacman -S rustup docker docker-compose`
- `yay -S bloomrpc-git`

### Linux (with apt)

- `apt-get install rustup docker docker-compose`
- `install bloomrpc from git`

### Generic stuff

- `rustup default nightly`
- `rustup +nightly component add rustfmt`
- `cargo install cargo-watch`

## Dev Workflow

(Recommended)
- `docker-compose up`

(Optional)
- `docker-compose up` // with only the database comment out the app itself
- `cargo watch -x run`

Then the service should be reachable over 0.0.0.0:3000

## Test API Service Response Times

- `brew install rtapi`
- `rtapi --file endpoints.json --output results.pdf`
