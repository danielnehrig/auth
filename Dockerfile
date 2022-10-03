FROM rustlang/rust:nightly-slim as builder

RUN USER=root cargo new --bin app
WORKDIR /app
COPY ./Cargo.toml ./Cargo.toml
RUN rustup default nightly
RUN rustup component add rustfmt
RUN apt-get -y update \
    && apt-get -y install libssl-dev \
    && apt-get install -y ca-certificates tzdata \
    && apt-get -y install openssl \
    && apt-get -y install curl \
    && apt-get -y install protobuf-compiler \
    && apt-get -y install ca-certificates tzdata \
    && apt-get -y install pkg-config
RUN cargo build --release
RUN rm src/*.rs

ADD . ./

RUN cargo build --release

FROM debian:stable-slim
ARG APP=/usr/src/app



RUN apt-get -y update \
    && apt-get -y install libssl-dev \
    && apt-get install -y ca-certificates tzdata \
    && apt-get -y install openssl \
    && apt-get -y install curl \
    && apt-get -y install protobuf-compiler \
    && apt-get -y install pkg-config
EXPOSE 3000

ENV TZ=Etc/UTC \
    APP_USER=appuser

RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

COPY --from=builder /app/target/release/auth ${APP}/app

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

CMD ["./app"]
