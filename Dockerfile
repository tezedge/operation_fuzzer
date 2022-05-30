FROM debian:bullseye
RUN apt update
RUN apt install -y git curl openssl libssl-dev pkg-config
RUN apt install -y libsodium-dev clang libclang-dev llvm llvm-dev libev-dev
RUN apt install -y make lcov python3 python3-pip
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 1
RUN update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 1
RUN pip install psutil
RUN pip install poetry
RUN git clone https://github.com/tezedge/tezedge --branch develop
COPY ./scripts /scripts
ENV RUSTUP_HOME=/rust
ENV CARGO_HOME=/cargo
ENV PATH=/cargo/bin:/rust/bin:$PATH
ARG rust_toolchain="nightly-2021-11-21"
RUN curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain ${rust_toolchain} -y --no-modify-path
RUN cargo install cargo-binutils
RUN rustup component add llvm-tools-preview
RUN apt-get install -y opam
RUN git clone https://gitlab.com/tezedge/tezos.git
RUN cd /tezos && opam init --disable-sandboxing -y && eval $(opam env) && env OPAMYES=1 make build-dev-deps && opam pin add bisect_ppx https://github.com/tezedge/bisect_ppx.git -y && ./scripts/with_coverage.sh opam config exec -- make && opam config exec -- make tezos-client && poetry install
RUN cd /tezos/tests_python && poetry add psutil base58check ed25519 pyblake2 construct && poetry install
RUN cp /scripts/*.py /tezos/tests_python/
RUN chmod +x /scripts/*
RUN apt-get install -y supervisor
ADD supervisord.conf /etc/supervisor/conf.d/supervisord.conf
CMD /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
