FROM espressif/idf-rust:esp32s3_1.92.0.0

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
    fish \
    ripgrep \
    libusb-1.0-0-dev \
    pkg-config \
    libssl-dev \
    libudev-dev \
    cmake \
    vim \
    less \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Single -G with a comma list — multiple -G flags overwrite each other.
# plugdev is what the host puts on /dev/ttyACM0; without it the
# unprivileged esp user inside the container can't open the serial port
# even with --privileged (caps don't grant non-root group access).
RUN getent group plugdev >/dev/null || groupadd -g 46 plugdev; \
    usermod -aG dialout,tty,plugdev esp

USER esp

# The base image's `export-esp.sh` is sourced from .bashrc, but .bashrc
# early-returns for non-interactive shells — so `docker exec` never sees
# the Xtensa GCC linker. Bake the relevant paths into the image env so
# every shell (interactive or not) picks them up.
ENV PATH="/home/esp/.rustup/toolchains/esp/xtensa-esp-elf/esp-15.2.0_20250920/xtensa-esp-elf/bin:/home/esp/.cargo/bin:${PATH}"
ENV LIBCLANG_PATH="/home/esp/.rustup/toolchains/esp/xtensa-esp32-elf-clang/esp-20.1.1_20250829/esp-clang/lib"

# Base image ships espflash 4.3.0 / ldproxy. Pin espflash to the
# current latest (4.4.0) for newer bug fixes; --force overwrites the
# pre-installed binary.
RUN cargo install --locked --force espflash@4.4.0

# Make /workspace writable by esp.
USER root
RUN mkdir -p /workspace && chown esp:esp /workspace
USER esp

WORKDIR /workspace
