#!/usr/bin/env bash
# rustc --print target-list
: <<'COMMENT'
aarch64-fuchsia
aarch64-linux-android
aarch64-pc-windows-msvc
aarch64-unknown-cloudabi
aarch64-unknown-freebsd
aarch64-unknown-hermit
aarch64-unknown-linux-gnu
aarch64-unknown-linux-musl
aarch64-unknown-netbsd
aarch64-unknown-none
aarch64-unknown-none-softfloat
aarch64-unknown-openbsd
aarch64-unknown-redox
aarch64-uwp-windows-msvc
aarch64-wrs-vxworks
arm-linux-androideabi
arm-unknown-linux-gnueabi
arm-unknown-linux-gnueabihf
arm-unknown-linux-musleabi
arm-unknown-linux-musleabihf
armebv7r-none-eabi
armebv7r-none-eabihf
armv4t-unknown-linux-gnueabi
armv5te-unknown-linux-gnueabi
armv5te-unknown-linux-musleabi
armv6-unknown-freebsd
armv6-unknown-netbsd-eabihf
armv7-linux-androideabi
armv7-unknown-cloudabi-eabihf
armv7-unknown-freebsd
armv7-unknown-linux-gnueabi
armv7-unknown-linux-gnueabihf
armv7-unknown-linux-musleabi
armv7-unknown-linux-musleabihf
armv7-unknown-netbsd-eabihf
armv7-wrs-vxworks-eabihf
armv7r-none-eabi
armv7r-none-eabihf
asmjs-unknown-emscripten
hexagon-unknown-linux-musl
i586-pc-windows-msvc
i586-unknown-linux-gnu
i586-unknown-linux-musl
i686-apple-darwin
i686-linux-android
i686-pc-windows-gnu
i686-pc-windows-msvc
i686-unknown-cloudabi
i686-unknown-freebsd
i686-unknown-haiku
i686-unknown-linux-gnu
i686-unknown-linux-musl
i686-unknown-netbsd
i686-unknown-openbsd
i686-unknown-uefi
i686-uwp-windows-gnu
i686-uwp-windows-msvc
i686-wrs-vxworks
mips-unknown-linux-gnu
mips-unknown-linux-musl
mips-unknown-linux-uclibc
mips64-unknown-linux-gnuabi64
mips64-unknown-linux-muslabi64
mips64el-unknown-linux-gnuabi64
mips64el-unknown-linux-muslabi64
mipsel-unknown-linux-gnu
mipsel-unknown-linux-musl
mipsel-unknown-linux-uclibc
mipsisa32r6-unknown-linux-gnu
mipsisa32r6el-unknown-linux-gnu
mipsisa64r6-unknown-linux-gnuabi64
mipsisa64r6el-unknown-linux-gnuabi64
msp430-none-elf
nvptx64-nvidia-cuda
powerpc-unknown-linux-gnu
powerpc-unknown-linux-gnuspe
powerpc-unknown-linux-musl
powerpc-unknown-netbsd
powerpc-wrs-vxworks
powerpc-wrs-vxworks-spe
powerpc64-unknown-freebsd
powerpc64-unknown-linux-gnu
powerpc64-unknown-linux-musl
powerpc64-wrs-vxworks
powerpc64le-unknown-linux-gnu
powerpc64le-unknown-linux-musl
riscv32i-unknown-none-elf
riscv32imac-unknown-none-elf
riscv32imc-unknown-none-elf
riscv64gc-unknown-linux-gnu
riscv64gc-unknown-none-elf
riscv64imac-unknown-none-elf
s390x-unknown-linux-gnu
sparc-unknown-linux-gnu
sparc64-unknown-linux-gnu
sparc64-unknown-netbsd
sparc64-unknown-openbsd
sparcv9-sun-solaris
thumbv6m-none-eabi
thumbv7a-pc-windows-msvc
thumbv7em-none-eabi
thumbv7em-none-eabihf
thumbv7m-none-eabi
thumbv7neon-linux-androideabi
thumbv7neon-unknown-linux-gnueabihf
thumbv7neon-unknown-linux-musleabihf
thumbv8m.base-none-eabi
thumbv8m.main-none-eabi
thumbv8m.main-none-eabihf
wasm32-unknown-emscripten
wasm32-unknown-unknown
wasm32-wasi
x86_64-apple-darwin
x86_64-fortanix-unknown-sgx
x86_64-fuchsia
x86_64-linux-android
x86_64-linux-kernel
x86_64-pc-solaris
x86_64-pc-windows-gnu
x86_64-pc-windows-msvc
x86_64-rumprun-netbsd
x86_64-sun-solaris
x86_64-unknown-cloudabi
x86_64-unknown-dragonfly
x86_64-unknown-freebsd
x86_64-unknown-haiku
x86_64-unknown-hermit
x86_64-unknown-hermit-kernel
x86_64-unknown-l4re-uclibc
x86_64-unknown-linux-gnu
x86_64-unknown-linux-gnux32
x86_64-unknown-linux-musl
x86_64-unknown-netbsd
x86_64-unknown-openbsd
x86_64-unknown-redox
x86_64-unknown-uefi
x86_64-uwp-windows-gnu
x86_64-uwp-windows-msvc
x86_64-wrs-vxworks
COMMENT

rm dpi-http-proxy-* -rf

TARGET="x86_64-unknown-linux-gnu"
EXE_PATH="target/$TARGET/release/http-proxy"
echo "Building for $TARGET.."
cargo rustc --target "$TARGET" --release -- -l static=ssl -l static=crypto && zip dpi-http-proxy-linux-x86_64.zip $EXE_PATH run.sh

TARGET="i686-unknown-linux-gnu"
EXE_PATH="target/$TARGET/release/http-proxy"
echo "Building for $TARGET.."
cargo rustc --target "$TARGET" --release -- -l static=ssl -l static=crypto && zip dpi-http-proxy-linux-i686.zip $EXE_PATH run.sh

TARGET="x86_64-pc-windows-gnu"
EXE_PATH="target/$TARGET/release/http-proxy.exe"
echo "Building for $TARGET.."
cargo rustc --target "$TARGET" --release -- -C linker=x86_64-w64-mingw32-gcc && zip dpi-http-proxy-win64.zip $EXE_PATH run.cmd

TARGET="i686-pc-windows-gnu"
EXE_PATH="target/$TARGET/release/http-proxy.exe"
echo "Building for $TARGET.."
cargo rustc --target "$TARGET" --release -- -C panic=abort -C linker=i686-w64-mingw32-gcc && zip dpi-http-proxy-win32.zip $EXE_PATH run.cmd

TARGET="x86_64-pc-windows-gnu"
EXE_PATH="target/$TARGET/release/http-proxy.exe"
echo "Building for $TARGET.."
cargo rustc --target "$TARGET" --release -- -C linker=x86_64-w64-mingw32-gcc -Clink-args="-Wl,--subsystem,windows" && zip dpi-http-proxy-win64-hide.zip $EXE_PATH run.cmd

TARGET="i686-pc-windows-gnu"
EXE_PATH="target/$TARGET/release/http-proxy.exe"
echo "Building for $TARGET.."
cargo rustc --target "$TARGET" --release -- -C panic=abort -C linker=i686-w64-mingw32-gcc -Clink-args="-Wl,--subsystem,windows" && zip dpi-http-proxy-win32-hide.zip $EXE_PATH run.cmd

: <<'COMMENT'
TARGET="arm-linux-androideabi"
EXE_PATH="target/$TARGET/release/http-proxy"
echo "Building for $TARGET.."
cargo rustc --target "$TARGET" --release -- -C linker=arm-linux-androideabi-clang -l static=ssl -l static=crypto && zip dpi-http-proxy-linux-arm.zip $EXE_PATH run.sh

TARGET="aarch64-linux-android"
EXE_PATH="target/$TARGET/release/http-proxy"
echo "Building for $TARGET.."
cargo rustc --target "$TARGET" --release -- -C linker=aarch64-linux-androideabi-clang -l static=ssl -l static=crypto && zip dpi-http-proxy-linux-aarch64.zip $EXE_PATH run.sh
COMMENT
