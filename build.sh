#!/bin/sh

# read __memory.x.sum file
MEMORY_FILE=$(cat __memory.x.sum)
# calculate __memory.x.sum
sha256sum ./memory.x > __memory.x.sum
# compare __memory.x.sum and MEMORY_FILE
if [ "$MEMORY_FILE" != "$(cat __memory.x.sum)" ]; then
    echo "memory.x file changed. Clean caches..."
    cargo clean
    echo "Done."
fi

# cargo update
cargo build --release
mv ./target/thumbv7m-none-eabi/release/unsafe-key ./exec
arm-none-eabi-objcopy ./exec -O binary ./exec.bin
du -h ./exec.bin
stm32flash -w ./exec.bin -v -g 0x00 /dev/ttyUSB0 || exit 1
rm ./exec.bin
rm ./exec
