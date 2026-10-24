# 12.xx loader source

Source for `ps5-linux-loader-12xx-ONLY-aio.elf`. Phat and Slim, firmware 12.00,
12.02, 12.20, 12.40, 12.60 and 12.70.

```
make PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
```

You need the PS5 payload SDK, plus gcc, binutils and xxd for the three shellcode
blobs. The output lands in `bin/ps5-linux-loader.elf`.

`./build-variant.sh 1240` builds one firmware on its own instead of the AIO.

`source/` is the loader itself, `include/` holds the firmware tables, and the three
`shellcode_*` directories build the blobs it copies into the console.

Based on https://github.com/ps5-linux/ps5-linux-loader. GPL-3.0.

The built loaders are at https://github.com/Wigglez-sudo/12.xx-linux-loader.
