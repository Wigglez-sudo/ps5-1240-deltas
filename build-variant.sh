#!/bin/sh
set -eu

FW=${1:-}
OUT=${2:-../payloads}
SDK=${PS5_PAYLOAD_SDK:-/opt/ps5-payload-sdk}

case "$FW" in
  1200) TABLE=off_1200 ;;
  1202) TABLE=off_1202 ;;
  1220|1240) TABLE=off_1240 ;;
  1260|1270) TABLE=off_1270 ;;
  aio)  TABLE= ;;
  *) echo "usage: $0 {1200|1202|1220|1240|1260|1270|aio} [outdir]" >&2; exit 2 ;;
esac

SRC=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cp -a "$SRC/." "$WORK/"

python3 - "$WORK/source/utils.c" "$FW" "$TABLE" <<'PY'
import re, sys
path, fw, table = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
if fw == "aio":
    body = """  case 0x1200:
    env_offset = off_1200;
    break;
  case 0x1202:
    env_offset = off_1202;
    break;
  case 0x1220:
  case 0x1240:
    env_offset = off_1240;
    break;
  case 0x1260:
  case 0x1270:
    env_offset = off_1270;
    break;
  default:
    return -1;"""
    tag = "12xx-1200-1202-1220-1240-1260-1270"
else:
    body = ("  case 0x%s:\n    env_offset = %s;\n    break;\n"
            "  default:\n    return -1;   /* %s.%s-only build */" % (fw, table, fw[:2], fw[2:]))
    tag = "%s-only" % fw
s = re.sub(r'  switch \(fw\) \{.*?\n  \}', '  switch (fw) {\n' + body + '\n  }', s, count=1, flags=re.S)
s = re.sub(r'#define PS5_BUILD_TAG "[^"]*"', '#define PS5_BUILD_TAG "%s"' % tag, s, count=1)
open(path, "w").write(s)
print("variant %s -> %s (table %s)" % (fw, tag, table or "all"))
PY

make -C "$WORK" -j4 PS5_PAYLOAD_SDK="$SDK" >/dev/null

if [ "$FW" = "aio" ]; then
  NAME=ps5-linux-loader-12xx-aio.elf
else
  NAME=ps5-linux-loader-${FW}-only.elf
fi
mkdir -p "$OUT"
cp "$WORK/bin/ps5-linux-loader.elf" "$OUT/$NAME"
echo "$OUT/$NAME"
sha256sum "$OUT/$NAME"
