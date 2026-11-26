# scripts/gen-ja4n-synthetic.py must never overwrite the capture it compares
# against, whichever path, symlink or hard link names it, and must reject
# malformed captures with a clear error (exit 2) instead of a traceback.
#
# @TEST-EXEC: bash check.sh %DIR/../scripts/gen-ja4n-synthetic.py $TRACES/ja4n-synthetic.pcap >output 2>&1 || { cat output; exit 1; }
# @TEST-EXEC: btest-diff output

@TEST-START-FILE check.sh
set -u
GEN=$1
FIXTURE=$2

# Expect exit status 2, an "error:" line and no traceback.
reject() {
    local name=$1; shift
    python3 "$GEN" "$@" >run.out 2>run.err
    local rc=$?
    if [ $rc -ne 2 ] || ! grep -q '^error: ' run.err || grep -q Traceback run.err; then
        echo "FAIL $name: exit $rc"; cat run.out run.err; exit 1
    fi
    echo "rejected $name"
}

# --- The reference survives every way of naming it as the output. ---------
mkdir -p ref sub
cp "$FIXTURE" ref/pristine.pcap
cp ref/pristine.pcap ref/target.pcap
ln -s target.pcap ref/symlink.pcap
ln ref/target.pcap ref/hardlink.pcap
ABS=$(pwd)/ref/target.pcap

reject same-path         -o ref/target.pcap --force --compare ref/target.pcap
reject relative-absolute -o ref/target.pcap --force --compare "$ABS"
reject dot-segments      -o ./sub/../ref/./target.pcap --force --compare ref/target.pcap
reject output-symlink    -o ref/symlink.pcap --force --compare ref/target.pcap
reject compare-symlink   -o ref/target.pcap --force --compare ref/symlink.pcap
reject hard-link         -o ref/hardlink.pcap --force --compare ref/target.pcap
reject same-path-noforce -o ref/target.pcap --compare ref/target.pcap
cmp ref/pristine.pcap ref/target.pcap || { echo "FAIL: reference changed"; exit 1; }
[ "$(readlink ref/symlink.pcap)" = target.pcap ] || { echo "FAIL: symlink replaced"; exit 1; }
cmp ref/pristine.pcap ref/hardlink.pcap || { echo "FAIL: hard link changed"; exit 1; }
echo "reference unchanged"

# A different file is still compared normally.
python3 "$GEN" -o generated.pcap --compare ref/target.pcap >run.out 2>&1 && grep -qx IDENTICAL run.out \
    || { echo "FAIL: normal comparison"; cat run.out; exit 1; }
echo "distinct output compares IDENTICAL"

# --- Malformed captures. -------------------------------------------------
python3 - "$FIXTURE" <<'PY'
import struct, sys
d = open(sys.argv[1], "rb").read()
hdr, rec = d[:24], d[24:]
incl = struct.unpack("<I", rec[8:12])[0]
first = rec[:16 + incl]                     # first record: header + frame
frame = first[16:]

def with_frame(fr):
    return hdr + struct.pack("<IIII", 1, 0, len(fr), len(fr)) + fr

def patch_hdr(off, fmt, val):
    h = bytearray(hdr); struct.pack_into(fmt, h, off, val); return bytes(h) + rec

udp_ip4 = bytearray(frame)
cases = {
    "empty": b"",
    "truncated-file-header": hdr[:10],
    "bad-magic": b"\0\0\0\0" + hdr[4:] + rec,
    "nanosecond-magic": patch_hdr(0, "<I", 0xA1B23C4D),
    "bad-version": patch_hdr(4, "<H", 3),
    "zero-snaplen": patch_hdr(16, "<I", 0),
    "non-ethernet-linktype": patch_hdr(20, "<I", 101),
    "truncated-record-header": hdr + first[:10],
    "incomplete-record": hdr + first[:-5],
    "bad-microseconds": hdr + first[:4] + struct.pack("<I", 1_000_000) + first[8:],
    "caplen-over-origlen": hdr + first[:12] + struct.pack("<I", incl - 1) + first[16:],
    "frame-shorter-than-ethernet": with_frame(frame[:6]),
    "non-ip-ethertype": with_frame(frame[:12] + b"\x08\x06" + frame[14:]),
    "ipv4-not-udp": with_frame(frame[:23] + b"\x06" + frame[24:]),
    "ipv4-bad-ihl": with_frame(frame[:14] + b"\x41" + frame[15:]),
    "udp-length-too-big": with_frame(frame[:38] + b"\xff\xff" + frame[40:]),
    "truncated-udp-header": with_frame(frame[:34 + 4]),
}
for name, data in cases.items():
    open(f"bad-{name}.pcap", "wb").write(data)
print(" ".join(cases))
PY
for f in bad-*.pcap; do
    name=${f#bad-}; name=${name%.pcap}
    reject "$name" -o "out-$name.pcap" --compare "$f"
done
reject missing-compare -o out-missing.pcap --compare does-not-exist.pcap
reject compare-is-directory -o out-dir.pcap --compare sub

# --- Unreadable files. ----------------------------------------------------
# Root ignores file permissions, so a driver makes open() raise a real
# PermissionError for one path: "always", or only after its first read
# (the generator's readability check) to hit the comparison itself.
cat >deny.py <<'PY'
import builtins, os, runpy, sys
gen, mode, target, *argv = sys.argv[1:]
target, real_open, reads = os.path.realpath(target), builtins.open, [0]
def deny_open(file, flags="r", *a, **k):
    if isinstance(file, (str, os.PathLike)) and "r" in flags and os.path.realpath(file) == target:
        reads[0] += 1
        if mode == "always" or reads[0] > 1:
            raise PermissionError(13, "Permission denied", os.fspath(file))
    return real_open(file, flags, *a, **k)
builtins.open = deny_open
sys.argv = [gen] + argv
runpy.run_path(gen, run_name="__main__")
PY
REAL_GEN=$GEN
reject_denied() {
    local name=$1 mode=$2 target=$3; shift 3
    GEN=deny.py
    reject "$name" "$REAL_GEN" "$mode" "$target" "$@"
    GEN=$REAL_GEN
    grep -q 'cannot read: Permission denied' run.err || { echo "FAIL $name: wrong error"; cat run.err; exit 1; }
}
cp ref/pristine.pcap unreadable.pcap
reject_denied unreadable-reference always unreadable.pcap -o out-denied.pcap --compare unreadable.pcap
[ ! -e out-denied.pcap ] || { echo "FAIL: output created before the readability check"; exit 1; }
echo "no output written for an unreadable reference"
reject_denied reference-unreadable-at-compare after-first unreadable.pcap -o out-late.pcap --compare unreadable.pcap
reject_denied generated-unreadable-at-compare always out-gen.pcap -o out-gen.pcap --compare unreadable.pcap

# The real thing where permissions apply (not as root); kept out of the
# baseline so the output doesn't depend on the user.
chmod 000 unreadable.pcap
if [ "$(id -u)" != 0 ]; then
    reject real-permission-denied -o out-real.pcap --compare unreadable.pcap >real-permission.txt
fi
chmod 644 unreadable.pcap
@TEST-END-FILE
