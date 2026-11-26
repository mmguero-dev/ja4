#!/usr/bin/env python3
"""Generate the JA4N synthetic test capture (pcap/ja4n-synthetic.pcap).

Every case below is one UDP flow exercising one JA4N edge case. Flows get
addresses and start times from their position in CASES, so cases must only
ever be appended: inserting or reordering one changes every later flow, and
with it the expected values in testing/tests/ja4n-synthetic.zeek.

Python 3 standard library only. Output is fully deterministic: no clock,
randomness or network access, and packets are written in an explicit order.

Usage:
  gen-ja4n-synthetic.py [-o OUT] [--force] [--compare PCAP]

  -o OUT          where to write the capture (default: a new file in the
                  system temporary directory; the path is printed)
  --force         allow -o to replace an existing file
  --compare PCAP  after writing, compare the result with PCAP (e.g. the
                  committed pcap/ja4n-synthetic.pcap) and exit non-zero if
                  they differ in any way. OUT must not be PCAP itself (by
                  any path, symlink or hard link); that is rejected before
                  anything is written.

Exit status: 0 success / identical, 1 captures differ, 2 usage error or
unreadable/malformed capture.
"""

import argparse
import hashlib
import os
import struct
import sys
import tempfile

T0 = 1700000000          # 2023-11-14T22:13:20Z, base time of flow 0
FLOW_SPACING = 1000      # seconds between flow start times, beyond any UDP timeout
NTP_OFF = 2208988800     # seconds from the NTP epoch (1900) to the Unix epoch
DAY = 86400

CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")


# --- NTP payloads --------------------------------------------------------------

def ts(unix_secs, frac=0):
    """A 64-bit NTP timestamp for whole Unix seconds plus a 32-bit fraction."""
    return ((unix_secs + NTP_OFF) << 32) | frac


def ntp(li=0, vn=4, mode=3, stratum=0, poll=6, prec=-20, rdelay=0, rdisp=0,
        refid=b"\0\0\0\0", ref=0, org=0, rec=0, xmt=0, extra=b""):
    """A 48-byte NTP header (RFC 5905 section 7.3) followed by `extra`."""
    first = ((li & 3) << 6) | ((vn & 7) << 3) | (mode & 7)
    return struct.pack("!BBbBII4sQQQQ", first, stratum, poll, prec & 0xFF, rdelay, rdisp,
                       refid, ref, org, rec, xmt) + extra


# --- Packet construction ---------------------------------------------------------

def _csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _v4(addr):
    return bytes(int(x) for x in addr.split("."))


def _v6(addr):
    import ipaddress
    return ipaddress.IPv6Address(addr).packed


def frame(v6, src, dst, sport, dport, payload, from_client):
    """Ethernet + IPv4/IPv6 + UDP. Header fields: IPv4 id 1, TTL 64, no flags;
    IPv6 hop limit 64, flow label 0; UDP checksum always computed."""
    udp_len = 8 + len(payload)
    s, d = (_v6(src), _v6(dst)) if v6 else (_v4(src), _v4(dst))
    if v6:
        pseudo = s + d + struct.pack("!I3xB", udp_len, 17)
    else:
        pseudo = s + d + struct.pack("!BBH", 0, 17, udp_len)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload
    c = _csum(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", c) + udp[8:]
    if v6:
        l3 = struct.pack("!IHBB", 6 << 28, udp_len, 17, 64) + s + d
        ethertype = 0x86DD
    else:
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + udp_len, 1, 0, 64, 17, 0, s, d)
        l3 = hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:]
        ethertype = 0x0800
    # Both directions use the same MAC pair, as the original fixture does.
    return SERVER_MAC + CLIENT_MAC + struct.pack("!H", ethertype) + l3 + udp


# --- Cases ---------------------------------------------------------------------------
#
# A case is (name, options, packets). options: v6 (default False), cport
# (client port, default 40000), sport (server port, default 123). Each packet
# is (from_client, payload, offset_us), where offset_us is microseconds after
# the flow's start. Payload builders receive b, the flow's start time.

def C(name, packets, v6=False, cport=40000, sport=123):
    return (name, dict(v6=v6, cport=cport, sport=sport), packets)


def ms(x):
    return int(round(x * 1000)) * 1000 if isinstance(x, float) else x * 1000


CLIENT, SERVER = True, False


def _cases():
    cases = []
    add = cases.append

    # 1/2. Typical client request and server response, IPv4 and IPv6.
    for v6 in (False, True):
        add(C(f"basic-exchange-{'ipv6' if v6 else 'ipv4'}", lambda b: [
            (CLIENT, ntp(vn=4, mode=3, poll=6, prec=-20, xmt=ts(b, 0x1234)), 0),
            (SERVER, ntp(vn=4, mode=4, stratum=2, poll=6, prec=-23, rdelay=0x0123, rdisp=0x0456,
                         refid=b"\xc0\x00\x02\x01", ref=ts(b - 100), org=ts(b, 0x1234), rec=ts(b, 9),
                         xmt=ts(b, 10)), ms(10)),
        ], v6=v6))

    add(C("ntpd-style-both-ports-123-historical-ref", lambda b: [
        (CLIENT, ntp(vn=4, mode=3, stratum=3, poll=10, prec=-25, rdelay=0x0200, rdisp=0x0300,
                     refid=b"\x0a\x00\x00\x01", ref=ts(b - 400 * DAY), org=ts(b - 5), rec=ts(b - 5),
                     xmt=ts(b)), 0),
        (SERVER, ntp(vn=4, mode=4, stratum=1, poll=10, prec=-29, rdisp=0x10, refid=b"GPS\0",
                     ref=ts(b - 8), org=ts(b), rec=ts(b, 1), xmt=ts(b, 2)), ms(20)),
    ], cport=123))

    # 3. Versions 1-4 and modes 1-5.
    for vn in (1, 2, 3, 4):
        add(C(f"version-{vn}-client-server", lambda b, vn=vn: [
            (CLIENT, ntp(vn=vn, mode=3, poll=4, prec=-6, xmt=ts(b)), 0),
            (SERVER, ntp(vn=vn, mode=4, stratum=2, poll=4, prec=-18, refid=b"\x01\x02\x03\x04",
                         xmt=ts(b)), ms(10)),
        ]))
    add(C("symmetric-active-passive", lambda b: [
        (CLIENT, ntp(vn=4, mode=1, stratum=2, poll=6, refid=b"\x7f\x7f\x01\x00", xmt=ts(b)), 0),
        (SERVER, ntp(vn=4, mode=2, stratum=2, poll=6, refid=b"\x7f\x7f\x01\x00", xmt=ts(b)), ms(10)),
    ], cport=123))
    add(C("broadcast-one-direction", lambda b: [
        (SERVER, ntp(vn=4, mode=5, stratum=2, poll=6, refid=b"\x7f\x7f\x01\x00", xmt=ts(b)), 0),
    ], cport=123))
    # First packet fails classification; the later valid one is the same direction.
    for label, bad in (("version-0", dict(vn=0)), ("version-5", dict(vn=5)),
                       ("mode-0", dict(mode=0)), ("stratum-17", dict(stratum=17))):
        add(C(f"unclassifiable-first-{label}", lambda b, bad=bad: [
            (CLIENT, ntp(**{"xmt": ts(b), **bad}), 0),
            (CLIENT, ntp(xmt=ts(b)), ms(500)),
        ]))

    # 4. Leap indicators and strata.
    for li in (1, 2, 3):
        add(C(f"leap-{li}", lambda b, li=li: [
            (SERVER, ntp(li=li, mode=4, stratum=2, xmt=ts(b)), 0),
        ]))
    for st, rid in ((0, b"RATE"), (0, b"DENY"), (1, b"PPS\0"), (1, b"LOCL"),
                    (15, b"\x0a\x0b\x0c\x0d"), (16, b"INIT")):
        add(C(f"stratum-{st}-refid-{rid.rstrip(bytes(1)).decode('latin-1')}", lambda b, st=st, rid=rid: [
            (SERVER, ntp(li=3 if st in (0, 16) else 0, mode=4, stratum=st, refid=rid, xmt=ts(b)), 0),
        ]))

    # 5. Poll exponents.
    for poll in (0, 1, 17, -1, -4, -6, -128, 127):
        add(C(f"poll-{poll}", lambda b, poll=poll: [(CLIENT, ntp(poll=poll, xmt=ts(b)), 0)]))

    # 6. Precision and 16.16 fixed-point boundaries.
    for prec in (0, 1, 127, -128, -1, -32):
        add(C(f"precision-{prec}", lambda b, prec=prec: [(CLIENT, ntp(prec=prec, xmt=ts(b)), 0)]))
    for rd, rp in ((0, 0), (0x10000, 0x10000), (0xFFFF, 0x10001), (0x10000, 0), (0xFFFFFFFF, 1)):
        add(C(f"root-delay-{rd:#x}-dispersion-{rp:#x}", lambda b, rd=rd, rp=rp: [
            (SERVER, ntp(mode=4, stratum=2, rdelay=rd, rdisp=rp, xmt=ts(b)), 0),
        ]))

    # 7. Zero, recent and historical timestamps.
    add(C("timestamps-fraction-only-1900-exactly-1970", lambda b: [
        (SERVER, ntp(mode=4, stratum=2, ref=1, org=ts(-NTP_OFF + 1), rec=ts(0), xmt=ts(b)), 0),
    ]))
    add(C("timestamps-30-day-boundaries", lambda b: [
        (SERVER, ntp(mode=4, stratum=2, ref=ts(b - 30 * DAY), org=ts(b + 30 * DAY),
                     rec=ts(b - 30 * DAY - 1), xmt=ts(b + 30 * DAY + 1)), 0),
    ]))
    add(C("timestamps-historical-all-ones-era-wrap", lambda b: [
        (SERVER, ntp(mode=4, stratum=2, ref=ts(b - 20 * 365 * DAY), org=0xFFFFFFFFFFFFFFFF,
                     rec=ts(b, 0xFFFFFFFF), xmt=0x0000000100000000), 0),
    ]))
    # Capture time has a fraction; the reference truncates it to whole seconds.
    add(C("capture-time-fraction-truncated", lambda b: [
        (CLIENT, ntp(xmt=ts(b - 30 * DAY)), ms(900)),
    ]))

    # 8. IPv6 vs IPv4 reference ids.
    add(C("ipv6-stratum-3-refid-is-family", lambda b: [
        (SERVER, ntp(mode=4, stratum=3, refid=b"\xde\xad\xbe\xef", xmt=ts(b)), 0)], v6=True))
    add(C("ipv6-stratum-1-refid-is-name", lambda b: [
        (SERVER, ntp(mode=4, stratum=1, refid=b"GPS\0", xmt=ts(b)), 0)], v6=True))
    add(C("ipv6-stratum-0-zero-refid", lambda b: [
        (SERVER, ntp(mode=4, stratum=0, refid=b"\0\0\0\0", xmt=ts(b)), 0)], v6=True))

    # 9. Unusual reference identifiers (stratum 1).
    for rid in (b"\x01\x02\x03\x04", b"A\0B\0", b"AB C", b"X\0YZ", b"\0\0\0X", b"\x80ABC", b"~_ \x7e",
                b"\x7fABC", b"AB_\0"):
        add(C(f"refid-{rid.hex()}", lambda b, rid=rid: [
            (SERVER, ntp(mode=4, stratum=1, refid=rid, xmt=ts(b)), 0)]))

    # 10. Truncated, malformed and odd-length payloads.
    add(C("first-client-payload-truncated", lambda b: [
        (CLIENT, ntp(xmt=ts(b))[:47], 0),
        (CLIENT, ntp(xmt=ts(b)), ms(100)),
    ]))
    add(C("truncated-client-then-valid-server-qualifies", lambda b: [
        (CLIENT, ntp(xmt=ts(b))[:47], 0),
        (SERVER, ntp(mode=4, stratum=2, xmt=ts(b)), ms(100)),
        (CLIENT, ntp(poll=7, xmt=ts(b)), ms(200)),
        (CLIENT, ntp(poll=8)[:47], ms(300)),
    ]))
    add(C("qualified-flow-not-rechecked-mode-0-version-7", lambda b: [
        (CLIENT, ntp(xmt=ts(b)), 0),
        (CLIENT, ntp(vn=7, mode=0, stratum=200, xmt=ts(b)), ms(100)),
    ]))
    add(C("extension-field-and-macs-ignored", lambda b: [
        (CLIENT, ntp(xmt=ts(b), extra=struct.pack("!HH", 0x0104, 16) + b"\x00" * 12), 0),
        (CLIENT, ntp(xmt=ts(b), extra=b"\x00\x00\x00\x01" + b"\xaa" * 16), ms(100)),
        (CLIENT, ntp(xmt=ts(b), extra=b"\x00\x00\x00\x01" + b"\xbb" * 20), ms(200)),
        (CLIENT, ntp(xmt=ts(b), extra=b"\xff" * 3), ms(300)),
    ]))
    add(C("mode-6-control-request-and-response", lambda b: [
        (CLIENT, bytes([0x16, 0x02, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]), 0),
        (SERVER, bytes([0x16, 0x82, 0, 1, 0, 0, 0, 0, 0, 0, 0, 40]) + b'version="ntpd"' + b"\0" * 26, ms(10)),
    ]))
    add(C("mode-7-private-request", lambda b: [
        (CLIENT, bytes([0x17, 0x00, 0x03, 0x2a]) + b"\0" * 44, 0),
    ]))
    add(C("garbage-on-port-123", lambda b: [
        (CLIENT, bytes(range(0x80, 0x80 + 60)), 0),
    ]))
    add(C("empty-payload-then-valid", lambda b: [
        (CLIENT, b"", 0),
        (CLIENT, ntp(xmt=ts(b)), ms(100)),
    ]))

    # 11. Multiple packets within a connection.
    add(C("five-identical-exchanges", lambda b: [
        p for i in range(5) for p in (
            (CLIENT, ntp(xmt=ts(b + i)), i * 2_000_000),
            (SERVER, ntp(mode=4, stratum=2, org=ts(b + i), xmt=ts(b + i)), i * 2_000_000 + 10_000),
        )
    ]))
    add(C("changing-poll-6-7-8-7-6", lambda b: [
        (CLIENT, ntp(poll=poll, xmt=ts(b + i)), i * 2_000_000) for i, poll in enumerate((6, 7, 8, 7, 6))
    ]))

    # 14. Not port 123: never fingerprinted.
    add(C("not-port-123", lambda b: [
        (CLIENT, ntp(xmt=ts(b)), 0),
        (SERVER, ntp(mode=4, stratum=2, xmt=ts(b)), ms(10)),
    ], sport=12300))

    add(C("server-packet-first", lambda b: [
        (SERVER, ntp(mode=4, stratum=2, poll=9, xmt=ts(b)), 0),
        (CLIENT, ntp(poll=9, xmt=ts(b)), ms(10)),
    ]))

    add(C("reference-time-is-connection-start", lambda b: [
        (CLIENT, ntp(xmt=ts(b)), 0),
        (CLIENT, ntp(poll=7, ref=ts(b - 30 * DAY), xmt=ts(b)), 5_000_000),  # exactly 30 days before the first packet
    ]))

    # Zeek flips roles twice on the first packet (port-123 side sends client
    # mode): the two port-123-side packets share a direction although Zeek's
    # is_orig differs between them.
    add(C("role-flip-on-first-packet", lambda b: [
        (SERVER, ntp(mode=3, stratum=17, xmt=ts(b)), 0),               # first of its direction, fails
        (SERVER, ntp(mode=3, poll=5, xmt=ts(b)), 250_000),             # same direction: not re-classified
        (CLIENT, ntp(mode=4, stratum=2, xmt=ts(b)), 500_000),          # other direction's first: qualifies
        (SERVER, ntp(mode=3, poll=7, xmt=ts(b)), 750_000),             # now fingerprinted
    ]))

    # Zeek flips roles on the second packet (server mode sent by the originator).
    add(C("role-flip-on-second-packet", lambda b: [
        (CLIENT, ntp(mode=3, stratum=17, xmt=ts(b)), 0),               # first of its direction, fails
        (CLIENT, ntp(mode=4, stratum=2, poll=8, xmt=ts(b)), 250_000),  # same direction, causes the flip
        (SERVER, ntp(mode=4, stratum=2, xmt=ts(b)), 500_000),          # other direction's first: qualifies
        (CLIENT, ntp(mode=3, poll=9, xmt=ts(b)), 750_000),             # fingerprinted
    ]))

    return cases


CASES = _cases()


def packets():
    """All packets as (timestamp_us, frame bytes), in capture order."""
    out = []
    for n, (name, opt, build) in enumerate(CASES, start=1):
        if opt["v6"]:
            c, s = f"2001:db8:1::{n:x}", f"2001:db8:2::{n:x}"
        else:
            c, s = f"10.1.{n // 250}.{n % 250 + 1}", f"10.2.{n // 250}.{n % 250 + 1}"
        base = T0 + n * FLOW_SPACING
        for from_client, payload, offset_us in build(base):
            src, dst = (c, s) if from_client else (s, c)
            sp, dp = (opt["cport"], opt["sport"]) if from_client else (opt["sport"], opt["cport"])
            out.append((base * 1_000_000 + offset_us,
                        frame(opt["v6"], src, dst, sp, dp, payload, from_client)))
    # Stable sort: packets with equal times keep case order.
    out.sort(key=lambda p: p[0])
    return out


def write_pcap(path, pkts):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # usec, Ethernet
        for t_us, fr in pkts:
            f.write(struct.pack("<IIII", t_us // 1_000_000, t_us % 1_000_000, len(fr), len(fr)) + fr)


class PcapError(Exception):
    """A capture that cannot be read or is not what this script writes."""


LINKTYPE_ETHERNET = 1
MAX_SNAPLEN = 262144


def read_bytes(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise PcapError(f"{path}: cannot read: {e.strerror or e}")


def read_pcap(path):
    """Parse a classic little-endian microsecond pcap of Ethernet frames.
    Returns (24-byte file header, [(timestamp_us, frame, orig_len)])."""
    data = read_bytes(path)
    if len(data) < 24:
        raise PcapError(f"{path}: truncated file header ({len(data)} of 24 bytes)")
    magic, major, minor, _zone, _sigfigs, snaplen, linktype = struct.unpack("<IHHiIII", data[:24])
    if magic != 0xA1B2C3D4:
        raise PcapError(f"{path}: not a little-endian microsecond pcap (magic {magic:#010x})")
    if (major, minor) != (2, 4):
        raise PcapError(f"{path}: unsupported pcap version {major}.{minor}")
    if not 0 < snaplen <= MAX_SNAPLEN:
        raise PcapError(f"{path}: invalid snapshot length {snaplen}")
    if linktype != LINKTYPE_ETHERNET:
        raise PcapError(f"{path}: link type {linktype} is not Ethernet ({LINKTYPE_ETHERNET})")

    pkts, off, n = [], 24, 0
    while off < len(data):
        n += 1
        if len(data) - off < 16:
            raise PcapError(f"{path}: packet {n}: truncated record header at offset {off}")
        sec, usec, incl, orig = struct.unpack("<IIII", data[off:off + 16])
        if usec >= 1_000_000:
            raise PcapError(f"{path}: packet {n}: invalid microseconds {usec}")
        if incl > snaplen or incl > orig:
            raise PcapError(f"{path}: packet {n}: captured length {incl} exceeds "
                            f"{'snapshot length ' + str(snaplen) if incl > snaplen else 'original length ' + str(orig)}")
        if len(data) - off - 16 < incl:
            raise PcapError(f"{path}: packet {n}: incomplete record ({len(data) - off - 16} of {incl} bytes)")
        pkts.append((sec * 1_000_000 + usec, data[off + 16:off + 16 + incl], orig))
        off += 16 + incl
    return data[:24], pkts


def flow_key(fr, n=0):
    """(src, sport, dst, dport, udp payload) of an Ethernet/IP/UDP frame."""
    import ipaddress

    def bad(why):
        return PcapError(f"packet {n}: malformed frame: {why}")

    if len(fr) < 14:
        raise bad(f"{len(fr)} bytes is shorter than an Ethernet header")
    et, = struct.unpack("!H", fr[12:14])
    ip = fr[14:]
    if et == 0x0800:
        if len(ip) < 20 or ip[0] >> 4 != 4:
            raise bad("truncated or invalid IPv4 header")
        ihl = (ip[0] & 0x0F) * 4
        if ihl < 20 or len(ip) < ihl:
            raise bad(f"invalid IPv4 header length {ihl}")
        if ip[9] != 17:
            raise bad(f"IPv4 protocol {ip[9]} is not UDP")
        src, dst, udp = ipaddress.IPv4Address(ip[12:16]), ipaddress.IPv4Address(ip[16:20]), ip[ihl:]
    elif et == 0x86DD:
        if len(ip) < 40 or ip[0] >> 4 != 6:
            raise bad("truncated or invalid IPv6 header")
        if ip[6] != 17:
            raise bad(f"IPv6 next header {ip[6]} is not UDP")
        src, dst, udp = ipaddress.IPv6Address(ip[8:24]), ipaddress.IPv6Address(ip[24:40]), ip[40:]
    else:
        raise bad(f"EtherType {et:#06x} is neither IPv4 nor IPv6")
    if len(udp) < 8:
        raise bad("truncated UDP header")
    sp, dp, ulen = struct.unpack("!HHH", udp[:6])
    if ulen < 8 or ulen > len(udp):
        raise bad(f"UDP length {ulen} does not fit the {len(udp)}-byte datagram")
    return (str(src), sp, str(dst), dp, udp[8:ulen])


def keyed(path, frame, n):
    try:
        return flow_key(frame, n)
    except PcapError as e:
        raise PcapError(f"{path}: {e}")


def compare(generated, committed):
    ha = hashlib.sha256(read_bytes(generated)).hexdigest()
    hb = hashlib.sha256(read_bytes(committed)).hexdigest()
    a_hdr, a = read_pcap(generated)
    b_hdr, b = read_pcap(committed)
    print(f"generated: {generated}\n  sha256 {ha}\n  packets {len(a)}")
    print(f"committed: {committed}\n  sha256 {hb}\n  packets {len(b)}")
    problems = 0
    if a_hdr != b_hdr:
        print("file header differs:", a_hdr.hex(), b_hdr.hex()); problems += 1
    for i, (pa, pb) in enumerate(zip(a, b)):
        if pa[0] != pb[0]:
            print(f"packet {i + 1}: timestamp {pa[0] / 1e6:.6f} vs {pb[0] / 1e6:.6f}"); problems += 1
        if pa[1:] != pb[1:]:
            ka, kb = keyed(generated, pa[1], i + 1), keyed(committed, pb[1], i + 1)
            what = "payload" if ka[:4] == kb[:4] else "addresses/ports"
            print(f"packet {i + 1}: {what} differ ({ka[:4]} vs {kb[:4]})"); problems += 1
    if len(a) != len(b):
        print(f"packet count differs: {len(a)} vs {len(b)}"); problems += 1
    sa = sorted((p[0], keyed(generated, p[1], i + 1)) for i, p in enumerate(a))
    sb = sorted((p[0], keyed(committed, p[1], i + 1)) for i, p in enumerate(b))
    if sa != sb:
        print("semantic difference: the (time, endpoints, payload) sets differ"); problems += 1
    print("IDENTICAL" if problems == 0 and ha == hb else f"DIFFERENT ({problems} problem(s))")
    return problems == 0 and ha == hb


def same_file(a, b):
    """Whether paths a and b name the same file: same resolved path (covers
    relative/absolute spellings and symlinks, including a dangling symlink a
    write would follow) or, for existing files, the same inode (hard links)."""
    if os.path.realpath(a) == os.path.realpath(b):
        return True
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("-o", "--output")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--compare")
    ap.add_argument("--list", action="store_true", help="print the flows and exit")
    args = ap.parse_args()

    if args.list:
        for n, (name, opt, build) in enumerate(CASES, start=1):
            print(f"{n:3d} {name}")
        return 0

    out = args.output
    if args.compare is not None:
        if not os.path.isfile(args.compare):
            print(f"error: --compare {args.compare}: not a readable regular file", file=sys.stderr)
            return 2
        try:
            with open(args.compare, "rb"):
                pass
        except OSError as e:
            print(f"error: --compare {args.compare}: cannot read: {e.strerror or e}", file=sys.stderr)
            return 2
        if out is not None and same_file(out, args.compare):
            print(f"error: --output {out} is the --compare file {args.compare}; "
                  "refusing to overwrite the reference", file=sys.stderr)
            return 2
    if out is None:
        fd, out = tempfile.mkstemp(prefix="ja4n-synthetic-", suffix=".pcap")
        os.close(fd)
    elif os.path.lexists(out) and not args.force:
        print(f"error: {out} exists; pass --force to replace it", file=sys.stderr)
        return 2

    pkts = packets()
    try:
        write_pcap(out, pkts)
    except OSError as e:
        print(f"error: cannot write {out}: {e.strerror}", file=sys.stderr)
        return 2
    print(f"wrote {len(pkts)} packets in {len(CASES)} flows to {out}")
    if args.compare:
        try:
            return 0 if compare(out, args.compare) else 1
        except PcapError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
