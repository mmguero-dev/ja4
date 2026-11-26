# JA4N for IPv6 against independent Arkime golden values.
#
# ja4n-arkime-ospf-ipv6.pcap holds frames 217 and 226 of arkime/arkime
# tests/pcap/ospf.pcap (https://github.com/arkime/arkime, blob
# 420727b79962df3ab345485bb83a98db6d116b87, sha256
# 1c3442fe1f3be3d9cccdbae64bc4db69b97944a0990a0c018433b21891e82278), copied with
# their original bytes and timestamps:
#
#   editcap -F pcap -r ospf.pcap ja4n-arkime-ospf-ipv6.pcap 217 226
#
# Those are two NTPv4 client requests, 2001:bef::a00:27ff:fe0d:5c3c:123 to
# 2001:418:8405:4002::3:123 and to 2001:67c:1560:8003::c8:123, each its own
# connection. The capture comes from the Arkime project and is used under the
# Apache License 2.0; provenance and attribution are in
# pcap/ja4n-arkime-ospf-ipv6.pcap.license.
#
# The expected lines below are the "ntp.ja4n" values Arkime recorded for these
# two sessions in arkime/ja4 pcap/ospf.test (commit
# 27099fb11f351f35d69f4ce366374aa91536af04), not output of this plugin.
#
# @TEST-EXEC: zeek -C -r $TRACES/ja4n-arkime-ospf-ipv6.pcap %INPUT
# @TEST-EXEC: test ! -f ja4n.log
# @TEST-EXEC: grep -q '^#fields.*ja4n' ntp.log
# @TEST-EXEC: zeek-cut ja4n < ntp.log | awk '$1 != "(empty)" { n++ } END { exit !(NR == 2 && n == 2) }'
# @TEST-EXEC: %DIR/../scripts/ja4n-normalize < ntp.log > actual
# @TEST-EXEC: diff -u arkime-golden actual
# @TEST-EXEC: %DIR/../scripts/ja4n-check-fields < ntp.log
# @TEST-EXEC: zeek-cut uid id.orig_h id.orig_p id.resp_h id.resp_p mode ja4n < ntp.log > output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE arkime-golden
2001:418:8405:4002::3:123	2001:bef::a00:27ff:fe0d:5c3c:123	c4-3-0-6-24-02_0001_INIT_64
2001:67c:1560:8003::c8:123	2001:bef::a00:27ff:fe0d:5c3c:123	c4-3-0-6-24-02_0001_INIT_64
@TEST-END-FILE
