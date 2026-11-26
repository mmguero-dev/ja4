# pcap/ja4n-synthetic.pcap must be exactly what scripts/gen-ja4n-synthetic.py
# produces, so the fixture can be reviewed and regenerated from readable
# cases. The generator needs only the Python 3 standard library.
#
# @TEST-EXEC: python3 %DIR/../scripts/gen-ja4n-synthetic.py -o generated.pcap --compare $TRACES/ja4n-synthetic.pcap >output 2>&1 || { cat output; exit 1; }
