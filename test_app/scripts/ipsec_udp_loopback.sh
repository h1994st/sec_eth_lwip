make clean
make app LOG_LEVEL=1 CONNECTION=0 IPSEC=1 MACSEC=0 ADDR_BYTE_4=200 RECEIVER_ADDR=127.0.0.1

./app
