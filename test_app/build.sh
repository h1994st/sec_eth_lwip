make clean
make sender CONNECTION=0 MACSEC=0 ADDR_BYTE_4=2 RECEIVER_ADDR=192.168.1.3
make clean
make receiver CONNECTION=0 MACSEC=0 ADDR_BYTE_4=3 RECEIVER_ADDR=192.168.1.3
make clean
make app CONNECTION=0 MACSEC=0 ADDR_BYTE_4=200 RECEIVER_ADDR=127.0.0.1
make clean
