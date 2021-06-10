make clean
make sender LOG_LEVEL=1 CONNECTION=0 IPSEC=0 MACSEC=1 ADDR_BYTE_4=2 RECEIVER_ADDR=192.168.1.3
make clean
make receiver LOG_LEVEL=1 CONNECTION=0 IPSEC=0 MACSEC=1 ADDR_BYTE_4=3 RECEIVER_ADDR=192.168.1.3
make clean

# sudo PRECONFIGURED_TAPIF=tap1 ./receiver &
# sleep 5
# sudo PRECONFIGURED_TAPIF=tap0 ./sender &
# sleep 5
# pkill receiver
# pkill sender
