CMD=$1

if [ "$CMD" == "up" ]; then
    sudo ip tuntap add dev tap0 mode tap user `whoami`
    sudo ip tuntap add dev tap1 mode tap user `whoami`
    # echo 1 | sudo tee /proc/sys/net/ipv4/conf/tap0/accept_local
    # echo 1 | sudo tee /proc/sys/net/ipv4/conf/tap1/accept_local
    # echo 2 | sudo tee /proc/sys/net/ipv4/conf/tap0/rp_filter
    # echo 2 | sudo tee /proc/sys/net/ipv4/conf/tap1/rp_filter
    sudo ip link add lwipbridge type bridge
    # sudo ip addr add 192.168.1.1/24 dev lwipbridge
    sudo ifconfig lwipbridge inet 192.168.1.1 netmask 255.255.255.0 broadcast 192.168.1.255
    sudo ip link set tap0 master lwipbridge
    sudo ip link set tap1 master lwipbridge
    # sudo ip addr add 192.168.1.2/32 dev tap0
    # sudo ip addr add 192.168.1.3/32 dev tap1
    sudo ifconfig tap0 inet 192.168.1.2 netmask 255.255.255.0 broadcast 192.168.1.255
    sudo ifconfig tap1 inet 192.168.1.3 netmask 255.255.255.0 broadcast 192.168.1.255
    sudo ip link set tap0 up
    sudo ip link set tap1 up
    sudo ip link set dev lwipbridge up
fi

if [ "$CMD" == "down" ]; then
    sudo ip tuntap del dev tap0 mode tap
    sudo ip tuntap del dev tap1 mode tap
    sudo ip link del lwipbridge
fi
