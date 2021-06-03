CMD=$1

if [ "$CMD" == "up" ]; then
    sudo ip tuntap add dev tap0 mode tap user `whoami`
    sudo ip link set tap0 up
    sudo ip link add lwipbridge type bridge
    sudo ip link set tap0 master lwipbridge
    sudo ip addr add 192.168.1.1/24 dev lwipbridge
    sudo ip link set dev lwipbridge up
fi

if [ "$CMD" == "down" ]; then
    sudo ip tuntap del dev tap0 mode tap
    sudo ip link del lwipbridge
fi
