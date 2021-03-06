# lwip for Secure Ethernet

- This is a fork of [lwip-tcpip/lwip@7ec4e9b](https://github.com/lwip-tcpip/lwip/tree/7ec4e9be304e7f8953740f10b2c810a292e89449)
- The IPsec part is ported from
    - [owenlwebb/lwip-eips](https://github.com/owenlwebb/lwip-eips) --> [h1994st/lwip-eips](https://github.com/h1994st/lwip-eips)
    - which is originally implemented by [tinytux/embeddedipsec](https://github.com/tinytux/embeddedipsec)

## Example application

Location: [contrib/examples/example_app](contrib/examples/example_app)

### Build `lwip`

1. Create `lwipcfg.h` under `contrib/examples/example_app` directory

    ```bash
    cp contrib/examples/example_app/lwipcfg.h.lwipcfg.h.example contrib/examples/example_app/lwipcfg.h
    ```

2. Disable DHCP and AUTOIP by defining `USE_DHCP` and `USE_AUTOIP` as `0` in `lwipcfg.h`

    ```c
    #define USE_DHCP    0
    #define USE_AUTOIP  0
    ```

3. Enable HTTP server application

    ```c
    // LWIP_HTTPD_APP has already defined as 0 in lwipcfg.h
    // change it to 1
    #define LWIP_HTTPD_APP 1
    ```

4. Create `build` directory for CMake and build

    ```bash
    mkdir build
    cd build
    cmake ..
    make
    ```

### Setup Tun/Tap Interface

```bash
sudo ip tuntap add dev tap0 mode tap user `whoami`
sudo ip link set tap0 up
sudo ip link add lwipbridge type bridge
sudo ip link set tap0 master lwipbridge
sudo ip addr add 192.168.1.1/24 dev lwipbridge
sudo ip link set dev lwipbridge up
```

Reference:

- <https://github.com/lwip-tcpip/lwip/blob/7ec4e9be304e7f8953740f10b2c810a292e89449/contrib/ports/unix/setup-tapif>
- <https://backreference.org/2010/03/26/tuntap-interface-tutorial/>

#### Cleanup Tun/Tap Interface

```bash
sudo ip tuntap del dev tap0 mode tap
sudo ip link del lwipbridge
```

### Run `example_app`

```bash
# Assume the current directory is `build`
cd contrib/ports/unix/example_app
PRECONFIGURED_TAPIF=tap0 ./example_app
```

After starting `example_app`, the expected output should be

```text
Starting lwIP, local interface IP is 192.168.1.200
status_callback==UP, local interface IP is 192.168.1.200
```

Then, open the browser and enter [192.168.1.200](http://192.168.1.200)

## `lwip_preload` Hook Library

### Build `lwip_preload`

By default, we use the raw socket interafce for the low-level communication. To use the tap device interface provided by lwip, please modify [contrib/ports/unix/preload_lib/lwipopts.h](contrib/ports/unix/preload_lib/lwipopts.h) to set `LWIP_RAWIF` to 0.

```bash
cd contrib/ports/unix/preload_lib
mkdir build
cd build
cmake ..
make
```

References about raw socket and its configurations:

- <https://iplab.naist.jp/class/2018/materials/hands-on/layer-2-raw-socket/>
- <https://gist.github.com/austinmarton/1922600>
- <https://gist.github.com/austinmarton/2862515>
- <https://github.com/h1994st/raw-socket-tutorial/blob/master/raw_socket_icmp_ping.c>
- <https://man7.org/linux/man-pages/man7/netdevice.7.html>

### Run Programs

The program will automatically configure MAC and IP addresses, based on the provided interface.

```bash
# use default "eth0" interaface
LD_PRELOAD=liblwip_preload.so <your program>

# use other interface
PRECONFIGURED_RAWIF=<network interafce> LD_PRELOAD=liblwip_preload.so <your program>
```

### Communication between Two Tap Devices

Communication between two tap devices require special configurations. First, two tap devices should be connected using a bridge device. Second, two tap devices should be assigned with IP addresses so that the kernel will handle packets to upper layers accordingly.

Examles: `udp_client` and `udp_server` in [h1994st/SecEthernetDev](https://github.com/h1994st/SecEthernetDev/tree/master/can_udp)

1. Follow [previous steps](#setup-tuntap-interface) to set up ***two*** tap devices

    ```bash
    sudo ip tuntap add dev tap0 mode tap user `whoami`
    sudo ip link set tap0 up
    sudo ip tuntap add dev tap1 mode tap user `whoami`
    sudo ip link set tap1 up
    sudo ip link add lwipbridge type bridge
    sudo ip link set tap0 master lwipbridge
    sudo ip link set tap1 master lwipbridge
    sudo ip addr add 192.168.1.1/24 dev lwipbridge
    sudo ip link set dev lwipbridge up

    # clean up
    sudo ip tuntap del dev tap0 mode tap
    sudo ip tuntap del dev tap1 mode tap
    sudo ip link del lwipbridge
    ```

2. Add IP addresses for two tap devices. This step is important; otherwise, the kernel is not aware of the correct routing of received packets.

    ```bash
    sudo ip addr add 192.168.1.200/24 dev tap0
    sudo ip addr add 192.168.1.201/24 dev tap1
    ```

3. Run `udp_client` and `udp_server`

    ```bash
    # 192.168.1.200
    PRECONFIGURED_TAPIF=tap0 LD_PRELOAD=/path/to/liblwip_preload.so ./udp_server

    # 192.168.1.201
    IS_IP2=1 PRECONFIGURED_TAPIF=tap1 LD_PRELOAD=/path/to/liblwip_preload.so ./udp_client -b /path/to/can_frames.pcap
    ```

## Run `ipsec_app`

```bash
bash test_ipsec.sh
```
