# lwip for Secure Ethernet

This is a fork of [lwip-tcpip/lwip@7ec4e9b](https://github.com/lwip-tcpip/lwip/blob/7ec4e9be304e7f8953740f10b2c810a292e89449)

## Build `lwip`

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

## Setup Tun/Tap Interface

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

### Cleanup Tun/Tap Interface

```bash
sudo ip tuntap del dev tap0 mode tap
sudo ip link del lwipbridge
```

## Run `example_app`

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
