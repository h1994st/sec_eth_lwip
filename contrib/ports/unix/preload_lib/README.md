# lwip Hook Library

This library can be loaded from `LD_PRELOAD` to hook socket APIs

```bash
# IP: 192.168.1.200
PRECONFIGURED_TAPIF=tap0 LD_PRELOAD=liblwip_preload.so <your program>

# IP: 192.168.1.201
# need to add tap1
IS_IP2=1 PRECONFIGURED_TAPIF=tap1 LD_PRELOAD=liblwip_preload.so <your program>
```
