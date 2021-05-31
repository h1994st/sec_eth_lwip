# lwip Hook Library

This library can be loaded from `LD_PRELOAD` to hook socket APIs

```bash
PRECONFIGURED_TAPIF=tap0 LD_PRELOAD=liblwip_preload.so <your program>
```
