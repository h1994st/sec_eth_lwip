#ifndef __MACSEC_CONFIG_H__
#define __MACSEC_CONFIG_H__

#include "lwip/opt.h"

#if defined(MACSEC) && MACSEC == 1

#include "macsec/types.h"

#define MAC_LEN 6
#define PROTO_ID_LEN 2

#define ETHERNET_HEADER_LEN 14 /* 12 bytes MAC addresses + 2 bytes EtherType */

#define MACSEC_HEADER_LEN 28 /* 12 bytes MAC addresses + 16 bytes SecTag */
#define MACSEC_SECTAG_LEN 16
#define MACSEC_ICV_LEN 16 /* at the end of Ethernet frame */

/* additional size, comparing with Ethernet frame */
#define MACSEC_MAX_HLEN (MACSEC_SECTAG_LEN + MACSEC_ICV_LEN - PROTO_ID_LEN)

#define MACSEC_CIPHER_SUITE AES_128_GCM

#endif /* defined(MACSEC) && MACSEC == 1 */

#endif /* __MACSEC_CONFIG_H__ */
