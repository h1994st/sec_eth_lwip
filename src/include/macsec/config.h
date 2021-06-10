#ifndef __MACSEC_CONFIG_H__
#define __MACSEC_CONFIG_H__

#include "macsec/types.h"

#define MAC_LEN 6
#define PROTO_ID_LEN 2

#define ETHERNET_HEADER_LEN 14

#define MACSEC_HEADER_LEN 28
#define MACSEC_SECTAG_LEN 16
#define MACSEC_ICV_LEN 16

#define MACSEC_CIPHER_SUITE AES_128_CBC

#endif /* __MACSEC_CONFIG_H__ */
