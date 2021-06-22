#ifndef LWIP_GK_CONFIG_H
#define LWIP_GK_CONFIG_H

#include "lwip/opt.h"

#if defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1

#define GK_SENDER_MAC_LEN (32) /* for HMAC-SHA256 */

#define GK_ETHTYPE_PROOF (0x080A)

#endif /* defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1 */

#endif /* LWIP_GK_CONFIG_H */
