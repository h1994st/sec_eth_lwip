#ifndef LWIP_GK_SENDER_H
#define LWIP_GK_SENDER_H

#include "lwip/opt.h"

#if defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1

#if defined(LWIP_GK_ROLE) && LWIP_GK_ROLE == 0

#include "gatekeeper/gatekeeper.h"

#endif /* defined(LWIP_GK_ROLE) && LWIP_GK_ROLE == 0 */

#endif /* defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1 */

#endif /* LWIP_GK_SENDER_H */
