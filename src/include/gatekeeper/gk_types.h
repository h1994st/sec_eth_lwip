#ifndef LWIP_GK_TYPES_H
#define LWIP_GK_TYPES_H

#include "lwip/opt.h"

#if defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1

#pragma pack(push, 1)
/* #pragma bytealign */

struct gk_proof_hdr {
    uint8_t pkt_hash[32];
    uint8_t proof_hmac[32];
};

#pragma pack(pop)

#endif /* defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1 */

#endif /* LWIP_GK_TYPES_H */
