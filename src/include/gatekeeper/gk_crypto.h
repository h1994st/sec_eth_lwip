#ifndef LWIP_GK_CRYPTO_H
#define LWIP_GK_CRYPTO_H

#include "lwip/opt.h"

#if defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

int gk_sha256(byte* input, word32 input_size, byte* output);
int gk_hmac_sha256(byte* input, word32 input_size, byte* output);

#endif /* defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1 */

#endif /* LWIP_GK_CRYPTO_H */
