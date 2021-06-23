#include "lwip/opt.h"

#if defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "gatekeeper/gk_config.h"
#include "gatekeeper/gk_crypto.h"

#ifdef LWIP_GK_ROLE
#if LWIP_GK_ROLE == 0 /* sender */
static uint8_t hmac_key[GK_SENDER_MAC_LEN] = { 0x00 };
#elif LWIP_GK_ROLE == 1 /* receiver */
static uint8_t hmac_key[GK_SENDER_MAC_LEN] = { 0x01 };
#else
#error "Unsupported LWIP_GK_ROLE"
#endif /* LWIP_GK_ROLE */
#endif /* LWIP_GK_ROLE */
static Hmac gk_hmac;
static Sha256 gk_hash;

int gk_sha256(byte* input, word32 input_size, byte* output) {
    int ret;
    memset(&gk_hash, 0, sizeof(gk_hash));

    ret = wc_InitSha256(&gk_hash);
    if (ret != 0) {
        return ret;
    }

    ret = wc_Sha256Update(&gk_hash, input, input_size);
    if (ret != 0) {
        return ret;
    }

    ret = wc_Sha256Final(&gk_hash, output);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

int gk_hmac_sha256(byte* input, word32 input_size, byte* output) {
    int ret;
    memset(&gk_hmac, 0, sizeof(gk_hmac));

    ret = wc_HmacInit(&gk_hmac, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }

    ret = wc_HmacSetKey(&gk_hmac, WC_SHA256, hmac_key, GK_SENDER_MAC_LEN);
    if (ret != 0) {
        return ret;
    }

    ret = wc_HmacUpdate(&gk_hmac, input, input_size);
    if (ret != 0) {
        return ret;
    }

    ret = wc_HmacFinal(&gk_hmac, output);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

#endif /* defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1 */
