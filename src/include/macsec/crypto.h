#ifndef __MACSEC_CRYPTO_H__
#define __MACSEC_CRYPTO_H__

#include "lwip/opt.h"

#if defined(MACSEC) && MACSEC == 1

#include <wolfssl/wolfcrypt/types.h>

byte* get_default_key(void);
byte* get_default_iv(void);
word32 macsec_encrypt_len(word32 size);
word32 macsec_decrypt_len(word32 size, byte* output);
int macsec_encrypt(byte* key, byte* iv, byte* input, word32 size, byte* output, word32 *output_size,
                   byte* auth_in, word32 auth_in_size, byte* auth_tag, word32 auth_tag_size);
int macsec_decrypt(byte* key, byte* iv, byte* input, word32 size, byte* output, word32 *output_size,
                   byte* auth_in, word32 auth_in_size, byte* auth_tag, word32 auth_tag_size);

#endif /* defined(MACSEC) && MACSEC == 1 */

#endif /* __MACSEC_CRYPTO_H__ */
