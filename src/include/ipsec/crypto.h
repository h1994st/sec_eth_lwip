#ifndef __IPSEC_CRYPTO_H__
#define __IPSEC_CRYPTO_H__

#include "lwip/opt.h"

#if defined(EIPS) && EIPS == 1

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

byte* get_default_aes_key(void);
byte* get_default_aes_iv(void);
byte* get_default_hmac_key(void);
word32 ipsec_encrypt_len(word32 size);
word32 ipsec_decrypt_len(word32 size, byte* output);
word32 ipsec_hash_len(void);
int aes_128_gcm_encrypt(byte* key, byte* iv, byte* input, word32 size, byte* output, word32 output_size,
                   byte* auth_in, word32 auth_in_size, byte* auth_tag, word32 auth_tag_size);
int aes_128_gcm_decrypt(byte* key, byte* iv, byte* input, word32 size, byte* output, word32 output_size,
                   byte* auth_in, word32 auth_in_size, byte* auth_tag, word32 auth_tag_size);
int hmac_sha256(byte* key, word32 key_size, byte* input, word32 input_size, byte* output, word32 output_size);

#endif /* defined(EIPS) && EIPS == 1 */

#endif /* __IPSEC_CRYPTO_H__ */
