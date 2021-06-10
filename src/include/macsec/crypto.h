#ifndef __MACSEC_CRYPTO_H__
#define __MACSEC_CRYPTO_H__

#include <wolfssl/wolfcrypt/types.h>

byte* get_default_key();
byte* get_default_iv();
word32 macsec_encrypt_len(word32 size, word32 block_size);
word32 macsec_decrypt_len(word32 size, byte* output);
int macsec_encrypt(byte* key, byte* iv, word32 size, byte* input, byte* output);
int macsec_decrypt(byte* key, byte* iv, word32 size, byte* input, byte* output);

#endif /* __MACSEC_CRYPTO_H__ */
