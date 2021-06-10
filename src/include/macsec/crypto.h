#ifndef __MACSEC_CRYPTO_H__
#define __MACSEC_CRYPTO_H__

#include <wolfssl/wolfcrypt/types.h>

byte* get_default_key();
byte* get_default_iv();
word32 macsec_encrypt_len(word32 size);
word32 macsec_decrypt_len(word32 size, byte* output);
int macsec_encrypt(byte* key, byte* iv, byte* input, word32 size, byte* output, word32* output_size);
int macsec_decrypt(byte* key, byte* iv, byte* input, word32 size, byte* output, word32* output_size);

#endif /* __MACSEC_CRYPTO_H__ */
