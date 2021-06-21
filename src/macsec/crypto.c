#include "lwip/opt.h"

#if defined(MACSEC) && MACSEC == 1

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>

#include "macsec/crypto.h"
#include "macsec/config.h"
#include "lwip/mem.h"

static byte default_key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static byte default_iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

static int aes_128_cbc_encrypt(byte* key, byte* iv, byte* input, word32 size, byte* output, word32* output_size) {
  Aes aes;
  int ret;
  word32 i;

  ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
  if (ret != 0) {
    return ret;
  }

  *output_size = macsec_encrypt_len(size);
  for (i = size; i < *output_size; i++) {
      /* pads the added characters with the number of pads */
      input[i] = (*output_size - size);
  }

  ret = wc_AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
  if (ret != 0) {
    return ret;
  }

  ret = wc_AesCbcEncrypt(&aes, output, input, *output_size);
  if (ret != 0) {
    return ret;
  }

  return 0;
}

static int aes_128_cbc_decrypt(byte* key, byte* iv, byte* input, word32 size, byte* output, word32* output_size) {
  Aes aes;
  int ret;
  word32 i;

  ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
  if (ret != 0) {
    return ret;
  }

  ret = wc_AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION);
  if (ret != 0) {
    return ret;
  }

  ret = wc_AesCbcDecrypt(&aes, output, input, size);
  if (ret != 0) {
    return ret;
  }

  *output_size = macsec_decrypt_len(size, output);
  for (i = *output_size; i < size; i++) {
    output[i] = 0;
  }

  return 0;
}

static int aes_128_gcm_encrypt(byte* key, byte* iv, byte* input, word32 size, byte* output, word32* output_size,
                               byte* auth_in, word32 auth_in_size, byte* auth_tag, word32 auth_tag_size) {
  Aes aes;
  int ret;

  ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
  if (ret != 0) {
    return ret;
  }

  *output_size = size;

  ret = wc_AesGcmSetKey(&aes, key, AES_BLOCK_SIZE);
  if (ret != 0) {
    return ret;
  }

  ret = wc_AesGcmEncrypt(&aes, output, input, size, iv, AES_BLOCK_SIZE, auth_tag, auth_tag_size, auth_in, auth_in_size);
  if (ret != 0) {
    return ret;
  }

  return 0;
}

static int aes_128_gcm_decrypt(byte* key, byte* iv, byte* input, word32 size, byte* output, word32* output_size,
                               byte* auth_in, word32 auth_in_size, byte* auth_tag, word32 auth_tag_size) {
  Aes aes;
  int ret;

  ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
  if (ret != 0) {
    return ret;
  }

  ret = wc_AesGcmSetKey(&aes, key, AES_BLOCK_SIZE);
  if (ret != 0) {
    return ret;
  }

  ret = wc_AesGcmDecrypt(&aes, output, input, size, iv, AES_BLOCK_SIZE, auth_tag, auth_tag_size, auth_in, auth_in_size);
  if (ret != 0) {
    return ret;
  }

  *output_size = size;

  return 0;
}

byte* get_default_key(void) {
  return default_key;
}

byte* get_default_iv(void) {
  return default_iv;
}

word32 macsec_encrypt_len(word32 size) {
  int padCounter = 0;
  word32 tmp_len;

  tmp_len = size;

  /* pads the length until it evenly matches a block / increaess pad number*/
  while (tmp_len % AES_BLOCK_SIZE != 0 || padCounter == 0) {
      tmp_len++;
      padCounter++;
  }

  return tmp_len;
}

word32 macsec_decrypt_len(word32 size, byte* output) {
  word32 length;
  byte padding_len = output[size-1];
  length = size - padding_len;
  return length;
}

int macsec_encrypt(byte* key, byte* iv, byte* input, word32 size, byte* output, word32 *output_size,
                   byte* auth_in, word32 auth_in_size, byte* auth_tag, word32 auth_tag_size) {
  if (MACSEC_CIPHER_SUITE == AES_128_CBC) {
    return aes_128_cbc_encrypt(key, iv, input, size, output, output_size);
  } else if (MACSEC_CIPHER_SUITE == AES_128_GCM) {
    return aes_128_gcm_encrypt(key, iv, input, size, output, output_size,
                               auth_in, auth_in_size, auth_tag, auth_tag_size);
  } else {
    return -1;
  }
}

int macsec_decrypt(byte* key, byte* iv, byte* input, word32 size, byte* output, word32 *output_size,
                   byte* auth_in, word32 auth_in_size, byte* auth_tag, word32 auth_tag_size) {
  if (MACSEC_CIPHER_SUITE == AES_128_CBC) {
    return aes_128_cbc_decrypt(key, iv, input, size, output, output_size);
  } else if (MACSEC_CIPHER_SUITE == AES_128_GCM) {
    return aes_128_gcm_decrypt(key, iv, input, size, output, output_size,
                               auth_in, auth_in_size, auth_tag, auth_tag_size);
  } else {
    return -1;
  }
}

#endif /* defined(MACSEC) && MACSEC == 1 */
