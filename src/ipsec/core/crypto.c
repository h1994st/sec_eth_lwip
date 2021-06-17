#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>

#include "ipsec/crypto.h"
#include "ipsec/config.h"
#include "lwip/mem.h"

static byte default_aes_key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static byte default_aes_iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

static byte default_hmac_key[24] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

int aes_128_gcm_encrypt(byte* key, byte* iv, byte* input, word32 size, byte* output, word32 output_size,
                               byte* auth_in, word32 auth_in_size, byte* auth_tag, word32 auth_tag_size) {
  Aes aes;
  int ret;
  word32 i;

  ret = wc_AesGcmSetKey(&aes, key, AES_BLOCK_SIZE);
  if (ret != 0) {
    return ret;
  }

  ret = wc_AesGcmEncrypt(&aes, output, input, output_size, iv, AES_BLOCK_SIZE, auth_tag, auth_tag_size, auth_in, auth_in_size);
  if (ret != 0) {
    return ret;
  }

  return 0;
}

int aes_128_gcm_decrypt(byte* key, byte* iv, byte* input, word32 size, byte* output, word32 output_size,
                               byte* auth_in, word32 auth_in_size, byte* auth_tag, word32 auth_tag_size) {
  Aes aes;
  int ret;
  word32 i;

  ret = wc_AesGcmSetKey(&aes, key, AES_BLOCK_SIZE);
  if (ret != 0) {
    return ret;
  }

  ret = wc_AesGcmDecrypt(&aes, output, input, size, iv, AES_BLOCK_SIZE, auth_tag, auth_tag_size, auth_in, auth_in_size);
  if (ret != 0) {
    return ret;
  }

  return 0;
}

byte* get_default_aes_key() {
  return default_aes_key;
}

byte* get_default_aes_iv() {
  return default_aes_iv;
}

byte* get_default_hmac_key() {
  return default_hmac_key;
}

int hmac_sha256(byte* key, word32 key_size, byte* input, word32 input_size, byte* output, word32 output_size) {
  Hmac hmac;

  wc_HmacSetKey(&hmac, SHA256, key, key_size);
  wc_HmacUpdate(&hmac, input, input_size);
  wc_HmacFinal(&hmac, output);
}

word32 ipsec_encrypt_len(word32 size) {
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

word32 ipsec_decrypt_len(word32 size, byte* output) {
  word32 length;
  byte padding_len = output[size-1];
  length = size - padding_len;
  return length;
}

word32 ipsec_hash_len() {
  return SHA256_DIGEST_SIZE;
}
