#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>

#include "macsec/crypto.h"
#include "macsec/config.h"

static byte default_key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static byte default_iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};


static void debug_print_hex(char *p, size_t len) {
  size_t i = 0;
  for (i=0; i < len; i++) {
      printf("%02x ", p[i] & 0xff);
  }
  printf("\n");
}

static int ase_128_cbc_encrypt(byte* key, byte* iv, word32 size, byte* input, byte* output) {
  Aes aes;
  int ret;
  word32 full_size, i;

  full_size = macsec_encrypt_len(size, AES_BLOCK_SIZE);
  for (i = size; i < full_size; i++) {
      /* pads the added characters with the number of pads */
      input[i] = (full_size - size);
  }

  ret = wc_AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
  if (ret != 0) {
    return ret;
  }

  ret = wc_AesCbcEncrypt(&aes, output, input, full_size);
  if (ret != 0) {
    return ret;
  }

  return 0;
}

static int ase_128_cbc_decrypt(byte* key, byte* iv, word32 size, byte* input, byte* output) {
  Aes aes;
  int ret;
  word32 ori_size, i;

  ret = wc_AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION);
  if (ret != 0) {
    return ret;
  }

  ret = wc_AesCbcDecrypt(&aes, output, input, size);
  if (ret != 0) {
    return ret;
  }

  ori_size = macsec_decrypt_len(size, output);
  for (i = ori_size; i < size; i++) {
    output[i] = 0;
  }

  return 0;
}

byte* get_default_key() {
  return default_key;
}

byte* get_default_iv() {
  return default_iv;
}

word32 macsec_encrypt_len(word32 size, word32 block_size) {
  int padCounter = 0;
  word32 tmp_len;

  tmp_len = size;

  /* pads the length until it evenly matches a block / increases pad number*/
  while (tmp_len % block_size != 0 || padCounter == 0) {
      tmp_len++;
      padCounter++;
  }

  return tmp_len;
}

word32 macsec_decrypt_len(word32 size, byte* output) {
  word32 length;
  length = size - output[size-1];
  return length;
}

int macsec_encrypt(byte* key, byte* iv, word32 size, byte* input, byte* output) {
  if (MACSEC_CIPHER_SUITE == AES_128_CBC) {
    return ase_128_cbc_encrypt(key, iv, size, input, output);
  } else {
    return -1;
  }
}

int macsec_decrypt(byte* key, byte* iv, word32 size, byte* input, byte* output) {
  if (MACSEC_CIPHER_SUITE == AES_128_CBC) {
    return ase_128_cbc_decrypt(key, iv, size, input, output);
  } else {
    return -1;
  }
}
