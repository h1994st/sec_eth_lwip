#include "macsec/api.h"
#include "macsec/types.h"
#include "macsec/crypto.h"

static void debug_print_hex(char *p, size_t len) {
  size_t i = 0;
  for (i=0; i < len; i++) {
      printf("%02x ", p[i] & 0xff);
  }
  printf("\n");
}

/* This function is only required to prevent arch.h including stdio.h
 * (which it does if LWIP_PLATFORM_ASSERT is undefined)
 */
void lwip_example_app_platform_assert(const char *msg, int line, const char *file) {
  printf("Assertion \"%s\" failed at line %d in %s\n", msg, line, file);
  fflush(NULL);
  abort();
}

int main() {
  u16_t encoded_len, decoded_len;
  char* encoded_packet;
  char* decoded_packet;
  u16_t len = 48;
  unsigned int encrypt_size;
  char packet[48] = {
    0x02, 0x12, 0x34, 0x56, 0x78, 0xff, 0x02, 0x12, 0x34, 0x56, 0x78, 0xab, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0xff, 0x11, 0x38, 0x75, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8,
    0x01, 0x03, 0xc5, 0x68, 0x1f, 0x40, 0x00, 0x0e, 0x74, 0x06, 0x61, 0x61, 0x61, 0x61, 0x61, 0x0a,
  };

  printf("original packet\n");
  debug_print_hex((char*) packet, len);

  encoded_len = macsec_encode_length((void*) packet, len);
  encoded_packet = malloc(encoded_len);
  macsec_encode((void*) packet, len, (void*) encoded_packet, &encoded_len);

  printf("encoded packet\n");
  debug_print_hex(encoded_packet, encoded_len);

  decoded_len = macsec_decode_length((void*) encoded_packet, encoded_len);
  decoded_packet = malloc(decoded_len);
  macsec_decode((void*) encoded_packet, encoded_len, (void*) decoded_packet, &decoded_len);

  printf("decoded packet\n");
  debug_print_hex(decoded_packet, decoded_len);

  free(encoded_packet);
  free(decoded_packet);

  return 0;

  /* why stack overflow here??? */
}
