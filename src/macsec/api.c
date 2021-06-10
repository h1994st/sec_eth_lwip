#include "macsec/api.h"
#include "macsec/types.h"
#include "macsec/config.h"


static u32_t PN = 0;

u16_t macsec_decode_length(void *payload, u16_t len) {
  u16_t userdata_len, decoded_userdata_len;

  userdata_len = len - MAC_LEN * 2 - MACSEC_SECTAG_LEN - MACSEC_ICV_LEN;
  decoded_userdata_len = userdata_len;
  return MAC_LEN * 2 + decoded_userdata_len;
}

u16_t macsec_encode_length(void *payload, u16_t len) {
  u16_t userdata_len, encoded_userdata_len;

  userdata_len = len - MAC_LEN * 2;
  encoded_userdata_len = userdata_len;
  return MAC_LEN * 2 + MACSEC_SECTAG_LEN + encoded_userdata_len + MACSEC_ICV_LEN;
}

err_t macsec_decode(void *old_payload, const u16_t old_len, void *new_payload, const u16_t new_len) {
  return MACSEC_STATUS_SUCCESS;
}

err_t macsec_encode(void *old_payload, const u16_t old_len, void *new_payload, const u16_t new_len) {
  macsec_header *macsec_hdr;
  unsigned int i;

  macsec_hdr = (macsec_header*) new_payload;

  /* dest and src are the same */
  memcpy(new_payload, old_payload, MAC_LEN * 2);

  /* fixed ether type */
  macsec_hdr->type = ETH_MACSEC;

  /* TODO: currently just ignore the flags */
  macsec_hdr->flags = 0;

  /* increasing packet number */
  macsec_hdr->pn = PN;
  PN += 1;

  /* SCI is set to src mac addr and port id */
  for (i = 0; i < 6; i++) {
    macsec_hdr->sci[i] = macsec_hdr->src[i];
  }
  macsec_hdr->sci[7] = 0x00;
  macsec_hdr->sci[8] = 0x01;

  /* compute the secure data */

  return MACSEC_STATUS_SUCCESS;
}
