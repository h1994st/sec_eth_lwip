#include "lwip/opt.h"

#if defined(MACSEC) && MACSEC == 1

#include "macsec/api.h"
#include "macsec/types.h"
#include "macsec/config.h"
#include "macsec/crypto.h"

static u32_t PN = 0;

u16_t macsec_decode_length(void *payload, u16_t len) {
  u16_t userdata_len, decoded_userdata_len;

  LWIP_UNUSED_ARG(payload);

  userdata_len = len - MAC_LEN * 2 - MACSEC_SECTAG_LEN - MACSEC_ICV_LEN;
  /* though the real user data is shorter than the encrypted data,
     we do not know the exact length before decryption */
  decoded_userdata_len = userdata_len;
  return MAC_LEN * 2 + decoded_userdata_len;
}

u16_t macsec_encode_length(void *payload, u16_t len) {
  u16_t userdata_len, encoded_userdata_len;

  LWIP_UNUSED_ARG(payload);

  userdata_len = len - MAC_LEN * 2;
  encoded_userdata_len = macsec_encrypt_len(userdata_len);
  return MACSEC_HEADER_LEN + encoded_userdata_len + MACSEC_ICV_LEN;
}

err_t macsec_decode(void *old_payload, const u16_t old_len, u16_t *new_len) {
  ethernet_header *eth_hdr;
  macsec_header *macsec_hdr;
  unsigned int old_data_length, new_data_length;
  int err;
  u8_t *icv;
  u8_t *data;

  /* shift buffer */
  /* shift MAC addresses */
  eth_hdr = (ethernet_header*) ((u8_t*)old_payload) + MACSEC_SECTAG_LEN; /* skip SecTag */
  macsec_hdr = (macsec_header*) old_payload;
  memmove(eth_hdr, macsec_hdr, 2 * MAC_LEN);
  data = ((u8_t*)old_payload) + MACSEC_HEADER_LEN;
  icv = ((u8_t*)old_payload) + old_len - MACSEC_ICV_LEN;

  /* decrypt secure data */
  old_data_length = old_len - MACSEC_HEADER_LEN - MACSEC_ICV_LEN;
  err = macsec_decrypt(get_default_key(), get_default_iv(), data, old_data_length, data, &new_data_length,
                       (byte*)macsec_hdr, MACSEC_HEADER_LEN, icv, MACSEC_ICV_LEN);
  if (err != 0) {
    return MACSEC_STATUS_FAILURE;
  }
  /* update new_len */
  *new_len = old_len - MACSEC_SECTAG_LEN - MACSEC_ICV_LEN;

  return MACSEC_STATUS_SUCCESS;
}

err_t macsec_encode(void *old_payload, const u16_t old_len, u16_t *new_len) {
  ethernet_header *eth_hdr;
  macsec_header *macsec_hdr;
  unsigned int old_data_length, new_data_length;
  char *icv;
  char *data;
  int err;

  /* shift buffer */
  /* shift MAC addresses */
  eth_hdr = (ethernet_header*) old_payload;
  macsec_hdr = (macsec_header*) (((char*)old_payload) - MACSEC_SECTAG_LEN - MACSEC_ICV_LEN); /* shift 32 bytes */
  memmove(macsec_hdr, eth_hdr, 2 * MAC_LEN);
  /* shift EtherType + data payload */
  data = ((char*)macsec_hdr) + MACSEC_HEADER_LEN;
  memmove(data, ((char*)old_payload) + 2 * MAC_LEN, old_len - 2 * MAC_LEN);
  icv = ((char*)macsec_hdr) + old_len + MACSEC_SECTAG_LEN;

  /* fixed ether type */
  macsec_hdr->type = ETH_MACSEC;

  /* TODO: in the current version just ignore the flags */
  macsec_hdr->flags = 0;

  /* increasing packet number */
  macsec_hdr->pn = PN;
  PN += 1;

  /* SCI is set to src mac addr and port id */
  memcpy(macsec_hdr->sci, macsec_hdr->src, MAC_LEN);
  macsec_hdr->sci[6] = 0x00;
  macsec_hdr->sci[7] = 0x01;

  /* compute the secure data */
  old_data_length = old_len - MAC_LEN * 2;
  err = macsec_encrypt(get_default_key(), get_default_iv(), (byte*)data, old_data_length, (byte*)data, &new_data_length,
                       (byte*)macsec_hdr, MACSEC_HEADER_LEN, (byte*)icv, MACSEC_ICV_LEN);
  if (err != 0) {
    return MACSEC_STATUS_FAILURE;
  }
  /* update new_len if necessary */
  *new_len = old_len + MACSEC_SECTAG_LEN + MACSEC_ICV_LEN;

  return MACSEC_STATUS_SUCCESS;
}

#endif /* defined(MACSEC) && MACSEC == 1 */
