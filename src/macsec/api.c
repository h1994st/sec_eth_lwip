#include "macsec/api.h"
#include "macsec/types.h"
#include "macsec/config.h"
#include "macsec/crypto.h"

static u32_t PN = 0;

u16_t macsec_decode_length(void *payload, u16_t len) {
  u16_t userdata_len, decoded_userdata_len;

  userdata_len = len - MAC_LEN * 2 - MACSEC_SECTAG_LEN - MACSEC_ICV_LEN;
  /* though the real user data is shorter than the encrypted data,
     we do not know the exact length before decryption */
  decoded_userdata_len = userdata_len;
  return MAC_LEN * 2 + decoded_userdata_len;
}

u16_t macsec_encode_length(void *payload, u16_t len) {
  u16_t userdata_len, encoded_userdata_len;

  userdata_len = len - MAC_LEN * 2;
  encoded_userdata_len = macsec_encrypt_len(userdata_len);
  return MACSEC_HEADER_LEN + encoded_userdata_len + MACSEC_ICV_LEN;
}

err_t macsec_decode(void *old_payload, const u16_t old_len, void *new_payload, u16_t *new_len) {
  ethernet_header *eth_hdr;
  macsec_header *macsec_hdr;
  unsigned int i, old_data_length, new_data_length;
  int err;

  eth_hdr = (ethernet_header*) new_payload;
  macsec_hdr = (macsec_header*) old_payload;

  /* dest and src are the same */
  memcpy(eth_hdr->dest, macsec_hdr->dest, MAC_LEN);
  memcpy(eth_hdr->src, macsec_hdr->src, MAC_LEN);

  /* decrypt secure data */
  old_data_length = old_len - MACSEC_HEADER_LEN - MACSEC_ICV_LEN;
  err = macsec_decrypt(get_default_key(), get_default_iv(), old_payload + MACSEC_HEADER_LEN, old_data_length, new_payload + MAC_LEN * 2, &new_data_length,
                       old_payload, MAC_LEN * 2, old_payload + MACSEC_HEADER_LEN + old_data_length, MACSEC_ICV_LEN);
  if (err != 0) {
    return MACSEC_STATUS_FAILURE;
  }
  /* update new_len */
  *new_len = MAC_LEN * 2 + new_data_length;

  return MACSEC_STATUS_SUCCESS;
}

err_t macsec_encode(void *old_payload, const u16_t old_len, void *new_payload, u16_t *new_len) {
  ethernet_header *eth_hdr;
  macsec_header *macsec_hdr;
  unsigned int i, old_data_length, new_data_length;
  int err;

  eth_hdr = (ethernet_header*) old_payload;
  macsec_hdr = (macsec_header*) new_payload;

  /* dest and src are the same */
  memcpy(macsec_hdr->dest, eth_hdr->dest, MAC_LEN);
  memcpy(macsec_hdr->src, eth_hdr->src, MAC_LEN);

  /* fixed ether type */
  macsec_hdr->type = ETH_MACSEC;

  /* TODO: in the current version just ignore the flags */
  macsec_hdr->flags = 0;

  /* increasing packet number */
  macsec_hdr->pn = PN;
  PN += 1;

  /* SCI is set to src mac addr and port id */
  memcpy(macsec_hdr->sci, eth_hdr->src, MAC_LEN);
  macsec_hdr->sci[6] = 0x00;
  macsec_hdr->sci[7] = 0x01;

  /* compute the secure data */
  old_data_length = old_len - MAC_LEN * 2;
  err = macsec_encrypt(get_default_key(), get_default_iv(), old_payload + MAC_LEN * 2, old_data_length, new_payload + MACSEC_HEADER_LEN, &new_data_length,
                       old_payload, MAC_LEN * 2, new_payload + MACSEC_HEADER_LEN + macsec_encrypt_len(old_data_length), MACSEC_ICV_LEN);
  if (err != 0) {
    return MACSEC_STATUS_FAILURE;
  }
  /* update new_len if necessary */
  *new_len = MACSEC_HEADER_LEN + new_data_length + MACSEC_ICV_LEN;

  return MACSEC_STATUS_SUCCESS;
}
