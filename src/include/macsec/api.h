#ifndef __MACSEC_API_H__
#define __MACSEC_API_H__

#include "lwip/err.h"
#include "macsec/types.h"

u16_t macsec_decode_length(void *payload, u16_t len);
u16_t macsec_encode_length(void *payload, u16_t len);
err_t macsec_decode(void *old_payload, const u16_t old_len, void *new_payload, const u16_t new_len);
err_t macsec_encode(void *old_payload, const u16_t old_len, void *new_payload, const u16_t new_len);

#endif /* __MACSEC_API_H__ */
