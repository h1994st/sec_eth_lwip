#ifndef IPSEC_CONFIG_H
#define IPSEC_CONFIG_H

#include "lwip/opt.h"
#include "ipsec/sa.h"

#if DUMMY_LOOPBACK_SA_SP
extern sad_entry dummy_loop_sa;
extern spd_entry dummy_loop_sp;
#endif /* DUMMY_LOOPBACK_SA_SP */

extern spd_entry outbound_spd[IPSEC_MAX_SPD_ENTRIES];
extern spd_entry inbound_spd[IPSEC_MAX_SPD_ENTRIES];
extern sad_entry outbound_sad[IPSEC_MAX_SAD_ENTRIES];
extern sad_entry inbound_sad[IPSEC_MAX_SAD_ENTRIES];

db_set_netif* db;

void sa_sp_db_init(void);

#endif  /* IPSEC_CONFIG_H */
