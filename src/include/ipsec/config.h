#ifndef IPSEC_CONFIG_H
#define IPSEC_CONFIG_H

#include "lwip/opt.h"

#if defined(EIPS) && EIPS == 1

#include "ipsec/sa.h"

#if defined(DUMMY_LOOPBACK_SA_SP) && DUMMY_LOOPBACK_SA_SP == 1
extern sad_entry dummy_loop_sa;
extern spd_entry dummy_loop_sp;
#endif /* defined(DUMMY_LOOPBACK_SA_SP) && DUMMY_LOOPBACK_SA_SP == 1 */

extern spd_entry outbound_spd[IPSEC_MAX_SPD_ENTRIES];
extern spd_entry inbound_spd[IPSEC_MAX_SPD_ENTRIES];
extern sad_entry outbound_sad[IPSEC_MAX_SAD_ENTRIES];
extern sad_entry inbound_sad[IPSEC_MAX_SAD_ENTRIES];

db_set_netif* db;

void sa_sp_db_init(void);

#endif /* defined(EIPS) && EIPS == 1 */

#endif  /* IPSEC_CONFIG_H */
