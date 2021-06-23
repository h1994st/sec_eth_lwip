/*
 * Provide an interface using raw socket
 */

#ifndef LWIP_RAWIF_H
#define LWIP_RAWIF_H

#include "lwip/netif.h"

err_t rawif_init(struct netif *netif);
void rawif_poll(struct netif *netif);
#if NO_SYS
int rawif_select(struct netif *netif);
#endif /* NO_SYS */

#endif /* LWIP_RAWIF_H */
