#ifndef IPSECDEV_H
#define IPSECDEV_H

#include <lwip/netif.h>
#include <lwip/pbuf.h>

#include "ipsec/ipsec.h"
#include "ipsec/debug.h"
#include "ipsec/config.h"

#include <string.h>

struct netif;

err_t ipsecdev_input(struct pbuf* p, struct netif *inp);
err_t ipsecdev_output(struct netif* netif, struct pbuf* p, const ip4_addr_t *ipaddr);
void ipsecdev_add(struct netif* netif);

#endif /* IPSECDEV_H */
