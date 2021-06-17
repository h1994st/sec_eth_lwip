#ifndef IPSECDEV_H
#define IPSECDEV_H

#include "lwip/opt.h"

#if defined(EIPS) && EIPS == 1

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

#endif /* defined(EIPS) && EIPS == 1 */

#endif /* IPSECDEV_H */
