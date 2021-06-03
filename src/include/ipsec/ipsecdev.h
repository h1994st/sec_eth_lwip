#ifndef IPSECDEV_H
#define IPSECDEV_H

#include <lwip/netif.h>
#include <lwip/pbuf.h>

#include "ipsec/ipsec.h"
#include "ipsec/debug.h"
#include "ipsec/config.h"

#include <string.h>

struct netif;

void ipsecdev_add(struct netif* netif);

#endif /* IPSECDEV_H */
