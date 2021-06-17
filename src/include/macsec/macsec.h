#ifndef MACSEC_H
#define MACSEC_H

#include <lwip/netif.h>
#include <lwip/pbuf.h>

#include <string.h>

struct netif;

void macsecdev_add(struct netif* netif);

#endif /* MACSEC_H */
