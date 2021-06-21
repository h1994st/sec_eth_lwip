#ifndef MACSEC_H
#define MACSEC_H

#include "lwip/opt.h"

#if defined(MACSEC) && MACSEC == 1

#include "lwip/netif.h"
#include "lwip/pbuf.h"

void macsecdev_add(struct netif* netif);

#endif /* defined(MACSEC) && MACSEC == 1 */

#endif /* MACSEC_H */
