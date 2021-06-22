#ifndef LWIP_GATEKEEPER_H
#define LWIP_GATEKEEPER_H

#include "lwip/opt.h"

#if defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1

#include <lwip/netif.h>
#include <lwip/pbuf.h>

#include "gatekeeper/gk_config.h"
#include "gatekeeper/gk_types.h"

err_t gk_input_impl(struct pbuf* p, struct netif *inp, netif_input_fn input_fn);
err_t gk_output_impl(struct pbuf* p);

void gkdev_add(struct netif* netif);

#endif /* defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1 */

#endif /* LWIP_GATEKEEPER_H */
