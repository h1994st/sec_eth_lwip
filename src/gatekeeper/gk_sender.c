#include "lwip/opt.h"

#if defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1

#if defined(LWIP_GK_ROLE) && LWIP_GK_ROLE == 0

#include <string.h>

#include "netif/ethernet.h"
#include "lwip/prot/ethernet.h"

#include "gatekeeper/gk_sender.h"
#include "gatekeeper/gk_crypto.h"

err_t gk_input_impl(struct pbuf* p, struct netif *inp, netif_input_fn input_fn) {
    /* No need to process input packets */
    LWIP_UNUSED_ARG(p);
    LWIP_UNUSED_ARG(inp);
    LWIP_UNUSED_ARG(input_fn);
    return ERR_OK;
}

err_t gk_output_impl(struct pbuf* p) {
    uint8_t *p_payload = (uint8_t *) p->payload;
    struct eth_hdr *eth = (struct eth_hdr *) p_payload;
    uint8_t *p_mac;

    /* check destination address */
    if (!eth_addr_cmp(&eth->dest, &ethbroadcast)) {
        /* skip */
        return ERR_OK;
    }

    /* check EtherType */
    if (lwip_ntohs(eth->type) != ETHTYPE_IP) {
        /* only for IPv4; otherwise, skip*/
        return ERR_OK;
    }

    /* shift buffer */
    eth = (struct eth_hdr *) (p_payload - GK_SENDER_MAC_LEN);
    memmove(eth, p_payload, p->tot_len);
    p_mac = ((uint8_t*)eth) + p->tot_len;

    /* append MAC */
    gk_hmac_sha256((uint8_t*)eth, p->tot_len, p_mac);

    /* update pbuf */
    p->payload = (void*) eth;
    p->tot_len += GK_SENDER_MAC_LEN;
    p->len += GK_SENDER_MAC_LEN;

    return ERR_OK;
}

#endif /* defined(LWIP_GK_ROLE) && LWIP_GK_ROLE == 0 */

#endif /* defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1 */