#include "lwip/opt.h"

#if defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1

#include "gatekeeper/gatekeeper.h"

struct orig_fns {
	netif_input_fn orig_input;
	netif_output_fn orig_output;
	netif_linkoutput_fn orig_linkoutput;
};

static struct orig_fns orig_fns_data[256];

static err_t gk_input(struct pbuf* p, struct netif *inp) {
    struct orig_fns *data = orig_fns_data + inp->num;
    err_t err;

    err = gk_input_impl(p, inp, data->orig_input);
    if (err == -100) {
        /* packet will be processed later */
        return ERR_OK;
    }
    if (err == -101) {
        /* consumed by gatekeeper */
        pbuf_free(p);
        return ERR_OK;
    }
    if (err != ERR_OK) {
        pbuf_free(p);
        return ERR_CONN;
    }

    return data->orig_input(p, inp);
}

static err_t gk_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *addr) {
    struct orig_fns *data = orig_fns_data + netif->num;
    return data->orig_output(netif, p, addr);
}

static err_t gk_linkoutput(struct netif* netif, struct pbuf* p) {
    struct orig_fns *data = orig_fns_data + netif->num;
    err_t err;

    err = gk_output_impl(p);
    if (err != ERR_OK) {
        pbuf_free(p);
        return ERR_CONN;
    }

    return data->orig_linkoutput(netif, p);
}

void gkdev_add(struct netif* netif) {
    struct orig_fns* data = orig_fns_data + netif->num;
    int ethr;

    ethr = netif->flags & (NETIF_FLAG_ETHERNET | NETIF_FLAG_ETHARP);

    if (ethr) {
        if (netif->input) {
            data->orig_input = netif->input;
            netif->input = gk_input;
        }
        if (netif->output) {
            data->orig_output = netif->output;
            netif->output = gk_output;
        }
        if (netif->linkoutput) {
            data->orig_linkoutput = netif->linkoutput;
            netif->linkoutput = gk_linkoutput;
        }
    }
}

#endif /* defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1 */
