#include "macsec/macsec.h"
#include "macsec/debug.h"


struct orig_fns {
	netif_input_fn orig_input;
	netif_output_fn orig_output;
	netif_linkoutput_fn orig_linkoutput;
};

static struct orig_fns orig_fns_data[256];

static err_t macsec_input(struct pbuf* p, struct netif *inp) {
    struct orig_fns *data = orig_fns_data + inp->num;
    return data->orig_input(p, inp);
}

static err_t macsec_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *addr) {
    struct orig_fns *data = orig_fns_data + netif->num;
    return data->orig_output(netif, p, addr);
}

static err_t macsec_linkoutput(struct netif* netif, struct pbuf* p) {
    struct orig_fns *data = orig_fns_data + netif->num;
    return data->orig_linkoutput(netif, p);
}

void macsecdev_add(struct netif* netif) {
    struct orig_fns* data = orig_fns_data + netif->num;
    int ethr;

    ethr = netif->flags & (NETIF_FLAG_ETHERNET | NETIF_FLAG_ETHARP);

    if (ethr) {
        if (netif->input) {
            data->orig_input = netif->input;
            netif->input = macsec_input;
        }
        if (netif->output) {
            data->orig_output = netif->output;
            netif->output = macsec_output;
        }
        if (netif->linkoutput) {
            data->orig_linkoutput = netif->linkoutput;
            netif->linkoutput = macsec_linkoutput;
        }
    }
}
