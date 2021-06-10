#include "macsec/macsec.h"
#include "macsec/debug.h"
#include "macsec/types.h"
#include "macsec/api.h"


struct orig_fns {
	netif_input_fn orig_input;
	netif_output_fn orig_output;
	netif_linkoutput_fn orig_linkoutput;
};

static struct orig_fns orig_fns_data[256];

static err_t macsec_input_check(struct pbuf* p) {
    macsec_header* macsec_hdr;
    macsec_hdr = (macsec_header*) p->payload;

    /* chained pbuf check */
	if(p->next != NULL) {
  		MACSEC_LOG_DBG("macsec_decode_check",
                      MACSEC_STATUS_NOT_IMPLEMENTED,
                      ("can not handle chained pbuf"));
        return MACSEC_STATUS_NOT_IMPLEMENTED;
	}

    /* pbuf reference check */
    if(p->ref != 1) {
  		MACSEC_LOG_DBG("macsec_decode_check",
                      MACSEC_STATUS_NOT_IMPLEMENTED,
                      ("can not handle pbuf->ref != 1 - p->ref == %d", p->ref));
		return MACSEC_STATUS_NOT_IMPLEMENTED;
	}

    /* only works for pbuf.payload allocated in RAM */
    if (!pbuf_match_allocsrc(p, PBUF_RAM)) {
  		MACSEC_LOG_DBG("macsec_decode_check",
                      MACSEC_STATUS_NOT_IMPLEMENTED,
                      ("can not handle pbuf alloc mode other than PBUF_RAM"));
		return MACSEC_STATUS_NOT_IMPLEMENTED;
    }

    /* must be MACsec encoded frame */
    if (macsec_hdr->type != ETH_MACSEC) {
		return MACSEC_STATUS_NOT_IMPLEMENTED;
    }

    return MACSEC_STATUS_SUCCESS;
}

static err_t macsec_output_check(struct pbuf* p) {
    ethernet_header* eth_hdr;
    eth_hdr = (ethernet_header*) p->payload;

    /* chained pbuf check */
	if(p->next != NULL) {
  		MACSEC_LOG_DBG("macsec_encode_check",
                      MACSEC_STATUS_NOT_IMPLEMENTED,
                      ("can not handle chained pbuf"));
        return MACSEC_STATUS_NOT_IMPLEMENTED;
	}

    /* pbuf reference check */
    if(p->ref != 1) {
  		MACSEC_LOG_DBG("macsec_encode_check",
                      MACSEC_STATUS_NOT_IMPLEMENTED,
                      ("can not handle pbuf->ref != 1 - p->ref == %d", p->ref));
		return MACSEC_STATUS_NOT_IMPLEMENTED;
	}

    /* only works for pbuf.payload allocated in RAM */
    if (!pbuf_match_allocsrc(p, PBUF_RAM)) {
  		MACSEC_LOG_DBG("macsec_encode_check",
                      MACSEC_STATUS_NOT_IMPLEMENTED,
                      ("can not handle pbuf alloc mode other than PBUF_RAM"));
		return MACSEC_STATUS_NOT_IMPLEMENTED;
    }

    /* Update: no restriction on eth type */
    /* since our tests all work on IPV4, only process IPV4 */
    /*
    if (eth_hdr->type != ETH_IPV4) {
  		MACSEC_LOG_DBG("macsec_encode_check",
                      MACSEC_STATUS_NOT_IMPLEMENTED,
                      ("can not handle eth type other than ipv4"));
		return MACSEC_STATUS_NOT_IMPLEMENTED;
    }*/

    return MACSEC_STATUS_SUCCESS;
}

static err_t macsec_input_impl(struct pbuf* p) {
    u16_t old_len, new_len;
    void *old_payload, *new_payload;
    err_t err;
    printf("enter macsec decode\n");
    debug_print_pbuf(p);

    /* fetch info from original pbuf */
    old_len = p->tot_len;
    old_payload = p->payload;

    /* calculate the length of MACsec packet */
    new_len = macsec_decode_length(old_payload, old_len);

    /* build the new packet */
    new_payload = mem_malloc(new_len);
    err = macsec_decode(old_payload, old_len, new_payload, &new_len);
    if (err != MACSEC_STATUS_SUCCESS) {
        return err;
    }

    /* replace the packet */
    p->payload = new_payload;
    p->tot_len = new_len;
    p->len = new_len;
    /* TODO: how to free this mem safely?
    mem_free(old_payload);
    */

    printf("leave macsec decode\n");
    debug_print_pbuf(p);
    return MACSEC_STATUS_SUCCESS;
}

static err_t macsec_output_impl(struct pbuf* p) {
    u16_t old_len, new_len;
    void *old_payload, *new_payload, *extended_payload;
    err_t err;
    printf("enter macsec encode\n");
    debug_print_pbuf(p);

    /* fetch info from original pbuf */
    old_len = p->tot_len;
    old_payload = p->payload;

    /* calculate the length of MACsec packet */
    new_len = macsec_encode_length(old_payload, old_len);

    /* build the new packet */
    extended_payload = mem_malloc(new_len);
    memcpy(extended_payload, old_payload, old_len);
    new_payload = mem_malloc(new_len);
    err = macsec_encode(extended_payload, old_len, new_payload, &new_len);
    if (err != MACSEC_STATUS_SUCCESS) {
        return err;
    }

    /* replace the packet */
    p->payload = new_payload;
    p->tot_len = new_len;
    p->len = new_len;
    mem_free(extended_payload);
    /* TODO: how to free this mem safely?
    mem_free(old_payload);
    */

    printf("leave macsec encode\n");
    debug_print_pbuf(p);
    return MACSEC_STATUS_SUCCESS;
}

static err_t macsec_input(struct pbuf* p, struct netif *inp) {
    struct orig_fns *data = orig_fns_data + inp->num;
    err_t err;

    err = macsec_input_check(p);
    if (err != MACSEC_STATUS_SUCCESS) {
        return data->orig_input(p, inp);
    }

    err = macsec_input_impl(p);
    if (err != MACSEC_STATUS_SUCCESS) {
        pbuf_free(p);
        return ERR_CONN;
    }

    return data->orig_input(p, inp);
}

static err_t macsec_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *addr) {
    struct orig_fns *data = orig_fns_data + netif->num;
    return data->orig_output(netif, p, addr);
}

static err_t macsec_linkoutput(struct netif* netif, struct pbuf* p) {
    struct orig_fns *data = orig_fns_data + netif->num;
    err_t err;

    err = macsec_output_check(p);
    if (err != MACSEC_STATUS_SUCCESS) {
        return data->orig_linkoutput(netif, p);
    }

    err = macsec_output_impl(p);
    if (err != MACSEC_STATUS_SUCCESS) {
        pbuf_free(p);
        return ERR_CONN;
    }

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
