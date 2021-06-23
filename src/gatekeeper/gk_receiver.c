#include "lwip/opt.h"

#if defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1

#if defined(LWIP_GK_ROLE) && LWIP_GK_ROLE == 1

#include <string.h>

#include "netif/list.h"
#include "netif/ethernet.h"
#include "lwip/prot/ethernet.h"
#include "lwip/prot/ip.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/udp.h"

#include "gatekeeper/gk_receiver.h"
#include "gatekeeper/gk_crypto.h"

/* a temporary place to store hash/MAC data */
static uint8_t data[32] = { 0 };
static struct list pbuf_list = { NULL, NULL, 100, 0 };

struct gk_pbuf_entry {
    uint8_t pkt_hash[32];
    struct pbuf *p;
};

/* do not handle the proof packet to upper layer */
static err_t handle_proof_packets(struct pbuf* p, struct netif *inp, netif_input_fn input_fn) {
    uint8_t *p_payload = (uint8_t *) p->payload;
    struct gk_proof_hdr *proof_hdr = (struct gk_proof_hdr *)(p_payload + PBUF_LINK_HLEN);
    struct pbuf *old_pbuf;
    struct gk_pbuf_entry *pbuf_entry;
    struct elem *e;

    printf("received proof packet!\n");

    /* retrieve the stored pbuf */
    /* proof_hdr->pkt_hash */
    old_pbuf = NULL;
    pbuf_entry = NULL;
    for (e = pbuf_list.first; e != NULL; e = e->next) {
        pbuf_entry = (struct gk_pbuf_entry*)e->data;
        if (memcmp(proof_hdr->pkt_hash, pbuf_entry->pkt_hash, 32) == 0) {
            /* found! */
            old_pbuf = pbuf_entry->p;
            break;
        }
    }
    if (old_pbuf == NULL) {
        /* not found */
        printf("drop the proof packet, as no corresponding packet exists!\n");
        return ERR_CONN;
    }

    if (gk_hmac_sha256((uint8_t*)old_pbuf->payload, old_pbuf->tot_len, data) != 0) {
        /* hmac error */
        printf("gk_hmac_sha256 failed\n");
        return ERR_BUF;
    }

    if (memcmp(data, proof_hdr->proof_hmac, 32) != 0) {
        /* wrong proof */
        printf("wrong MAC\n");
        return ERR_CONN;
    }

    /* remove the old pbuf */
    list_remove(&pbuf_list, pbuf_entry);
    mem_free(pbuf_entry);

    /* delivery the packet to the upper layer */
    printf("processing stored packet!\n");
    input_fn(old_pbuf, inp);
    /* TODO: do we need to free `old_pbuf` here? */

    return -101;
}

err_t gk_input_impl(struct pbuf* p, struct netif *inp, netif_input_fn input_fn) {
    uint8_t *p_payload = (uint8_t *) p->payload;
    struct eth_hdr *eth = (struct eth_hdr *) p_payload;
    struct ip_hdr *iph;
    struct udp_hdr *udph;
    uint8_t *p_end;
    uint16_t eth_type;
    struct gk_pbuf_entry* pbuf_entry;

    /* check destination address */
    if (!eth_addr_cmp(&eth->dest, &ethbroadcast)) {
        /* skip */
        return ERR_OK;
    }

    eth_type = lwip_ntohs(eth->type);
    if (eth_type == ETHTYPE_IP) {
        iph = (struct ip_hdr *)(p_payload + PBUF_LINK_HLEN);
        if (iph->_proto == IP_PROTO_UDP) {
            udph = (struct udp_hdr *)(p_payload + PBUF_LINK_HLEN + PBUF_IP_HLEN);
            p_end = ((uint8_t*)udph) + ntohs(udph->len);

            /* calculate hash */
            if (gk_sha256(p_payload, p_end - p_payload, data) != 0) {
                /* hash error */
                printf("gk_sha256 failed\n");
                return ERR_BUF;
            }

            /* store the packet */
            pbuf_entry = (struct gk_pbuf_entry*)mem_calloc(1, sizeof(struct gk_pbuf_entry));
            if (!pbuf_entry) {
                /* allocation error */
                printf("mem_calloc failed\n");
                return ERR_MEM;
            }
            memcpy(pbuf_entry->pkt_hash, data, 32);
            pbuf_entry->p = p;
            list_push(&pbuf_list, pbuf_entry);
            printf("stored the received packet!\n");

            return -100; /* stored */
        }
    } else if (eth_type == GK_ETHTYPE_PROOF) {
        return handle_proof_packets(p, inp, input_fn);
    }

    return ERR_OK;
}

err_t gk_output_impl(struct pbuf* p) {
    /* No need to process output packets */
    LWIP_UNUSED_ARG(p);
    return ERR_OK;
}

#endif /* defined(LWIP_GK_ROLE) && LWIP_GK_ROLE == 1 */

#endif /* defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1 */
