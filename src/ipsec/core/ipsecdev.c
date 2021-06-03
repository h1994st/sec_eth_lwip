#include "ipsec/ipsecdev.h"


struct orig_fns {
	netif_input_fn orig_input;
	netif_output_fn orig_output;
	netif_linkoutput_fn orig_linkoutput;
};

static struct orig_fns orig_fns_data[256];

static err_t ipsecdev_input(struct pbuf* p, struct netif *inp) {
    struct orig_fns *data = orig_fns_data + inp->num;
    ipsec_ip_header* pkt;
    int ofs = 0;
    int len = 0;
    int retcode = IPSEC_STATUS_NOT_INITIALIZED;
    spd_entry* spd;

    printf("Inside IPSecdev INPUT\n");

    /* check packet has data */
    if (p == NULL || p->payload == NULL) {
            IPSEC_LOG_DBG("ipsecdev_input",
                          IPSEC_STATUS_DATA_SIZE_ERROR,
                          ("Packet has no payload. Can't pass it to higher level protocol stacks."));
            pbuf_free(p);
    } else {
        pkt = (ipsec_ip_header*)p->payload;
        /* cannot handle chained pbufs */
        if (p->next != NULL) {
            IPSEC_LOG_DBG("ipsecdev_input",
                          IPSEC_STATUS_DATA_SIZE_ERROR,
                          ("can not handle chained pbuf - (packet must be < %d bytes )",
                          PBUF_POOL_BUFSIZE - PBUF_LINK_HLEN - PBUF_IPSEC_HLEN));
            /* in case of error, free pbuf and return ERR_OK as lwIP does */
            pbuf_free(p);
            return ERR_OK;
        }

        /* subject to IPSec processing? */
        if (pkt->protocol == IPSEC_PROTO_ESP || pkt->protocol == IPSEC_PROTO_AH) {
            retcode = ipsec_input_impl((__u8*)pkt, p->len, &ofs, &len, db);

            if (retcode == IPSEC_STATUS_SUCCESS) {
                if (pbuf_remove_header(p, p->len - len) != 0) {
                    IPSEC_LOG_ERR("ipsecdev_input",
                                  IPSEC_STATUS_FAILURE,
                                  ("failed to remove IPSec header"))
                    pbuf_free(p);
                }
                IPSEC_LOG_MSG("ipsecdev_input", ("fwd decapsulated IPsec packet"));
                return data->orig_input(p, inp);
            } else {
                IPSEC_LOG_ERR("ipsecdev_input",
                              retcode,
                              ("error on ipsec_input() processing (retcode = %d)",
                              retcode));
                pbuf_free(p);
            }
        } else {
            /* check what the policy says about non-IPsec traffic */
            spd = ipsec_spd_lookup(pkt, &db->inbound_spd) ;
            if (spd == NULL) {
                IPSEC_LOG_ERR("ipsecdev_input", IPSEC_STATUS_NO_POLICY_FOUND, ("no matching SPD policy found")) ;
                data->orig_input(p, inp);
                /*pbuf_free(p);*/
            } else {
                switch(spd->policy) {
                    case POLICY_APPLY:
                        IPSEC_LOG_AUD("ipsecdev_input", IPSEC_AUDIT_APPLY, ("POLICY_APPLY: got non-IPsec packet which should be one")) ;
                        pbuf_free(p) ;
                        break;
                    case POLICY_DISCARD:
                        IPSEC_LOG_AUD("ipsecdev_input", IPSEC_AUDIT_DISCARD, ("POLICY_DISCARD: dropping packet")) ;
                        pbuf_free(p) ;
                        break;
                    case POLICY_BYPASS:
                        IPSEC_LOG_AUD("ipsecdev_input", IPSEC_AUDIT_BYPASS, ("POLICY_BYPASS: forwarding packet to ip_input")) ;
                        data->orig_input(p, inp);
                        break;
                    default:
                        pbuf_free(p) ;
                        IPSEC_LOG_ERR("ipsecdev_input", IPSEC_STATUS_FAILURE, ("IPSEC_STATUS_FAILURE: dropping packet")) ;
                        IPSEC_LOG_AUD("ipsecdev_input", IPSEC_AUDIT_FAILURE, ("unknown Security Policy: dropping packet")) ;
                }
            }
        }
    }
	/* usually return ERR_OK as lwIP does */
	return ERR_OK;
}

static err_t ipsecdev_output(struct netif* netif, struct pbuf* p, const ip4_addr_t *ipaddr) {
    struct orig_fns *data = orig_fns_data + netif->num;
    spd_entry* relevant_sp;
    int ofs = 0;
    int len = 0;
    ipsec_status status = IPSEC_STATUS_NOT_INITIALIZED;
    struct ipsec_ip_addr dest_addr;
    ipsec_ip_header* hdr = (ipsec_ip_header*)p->payload;
    int space_overhead = 0;

    printf("Inside IPSecdev OUTPUT\n");

    /* chained pbuf check */
	if(p->next != NULL) {
  		IPSEC_LOG_DBG("ipsecdev_output",
                      IPSEC_STATUS_DATA_SIZE_ERROR,
                      ("can not handle chained pbuf"));
		return ERR_CONN;
	}

    /* pbuf reference check */
    if(p->ref != 1) {
  		IPSEC_LOG_DBG("ipsecdev_output",
                      IPSEC_STATUS_DATA_SIZE_ERROR,
                      ("can not handle pbuf->ref != 1 - p->ref == %d", p->ref));
		return ERR_CONN;
	}

    /** backup of physical destination IP address (inner IP header may become encrypted) */
	memcpy(&dest_addr, ipaddr, sizeof(struct ipsec_ip_addr));

    /* RFC Conform IPSec Processing */
    relevant_sp = ipsec_spd_lookup(hdr, &(db->outbound_spd));
	if (relevant_sp == NULL) {
		IPSEC_LOG_ERR("ipsecdev_output", IPSEC_STATUS_NO_POLICY_FOUND, ("no matching SPD policy found"));
		/* free local pbuf here */
		pbuf_free(p);
		return ERR_CONN ;
	}

    switch(relevant_sp->policy) {
        case POLICY_APPLY:
            IPSEC_LOG_AUD("ipsecdev_output", IPSEC_AUDIT_APPLY, ("POLICY_APPLY: processing IPsec packet")) ;

            /* add space to pbuf for AH/ESP overhead */
            space_overhead = relevant_sp->sa->protocol == IPSEC_PROTO_AH ? IPSEC_PROTO_AH : IPSEC_PROTO_ESP;
            if (pbuf_add_header(p, space_overhead) != 0) {
                IPSEC_LOG_ERR("ipsecdev_output", IPSEC_AUDIT_FAILURE, ("failed to add space for ESP data to pbuf"));
                pbuf_free(p);
                return ERR_MEM;
            }

            status = (ipsec_status)ipsec_output_impl((__u8*)hdr, ipsec_ntohs(hdr->len), &ofs, &len, hdr->src, hdr->dest, relevant_sp);

            /* todo: check length of output after ipsec is applied and remove unneeded space */
            if (status == IPSEC_STATUS_SUCCESS) {
                /* remove unused space (likely to occur in ESP mode due to variable padding.)
                ipsec_output_impl should guarantee that any extra space is at the FRONT of p->payload */
                space_overhead = ((char*)hdr + ofs) - (char*)p->payload;
                if (pbuf_remove_header(p, space_overhead) != 0) {
                    IPSEC_LOG_ERR("ipsecdev_output", IPSEC_AUDIT_FAILURE, ("failed to remove unnecessary IPSec space"));
                }
                IPSEC_LOG_MSG("ipsec_output", ("fwd IPsec packet to HW mapped device") );
                data->orig_output(netif, p, ipaddr);
            } else {
                IPSEC_LOG_ERR("ipsec_output", status, ("error on ipsec_output() processing"));
            }
            return ERR_OK;
        case POLICY_DISCARD:
            IPSEC_LOG_AUD("ipsecdev_output", IPSEC_AUDIT_DISCARD, ("POLICY_DISCARD: dropping packet")) ;
            break;
        case POLICY_BYPASS:
            IPSEC_LOG_AUD("ipsecdev_output", IPSEC_AUDIT_BYPASS, ("POLICY_BYPASS: forwarding packet to ip_output")) ;
            return data->orig_output(netif, p, ipaddr);
        default:
            IPSEC_LOG_ERR("ipsecdev_input", IPSEC_STATUS_FAILURE, ("POLICY_DIRCARD: dropping packet")) ;
            IPSEC_LOG_AUD("ipsecdev_input", IPSEC_AUDIT_FAILURE, ("unknown Security Policy: dropping packet")) ;
    }
	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_output", ("return = %d", ERR_CONN) );
	return ERR_CONN;
}

static err_t ipsecdev_linkoutput(struct netif* netif, struct pbuf* p) {
    /* intentionally leaving empty since thats how the original
    EIPS repo implemented it (i.e just forward along to the original linkoutput
    func for this netif.) */
    struct orig_fns *data = orig_fns_data + netif->num;
    return data->orig_linkoutput(netif, p);
}

void ipsecdev_add(struct netif* netif) {
    struct orig_fns* data = orig_fns_data + netif->num;
    int ethr;

    ethr = netif->flags & (NETIF_FLAG_ETHERNET | NETIF_FLAG_ETHARP);

    if (netif->input) {
        data->orig_input = netif->input;
        netif->input = ipsecdev_input;
    }
    if (!ethr && netif->output) {
        data->orig_output = netif->output;
        netif->output = ipsecdev_output;
    }
    if (ethr && netif->linkoutput) {
        data->orig_linkoutput = netif->linkoutput;
        netif->linkoutput = ipsecdev_linkoutput;
    }
}
