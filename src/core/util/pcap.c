/* A very helpful utility that dumps all traffic going through an
 * lwIP netif to a PCAP file.
 *
 * CREDIT: https://github.com/russdill/lwip-libevent
 */

#include <sys/time.h>

#include <lwip/netif.h>
#include <lwip/pbuf.h>

#include <pcap/pcap.h>

#include "util/pcap.h"

#include <string.h>

struct pcap_sf_pkthdr {
	uint32_t tv_sec;		/* time stamp */
	uint32_t tv_usec;
	bpf_u_int32 caplen;		/* length of portion present */
	bpf_u_int32 len;		/* length this packet (off wire) */
};

struct pcap_dump_data {
	netif_input_fn orig_input;
#if LWIP_IPV4
	netif_output_fn orig_output;
#endif /* LWIP_IPV4*/
#if LWIP_IPV6
	netif_output_ip6_fn orig_output_ip6;
#endif /* LWIP_IPV6 */
	netif_linkoutput_fn orig_linkoutput;

	pcap_t *p;
	pcap_dumper_t *dumper;
};

static struct pcap_dump_data dump_data[256];

static void
pcap_dump_pbuf(struct pcap_dump_data *data, struct pbuf *p)
{
	struct timeval ts;
	struct pcap_sf_pkthdr hdr;
	FILE *fp;

	gettimeofday(&ts, NULL);
	hdr.tv_sec = ts.tv_sec;
	hdr.tv_usec = ts.tv_usec;
	hdr.caplen = p->tot_len;
	hdr.len = p->tot_len;

	fp = pcap_dump_file(data->dumper);
	fwrite(&hdr, sizeof(hdr), 1, fp);

	while (p) {
		fwrite(p->payload, p->len, 1, fp);
		p = p->next;
	}
	fflush(fp);
}

static err_t pcap_dump_input(struct pbuf *p, struct netif *inp)
{
	struct pcap_dump_data *data = dump_data + inp->num;
	pcap_dump_pbuf(data, p);
	return data->orig_input(p, inp);
}

#if LWIP_IPV4
static err_t pcap_dump_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
	struct pcap_dump_data *data = dump_data + netif->num;
	pcap_dump_pbuf(data, p);
	return data->orig_output(netif, p, ipaddr);
}
#endif /* LWIP_IPV4*/

#if LWIP_IPV6
err_t pcap_dump_output_ip6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr)
{
	struct pcap_dump_data *data = dump_data + netif->num;
	pcap_dump_pbuf(data, p);
	return data->orig_output_ip6(netif, p, ipaddr);
}
#endif /* LWIP_IPV6 */

static err_t pcap_dump_linkoutput(struct netif *netif, struct pbuf *p)
{
	struct pcap_dump_data *data = dump_data + netif->num;
	pcap_dump_pbuf(data, p);
	return data->orig_linkoutput(netif, p);
}

int
pcap_dump_add(struct netif *netif, const char *pcap_file)
{
	struct pcap_dump_data *data = dump_data + netif->num;
	int ether;

	if (data->p)
		return -1;

	ether = netif->flags & (NETIF_FLAG_ETHERNET | NETIF_FLAG_ETHARP);

	data->p = pcap_open_dead(ether ? DLT_EN10MB : DLT_RAW, 2000);
	if (!data->p)
		return -1;

	data->dumper = pcap_dump_open(data->p, pcap_file);
	if (!data->dumper) {
		data->p = NULL;
		return -1;
	}

	if (netif->input) {
		data->orig_input = netif->input;
		netif->input = pcap_dump_input;
	}
#if LWIP_IPV4
	if (!ether && netif->output) {
		data->orig_output = netif->output;
		netif->output = pcap_dump_output;
	}
#endif /* LWIP_IPV4*/
#if LWIP_IPV6
	if (!ether && netif->output_ip6) {
		data->orig_output_ip6 = netif->output_ip6;
		netif->output_ip6 = pcap_dump_output_ip6;
	}
#endif /* LWIP_IPV6 */
	if (ether && netif->linkoutput) {
		data->orig_linkoutput = netif->linkoutput;
		netif->linkoutput = pcap_dump_linkoutput;
	}

	return 0;
}

void
pcap_dump_remove(struct netif *netif)
{
	struct pcap_dump_data *data = dump_data + netif->num;

	if (!data->p)
		return;

	pcap_dump_close(data->dumper);
	pcap_close(data->p);

	netif->input = data->orig_input;
#if LWIP_IPV4
	netif->output = data->orig_output;
#endif /* LWIP_IPV4*/
#if LWIP_IPV6
	netif->output_ip6 = data->orig_output_ip6;
#endif /* LWIP_IPV6 */
	netif->linkoutput = data->orig_linkoutput;

	memset(data, 0, sizeof(*data));
}
