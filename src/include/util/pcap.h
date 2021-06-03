/* A very helpful utility that dumps all traffic going through an
 * lwIP netif to a PCAP file.
 *
 * CREDIT: https://github.com/russdill/lwip-libevent
 */

#ifndef __PCAP_H__
#define __PCAP_H__

struct netif;

int pcap_dump_add(struct netif *netif, const char *pcap_file);
void pcap_dump_remove(struct netif *netif);

#endif
