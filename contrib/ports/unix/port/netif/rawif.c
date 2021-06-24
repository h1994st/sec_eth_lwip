#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <net/if.h>

#include "lwip/opt.h"

#include "lwip/debug.h"
#include "lwip/def.h"
#include "lwip/ip.h"
#include "lwip/mem.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "netif/etharp.h"

#include "netif/rawif.h"

#if defined(LWIP_UNIX_LINUX)
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
/*
 * By default, eth0 will be used for communication via the raw socket.
 *
 * You can also use PRECONFIGURED_RAWIF environment variable to change
 * the interface.
 */
#ifndef DEV_DEFAULT_RAWIF
#define DEV_DEFAULT_RAWIF "eth0"
#endif
#endif

/* Define those to better describe your network interface. */
#define IFNAME0 'r'
#define IFNAME1 'w'

#ifndef RAWIF_DEBUG
#define RAWIF_DEBUG LWIP_DBG_OFF
#endif

struct rawif {
  /* Add whatever per-interface state that is needed here. */
  int fd;
};

/* Forward declarations. */
static void rawif_input(struct netif *netif);
#if !NO_SYS
static void rawif_thread(void *arg);
#endif /* !NO_SYS */

static struct sockaddr_ll netif_address;

/*-----------------------------------------------------------------------------------*/
static void
low_level_init(struct netif *netif)
{
  struct rawif *rawif;
  char ifname[IF_NAMESIZE];
  char *preconfigured_rawif = getenv("PRECONFIGURED_RAWIF");

  rawif = (struct rawif *)netif->state;

  /* device capabilities */
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;

  /* the last argument is important. with it, we can receive packets using raw socket */
  rawif->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  LWIP_DEBUGF(RAWIF_DEBUG, ("rawif_init: fd %d\n", rawif->fd));
  if (rawif->fd == -1) {
#ifdef LWIP_UNIX_LINUX
    perror("rawif_init: cannot create raw socket");
#endif /* LWIP_UNIX_LINUX */
    exit(1);
  }

#ifdef LWIP_UNIX_LINUX
  {
    /* bind to the interface */

    struct ifreq ifr;
#if LWIP_IPV4
    ip4_addr_t ipaddr, netmask, gw;
#endif

    memset(&ifr, 0, sizeof(ifr));
    memset(ifname, 0, IF_NAMESIZE);

    if (preconfigured_rawif) {
      strncpy(ifname, preconfigured_rawif, IF_NAMESIZE);
    } else {
      strncpy(ifname, DEV_DEFAULT_RAWIF, IF_NAMESIZE);
    }
    ifname[IF_NAMESIZE-1] = 0; /* ensure \0 termination */
    memcpy(ifr.ifr_name, ifname, IF_NAMESIZE);

    if (setsockopt(rawif->fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) < 0) {
      close(rawif->fd);
      perror("rawif_init: setsockopt failed");
      exit(1);
    }

    /* Obtain interface index from network interface. */
    if (ioctl(rawif->fd, SIOCGIFINDEX, (void *) &ifr) < 0) {
      close(rawif->fd);
      perror("rawif_init: ioctl SIOCGIFINDEX");
      exit(1);
    }

    netif_address.sll_ifindex = ifr.ifr_ifindex;

#if LWIP_IPV4
    /* Obtain MAC address from network interface. */
    if (ioctl(rawif->fd, SIOCGIFHWADDR, (void *) &ifr) < 0) {
      close(rawif->fd);
      perror("rawif_init: ioctl SIOCGIFHWADDR");
      exit(1);
    }
    memcpy(netif->hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    netif->hwaddr_len = 6;
    netif_address.sll_halen = ETH_ALEN;
    memcpy(netif_address.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    /* Obtain IP address from network interface. */
    if (ioctl(rawif->fd, SIOCGIFADDR, (void *) &ifr) < 0) {
      close(rawif->fd);
      perror("rawif_init: ioctl SIOCGIFADDR");
      exit(1);
    }
    memcpy(&ipaddr, &(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr), sizeof(ipaddr));
    /* !!! shift the IP address by 5 */
    /* The IP address of lwip netif cannot be the same as the underlying Ethernet device;
     * otherwise, the kernel will handle TCP handshake by itself, leading to TCP RST. */
    memset(((uint8_t*)&ipaddr) + sizeof(ipaddr) - 1, ip4_addr4_val(ipaddr) + 5, 1);
    /* assume gateway address is the same, except for the last byte */
    memcpy(&gw, &ipaddr, sizeof(ipaddr));
    memset(((uint8_t*)&gw) + sizeof(gw) - 1, 1, 1);

    /* Obtain network mask from network interface. */
    if (ioctl(rawif->fd, SIOCGIFNETMASK, (void *) &ifr) < 0) {
      close(rawif->fd);
      perror("rawif_init: ioctl SIOCGIFNETMASK");
      exit(1);
    }
    memcpy(&netmask, &(((struct sockaddr_in*)&ifr.ifr_netmask)->sin_addr), sizeof(ipaddr));

    printf("Starting lwIP, local interface IP is %s\n", ip4addr_ntoa(&ipaddr));

    netif_set_addr(netif, &ipaddr, &netmask, &gw);
  }
#endif /* LWIP_IPV4 */
#endif /* LWIP_UNIX_LINUX */

  netif_set_link_up(netif);

#if !NO_SYS
  sys_thread_new("rawif_thread", rawif_thread, netif, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
#endif /* !NO_SYS */
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_output():
 *
 * Should do the actual transmission of the packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * might be chained.
 *
 */
/*-----------------------------------------------------------------------------------*/

static err_t
low_level_output(struct netif *netif, struct pbuf *p)
{
  struct rawif *rawif = (struct rawif *)netif->state;
  char buf[1518]; /* max packet size including VLAN excluding CRC */
  ssize_t written;

#if 0
  if (((double)rand()/(double)RAND_MAX) < 0.2) {
    printf("drop output\n");
    return ERR_OK; /* ERR_OK because we simulate packet loss on cable */
  }
#endif

  if (p->tot_len > sizeof(buf)) {
    MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
    perror("rawif: packet too large");
    return ERR_IF;
  }

  /* initiate transfer(); */
  pbuf_copy_partial(p, buf, p->tot_len, 0);

  /* signal that packet should be sent(); */
  written = sendto(rawif->fd, buf, p->tot_len, 0, (struct sockaddr *)&netif_address, sizeof(netif_address));
  if (written < p->tot_len) {
    MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
    perror("rawif: sendto");
    return ERR_IF;
  } else {
    MIB2_STATS_NETIF_ADD(netif, ifoutoctets, (u32_t)written);
    return ERR_OK;
  }
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_input():
 *
 * Should allocate a pbuf and transfer the bytes of the incoming
 * packet from the interface into the pbuf.
 *
 */
/*-----------------------------------------------------------------------------------*/
static struct pbuf *
low_level_input(struct netif *netif)
{
  struct pbuf *p;
  u16_t len;
  ssize_t readlen;
  char buf[1518]; /* max packet size including VLAN excluding CRC */
  struct rawif *rawif = (struct rawif *)netif->state;

  /* Obtain the size of the packet and put it into the "len"
     variable. */
  readlen = recvfrom(rawif->fd, buf, sizeof(buf), 0, NULL, NULL);
  if (readlen < 0) {
    close(rawif->fd);
    perror("read returned -1");
    exit(1);
  }
  len = (u16_t)readlen;

  MIB2_STATS_NETIF_ADD(netif, ifinoctets, len);

#if 0
  if (((double)rand()/(double)RAND_MAX) < 0.2) {
    printf("drop\n");
    return NULL;
  }
#endif

  /* We allocate a pbuf chain of pbufs from the pool. */
  p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
  if (p != NULL) {
    pbuf_take(p, buf, len);
    /* acknowledge that packet has been read(); */
  } else {
    /* drop packet(); */
    MIB2_STATS_NETIF_INC(netif, ifindiscards);
    LWIP_DEBUGF(NETIF_DEBUG, ("rawif_input: could not allocate pbuf\n"));
  }

  return p;
}

/*-----------------------------------------------------------------------------------*/
/*
 * rawif_input():
 *
 * This function should be called when a packet is ready to be read
 * from the interface. It uses the function low_level_input() that
 * should handle the actual reception of bytes from the network
 * interface.
 *
 */
/*-----------------------------------------------------------------------------------*/
static void
rawif_input(struct netif *netif)
{
  struct pbuf *p = low_level_input(netif);

  if (p == NULL) {
#if LINK_STATS
    LINK_STATS_INC(link.recv);
#endif /* LINK_STATS */
    LWIP_DEBUGF(RAWIF_DEBUG, ("rawif_input: low_level_input returned NULL\n"));
    return;
  }

  if (netif->input(p, netif) != ERR_OK) {
    LWIP_DEBUGF(NETIF_DEBUG, ("rawif_input: netif input error\n"));
    pbuf_free(p);
  }
}
/*-----------------------------------------------------------------------------------*/
/*
 * rawif_init():
 *
 * Should be called at the beginning of the program to set up the
 * network interface. It calls the function low_level_init() to do the
 * actual setup of the hardware.
 *
 */
/*-----------------------------------------------------------------------------------*/
err_t
rawif_init(struct netif *netif)
{
  struct rawif *rawif = (struct rawif *)mem_malloc(sizeof(struct rawif));

  if (rawif == NULL) {
    LWIP_DEBUGF(NETIF_DEBUG, ("rawif_init: out of memory for rawif\n"));
    return ERR_MEM;
  }
  netif->state = rawif;
  MIB2_INIT_NETIF(netif, snmp_ifType_other, 100000000);

  netif->name[0] = IFNAME0;
  netif->name[1] = IFNAME1;
#if LWIP_IPV4
  netif->output = etharp_output;
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
  netif->output_ip6 = ethip6_output;
#endif /* LWIP_IPV6 */
  netif->linkoutput = low_level_output;
  netif->mtu = 1500;

  low_level_init(netif);

  return ERR_OK;
}


/*-----------------------------------------------------------------------------------*/
void
rawif_poll(struct netif *netif)
{
  rawif_input(netif);
}

#if NO_SYS

int
rawif_select(struct netif *netif)
{
  fd_set fdset;
  int ret;
  struct timeval tv;
  struct rawif *rawif;
  u32_t msecs = sys_timeouts_sleeptime();

  rawif = (struct rawif *)netif->state;

  tv.tv_sec = msecs / 1000;
  tv.tv_usec = (msecs % 1000) * 1000;

  FD_ZERO(&fdset);
  FD_SET(rawif->fd, &fdset);

  ret = select(rawif->fd + 1, &fdset, NULL, NULL, &tv);
  if (ret > 0) {
    rawif_input(netif);
  }
  return ret;
}

#else /* NO_SYS */

static void
rawif_thread(void *arg)
{
  struct netif *netif;
  struct rawif *rawif;
  fd_set fdset;
  int ret;

  netif = (struct netif *)arg;
  rawif = (struct rawif *)netif->state;

  while(1) {
    FD_ZERO(&fdset);
    FD_SET(rawif->fd, &fdset);

    /* Wait for a packet to arrive. */
    ret = select(rawif->fd + 1, &fdset, NULL, NULL, NULL);

    if(ret == 1) {
      /* Handle incoming packet. */
      rawif_input(netif);
    } else if(ret == -1) {
      perror("rawif_thread: select");
    }
  }
}

#endif /* NO_SYS */
