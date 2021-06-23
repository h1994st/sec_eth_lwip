/* C runtime includes */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

/* lwIP core includes */
#include "lwip/opt.h"

#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/init.h"
#include "lwip/tcpip.h"
#include "lwip/netif.h"
#include "lwip/api.h"
#include "lwip/sockets.h"

#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/dns.h"

#include "lwip/ip_addr.h"
#if LWIP_RAWIF
#include "netif/rawif.h"
#else
#include "netif/tapif.h"
#endif /* LWIP_RAWIF */

#if defined(EIPS) && EIPS == 1
#include "ipsec/ipsecdev.h"
#endif /* defined(EIPS) && EIPS == 1 */
#if defined(MACSEC) && MACSEC == 1
#include "macsec/macsec.h"
#endif /* defined(MACSEC) && MACSEC == 1 */
#if defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1
#include "gatekeeper/gatekeeper.h"
#endif /* defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1 */

/* include the port-dependent configuration */
#include "lwipcfg.h"

#include "socket_overrides.h"

#ifndef LWIP_EXAMPLE_APP_ABORT
#define LWIP_EXAMPLE_APP_ABORT() 0
#endif

/** Define this to 1 to enable a port-specific ethernet interface as default interface. */
#ifndef USE_DEFAULT_ETH_NETIF
#define USE_DEFAULT_ETH_NETIF 1
#endif

/** Use an ethernet adapter? Default to enabled if port-specific ethernet netif or PPPoE are used. */
#ifndef USE_ETHERNET
#define USE_ETHERNET  (USE_DEFAULT_ETH_NETIF)
#endif

/** Use an ethernet adapter for TCP/IP? By default only if port-specific ethernet netif is used. */
#ifndef USE_ETHERNET_TCPIP
#define USE_ETHERNET_TCPIP  (USE_DEFAULT_ETH_NETIF)
#endif

static struct netif netif;

static void init_default_netif(const ip4_addr_t *ipaddr, const ip4_addr_t *netmask, const ip4_addr_t *gw)
{
#if LWIP_RAWIF
  netif_add(&netif, ipaddr, netmask, gw, NULL, rawif_init, tcpip_input);
#else
  netif_add(&netif, ipaddr, netmask, gw, NULL, tapif_init, tcpip_input);
#endif /* LWIP_RAWIF */

#if defined(EIPS) && EIPS == 1
  ipsecdev_add(&netif);
#endif /* defined(EIPS) && EIPS == 1 */

#if defined(MACSEC) && MACSEC == 1
  macsecdev_add(&netif);
#endif /* defined(MACSEC) && MACSEC == 1 */

#if defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1
  gkdev_add(&netif);
#endif /* defined(LWIP_GATEKEEPER) && LWIP_GATEKEEPER == 1 */

  netif_set_default(&netif);
}

#if LWIP_NETIF_STATUS_CALLBACK
static void
status_callback(struct netif *state_netif)
{
  if (netif_is_up(state_netif)) {
    printf("status_callback==UP, local interface IP is %s\n", ip4addr_ntoa(netif_ip4_addr(state_netif)));
  } else {
    printf("status_callback==DOWN\n");
  }
}
#endif /* LWIP_NETIF_STATUS_CALLBACK */

#if LWIP_NETIF_LINK_CALLBACK
static void
link_callback(struct netif *state_netif)
{
  if (netif_is_link_up(state_netif)) {
    printf("link_callback==UP\n");
  } else {
    printf("link_callback==DOWN\n");
  }
}
#endif /* LWIP_NETIF_LINK_CALLBACK */

/* This function initializes all network interfaces */
static void
preload_netif_init(void)
{
#if LWIP_RAWIF == 0
#if LWIP_IPV4 && USE_ETHERNET
  ip4_addr_t ipaddr, netmask, gw;
#endif /* LWIP_IPV4 && USE_ETHERNET */
  char *is_ip2 = getenv("IS_IP2");
#endif /* LWIP_RAWIF == 0 */

#if USE_ETHERNET
#if LWIP_RAWIF == 0
#if LWIP_IPV4
  ip4_addr_set_zero(&gw);
  ip4_addr_set_zero(&ipaddr);
  ip4_addr_set_zero(&netmask);
#if USE_ETHERNET_TCPIP
  LWIP_PORT_INIT_GW(&gw);
  if (!is_ip2) {
    LWIP_PORT_INIT_IPADDR(&ipaddr);
  } else {
    LWIP_PORT_INIT_IPADDR2(&ipaddr);
  }
  LWIP_PORT_INIT_NETMASK(&netmask);
  printf("Starting lwIP, local interface IP is %s\n", ip4addr_ntoa(&ipaddr));
#endif /* USE_ETHERNET_TCPIP */
#else /* LWIP_IPV4 */
  printf("Starting lwIP, IPv4 disable\n");
#endif /* LWIP_IPV4 */

#if LWIP_IPV4
  init_default_netif(&ipaddr, &netmask, &gw);
#else
  init_default_netif();
#endif
#else
  init_default_netif(NULL, NULL, NULL);
#endif /* LWIP_RAWIF == 0 */

#if LWIP_NETIF_STATUS_CALLBACK
  netif_set_status_callback(netif_default, status_callback);
#endif /* LWIP_NETIF_STATUS_CALLBACK */
#if LWIP_NETIF_LINK_CALLBACK
  netif_set_link_callback(netif_default, link_callback);
#endif /* LWIP_NETIF_LINK_CALLBACK */

#if USE_ETHERNET_TCPIP
  netif_set_up(netif_default);
#else /* USE_ETHERNET_TCPIP */
  /* Use ethernet for PPPoE only */
  netif.flags &= ~(NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP); /* no ARP */
  netif.flags |= NETIF_FLAG_ETHERNET; /* but pure ethernet */
#endif /* USE_ETHERNET_TCPIP */

#endif /* USE_ETHERNET */
}

/* This function initializes this lwIP test. When NO_SYS=1, this is done in
 * the main_loop context (there is no other one), when NO_SYS=0, this is done
 * in the tcpip_thread context */
static void
preload_init(void * arg)
{ /* remove compiler warning */
#if NO_SYS
  LWIP_UNUSED_ARG(arg);
#else /* NO_SYS */
  sys_sem_t *init_sem;
  LWIP_ASSERT("arg != NULL", arg != NULL);
  init_sem = (sys_sem_t*)arg;
#endif /* NO_SYS */

  /* init randomizer again (seed per thread) */
  srand((unsigned int)time(0));

  /* init network interfaces */
  preload_netif_init();

#if !NO_SYS
  sys_sem_signal(init_sem);
#endif /* !NO_SYS */
}

__attribute__((constructor))
static void lwip_ctor(void) {
  err_t err;
  sys_sem_t init_sem;

  lwip_compat_init();

  err = sys_sem_new(&init_sem, 0);
  LWIP_ASSERT("failed to create init_sem", err == ERR_OK);
  LWIP_UNUSED_ARG(err);
  tcpip_init(preload_init, &init_sem);
  /* we have to wait for initialization to finish before
   * calling update_adapter()! */
  sys_sem_wait(&init_sem);
  sys_sem_free(&init_sem);

  printf("lwip_ctor()\n");
}

__attribute__((destructor))
static void lwip_dtor(void) {
  printf("lwip_dtor()\n");
}
