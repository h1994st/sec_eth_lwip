/*
 * Copyright (c) 2001,2002 Florian Schulze.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the authors nor the names of the contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

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

#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/dns.h"
#include "lwip/dhcp.h"
#include "lwip/autoip.h"

/* lwIP netif includes */
#include "lwip/etharp.h"
#include "netif/ethernet.h"

/* applications includes */
#include "eips_test.h"
#include "default_netif.h"

/* include the port-dependent configuration */
#include "lwipcfg.h"

/** Define this to 1 to enable a port-specific ethernet interface as default interface. */
#ifndef USE_DEFAULT_ETH_NETIF
#define USE_DEFAULT_ETH_NETIF 1
#endif

/** Use an ethernet adapter? Default to enabled if port-specific ethernet netif or PPPoE are used. */
#ifndef USE_ETHERNET
#define USE_ETHERNET  (USE_DEFAULT_ETH_NETIF || PPPOE_SUPPORT)
#endif

/** Use an ethernet adapter for TCP/IP? By default only if port-specific ethernet netif is used. */
#ifndef USE_ETHERNET_TCPIP
#define USE_ETHERNET_TCPIP  (USE_DEFAULT_ETH_NETIF)
#endif

#ifndef USE_DHCP
#define USE_DHCP    LWIP_DHCP
#endif
#ifndef USE_AUTOIP
#define USE_AUTOIP  LWIP_AUTOIP
#endif

/* globales variables for netifs */
#if LWIP_DHCP
/* dhcp struct for the ethernet netif */
struct dhcp netif_dhcp;
#endif /* LWIP_DHCP */

#if LWIP_AUTOIP
/* autoip struct for the ethernet netif */
struct autoip netif_autoip;
#endif /* LWIP_AUTOIP */


static void status_callback(struct netif *state_netif) {
  if (netif_is_up(state_netif)) {
    printf("status_callback==UP, local interface IP is %s\n",
            ip4addr_ntoa(netif_ip4_addr(state_netif)));
  } else {
    printf("status_callback==DOWN\n");
  }
}


static void link_callback(struct netif *state_netif) {
  if (netif_is_link_up(state_netif)) {
    printf("link_callback==UP\n");
  } else {
    printf("link_callback==DOWN\n");
  }
}


/* This function initializes all network interfaces */
static void test_netif_init(void) {
  ip4_addr_t ipaddr, netmask, gw;

  #if USE_DHCP || USE_AUTOIP
    err_t err;
  #endif

  ip4_addr_set_zero(&gw);
  ip4_addr_set_zero(&ipaddr);
  ip4_addr_set_zero(&netmask);

  #if USE_ETHERNET_TCPIP
    #if USE_DHCP
      printf("Starting lwIP, local interface IP is dhcp-enabled\n");
    #elif USE_AUTOIP
      printf("Starting lwIP, local interface IP is autoip-enabled\n");
    #else /* USE_DHCP */
      LWIP_PORT_INIT_GW(&gw);
      LWIP_PORT_INIT_IPADDR(&ipaddr);
      LWIP_PORT_INIT_NETMASK(&netmask);
      printf("Starting lwIP, local interface IP is %s\n", ip4addr_ntoa(&ipaddr));
    #endif /* USE_DHCP */
  #endif /* USE_ETHERNET_TCPIP */

  init_default_netif(&ipaddr, &netmask, &gw);
  netif_set_status_callback(netif_default, status_callback);
  netif_set_link_callback(netif_default, link_callback);

  #if USE_ETHERNET_TCPIP
    #if LWIP_AUTOIP
      autoip_set_struct(netif_default, &netif_autoip);
    #endif /* LWIP_AUTOIP */
    #if LWIP_DHCP
      dhcp_set_struct(netif_default, &netif_dhcp);
    #endif /* LWIP_DHCP */
      netif_set_up(netif_default);
    #if USE_DHCP
      err = dhcp_start(netif_default);
      LWIP_ASSERT("dhcp_start failed", err == ERR_OK);
    #elif USE_AUTOIP
      err = autoip_start(netif_default);
      LWIP_ASSERT("autoip_start failed", err == ERR_OK);
    #endif /* USE_DHCP */
    #else /* USE_ETHERNET_TCPIP */
      /* Use ethernet for PPPoE only */
      netif.flags &= ~(NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP); /* no ARP */
      netif.flags |= NETIF_FLAG_ETHERNET; /* but pure ethernet */
  #endif /* USE_ETHERNET_TCPIP */
}


/* This function initializes this lwIP test. When NO_SYS=1, this is done in
 * the main_loop context (there is no other one), when NO_SYS=0, this is done
 * in the tcpip_thread context */
static void test_init(void *arg) {
  sys_sem_t *init_sem;
  LWIP_ASSERT("arg != NULL", arg != NULL);
  init_sem = (sys_sem_t*)arg;

  /* init randomizer again (seed per thread), network interfaces, and apps */
  srand((unsigned int)time(0));
  test_netif_init();

  #if LWIP_SOCKET
    eips_test_init();
  #endif

  sys_sem_signal(init_sem);
}

/* This is somewhat different to other ports: we have a main loop here:
 * a dedicated task that waits for packets to arrive. This would normally be
 * done from interrupt context with embedded hardware, but we don't get an
 * interrupt in windows for that :-) */
int main(void) {
  err_t err;
  sys_sem_t init_sem;

  /* initialize lwIP stack, network interfaces and applications */
  err = sys_sem_new(&init_sem, 0);
  LWIP_ASSERT("failed to create init_sem", err == ERR_OK);
  LWIP_UNUSED_ARG(err);
  tcpip_init(test_init, &init_sem);
  /* we have to wait for initialization to finish before
   * calling update_adapter()! */
  sys_sem_wait(&init_sem);
  sys_sem_free(&init_sem);

  /* MAIN LOOP for driver update (and timers if NO_SYS) */
  while (!LWIP_EXAMPLE_APP_ABORT())
    default_netif_poll();
  default_netif_shutdown();
}

/* This function is only required to prevent arch.h including stdio.h
 * (which it does if LWIP_PLATFORM_ASSERT is undefined)
 */
void lwip_example_app_platform_assert(const char *msg, int line, const char *file) {
  printf("Assertion \"%s\" failed at line %d in %s\n", msg, line, file);
  fflush(NULL);
  abort();
}
