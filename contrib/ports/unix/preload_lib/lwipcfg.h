/**
 * Additional settings for the win32 port.
 * Copy this to lwipcfg_msvc.h and make the config changes you need.
 */


/** Define this to the GUID of the windows network adapter to use
 * or NOT define this if you want PACKET_LIB_ADAPTER_NR to be used */
/*#define PACKET_LIB_ADAPTER_GUID       "00000000-0000-0000-0000-000000000000"*/
/*#define PACKET_LIB_GET_ADAPTER_NETADDRESS(addr) IP4_ADDR((addr), 192,168,1,0)*/
/*#define PACKET_LIB_QUIET*/

#define LWIP_PORT_INIT_IPADDR2(addr)   IP4_ADDR((addr), 192,168,1,201)
#define LWIP_PORT_INIT_IPADDR(addr)   IP4_ADDR((addr), 192,168,1,200)
#define LWIP_PORT_INIT_GW(addr)       IP4_ADDR((addr), 192,168,1,1)
#define LWIP_PORT_INIT_NETMASK(addr)  IP4_ADDR((addr), 255,255,255,0)

/* remember to change this MAC address to suit your needs!
   the last octet will be increased by netif->num for each netif */
#define LWIP_MAC_ADDR_BASE            {0x00,0x01,0x02,0x03,0x04,0x05}

/* configuration for applications */

#define LWIP_CHARGEN_APP              0
#define LWIP_DNS_APP                  0
#define LWIP_HTTPD_APP                0
/* Set this to 1 to use the netconn http server,
 * otherwise the raw api server will be used. */
/*#define LWIP_HTTPD_APP_NETCONN     */
#define LWIP_NETBIOS_APP              0
#define LWIP_NETIO_APP                0
#define LWIP_MDNS_APP                 0
#define LWIP_MQTT_APP                 0
#define LWIP_PING_APP                 0
#define LWIP_RTP_APP                  0
#define LWIP_SHELL_APP                0
#define LWIP_SNMP_APP                 0
#define LWIP_SNTP_APP                 0
#define LWIP_SOCKET_EXAMPLES_APP      0
#define LWIP_TCPECHO_APP              0
/* Set this to 1 to use the netconn tcpecho server,
 * otherwise the raw api server will be used. */
/*#define LWIP_TCPECHO_APP_NETCONN   */
#define LWIP_TFTP_APP                 0
#define LWIP_TFTP_CLIENT_APP          0
#define LWIP_UDPECHO_APP              0
#define LWIP_LWIPERF_APP              0
