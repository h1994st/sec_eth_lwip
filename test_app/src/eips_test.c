/* C Standard Includes */
#include <string.h>
#include <stdio.h>

/* lwIP Includes */
#include "lwip/opt.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"

/* Custom Includes */
#include "eips_test.h"

/* Options */
/*
#ifdef RECEIVER_ADDR
  #define ADDR RECEIVER_ADDR
#else
  #define ADDR "127.0.0.1"
#endif */
#define ADDR "192.168.1.3"
#define PORT 8000


static int lwip_socket_init_and_connect(const ip_addr_t* target) {
  int sockfd;
  struct sockaddr_in addr;

  /* setup address */
  memset(&addr, 0, sizeof(addr));
  addr.sin_len = sizeof(addr);
  addr.sin_family = AF_INET;
  addr.sin_port = PP_HTONS(PORT);
  inet_addr_from_ip4addr(&addr.sin_addr, ip_2_ip4(target));

  /* init socket and connect to target */
  if ((sockfd = lwip_socket(AF_INET, SOCK_STREAM, 0)) >= 0) {
    if (lwip_connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
      return sockfd;
    }
  }
  printf("lwIP socket init and connect error\n");
  exit(1);
}


static int lwip_socket_init_and_listen(void) {
  int sockfd;
  struct sockaddr_in addr;
  if ((sockfd = lwip_socket(AF_INET, SOCK_STREAM, 0)) >= 0) {
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = lwip_htons(sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = PP_HTONS(PORT);
    if (lwip_bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
      if (lwip_listen(sockfd, 0) == 0) {
        return sockfd;
      }
    }
  }
  printf("lwIP socket init and listen error\n");
  exit(1);
}

#if CONNECTION
/* EIPS Sender */
static void eips_sender(void* p) {
  int sockfd;
  ip_addr_t dst;
  char msg[] = "The Quick Brown Fox Jumped Over The Lazy Dog!\n";
  (void)p;

  ip4addr_aton(ADDR, ip_2_ip4(&dst));

  sockfd = lwip_socket_init_and_connect(&dst);
  lwip_write(sockfd, &msg, sizeof(msg));
  lwip_close(sockfd);
}


/* EIPS Receiver */
static void eips_receiver(void* p) {
  int sockfd, connfd;
  char datum;
  (void)p;

  /* init receiving socket and listen */
  sockfd = lwip_socket_init_and_listen();

  /* startup sender thread */
  sys_thread_new("eips_sender", eips_sender, NULL, 0, 0);

  printf("start connecting\n");
  /* wait for sender to connect and print whatever it sends */
  connfd = lwip_accept(sockfd, NULL, NULL);
  printf("connected\n");
  while (lwip_read(connfd, &datum, 1) >= 0)
    printf("%c", datum);

  /* teardown */
  lwip_close(sockfd);
  printf("EIPS Sender/Receiver Test Complete.\n");
}

#else
/* EIPS Sender */
static void eips_sender(void* p) {
  int sockfd;
  struct sockaddr_in servaddr;
  char msg[] = "aaaaa\n";
  ip_addr_t server_ip;

  ip4addr_aton(ADDR, ip_2_ip4(&server_ip));

  /* init socket and connect to target */
  if ((sockfd = lwip_socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    printf("socket init failed\n");
    exit(1);
  }

  memset(&servaddr, 0, sizeof(servaddr));

  /* Filling server information */
  servaddr.sin_len = sizeof(servaddr);
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = PP_HTONS(PORT);
  inet_addr_from_ip4addr(&servaddr.sin_addr, ip_2_ip4((ip_addr_t*) &server_ip));

  lwip_sendto(sockfd, (const char *)msg, strlen(msg),
        MSG_DONTWAIT, (const struct sockaddr *) &servaddr,
            sizeof(servaddr));
  lwip_close(sockfd);
}


/* EIPS Receiver */
static void eips_receiver(void* p) {
  int sockfd;
  char buffer[100];
  struct sockaddr_in servaddr;
  struct sockaddr_in cliaddr;
  int addr_len, n;
  int socket;

  if ((sockfd = lwip_socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    printf("socket init failed\n");
    exit(1);
  }

  memset(&servaddr, 0, sizeof(servaddr));
  memset(&cliaddr, 0, sizeof(cliaddr));

  /* Filling server information */
  servaddr.sin_len = lwip_htons(sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = PP_HTONS(PORT);

  if (lwip_bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
    printf("socket bind failed\n");
    exit(1);
  }

  /* wait for sender to connect and print whatever it sends */
  addr_len = sizeof(cliaddr);
  n = lwip_recvfrom(sockfd, (char *)buffer, 100,
              MSG_WAITALL, ( struct sockaddr *) &cliaddr,
              &addr_len);
  buffer[n] = '\0';
  lwip_close(sockfd);

  printf("%s\n", buffer);
  printf("EIPS Sender/Receiver Test Complete.\n");
}
#endif /* CONNECTION */

void eips_test_sender(void) {
  sys_thread_new("eips_sender", eips_sender, NULL, 0, 0);
}

void eips_test_receiver(void) {
  sys_thread_new("eips_receiver", eips_receiver, NULL, 0, 0);
}

/* Tests that destination address is valid before starting main EIPS Sockets thread */
void eips_test_init(void) {
  sys_thread_new("eips_receiver", eips_receiver, NULL, 0, 0);
  sleep(1);
  sys_thread_new("eips_sender", eips_sender, NULL, 0, 0);
}
