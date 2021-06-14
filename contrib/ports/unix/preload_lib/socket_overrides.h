#ifndef SOCKET_OVERRIDES_H
#define SOCKET_OVERRIDES_H

/* lwIP core includes */
#include "lwip/opt.h"
#include "lwip/sockets.h"

/* include the port-dependent configuration */
#include "lwipcfg.h"

#ifdef LWIP_COMPAT_SOCKETS
#if LWIP_COMPAT_SOCKETS == 0

typedef int (*accept_func_t)(int, struct sockaddr *, socklen_t *);
typedef int (*bind_func_t)(int, const struct sockaddr *, socklen_t);
typedef int (*shutdown_func_t)(int, int);
typedef int (*getpeername_func_t) (int, struct sockaddr *, socklen_t *);
typedef int (*getsockname_func_t) (int, struct sockaddr *, socklen_t *);
typedef int (*getsockopt_func_t) (int, int, int, void *, socklen_t *);
typedef int (*setsockopt_func_t) (int, int, int, const void *, socklen_t);
typedef int (*connect_func_t)(int, const struct sockaddr *, socklen_t);
typedef int (*listen_func_t)(int, int);
typedef ssize_t (*recv_func_t)(int, void *, size_t, int);
typedef ssize_t (*recvfrom_func_t)(int, void *, size_t, int, struct sockaddr *,
                                socklen_t *);
typedef ssize_t (*recvmsg_func_t)(int, struct msghdr *, int);
typedef ssize_t (*send_func_t)(int, const void *, size_t, int);
typedef ssize_t (*sendmsg_func_t)(int, const struct msghdr *, int);
typedef ssize_t (*sendto_func_t)(int, const void *, size_t, int,
                              const struct sockaddr *, socklen_t);
typedef int (*socket_func_t)(int, int, int);
#if LWIP_SOCKET_SELECT
typedef int (*select_func_t)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
#endif
#if LWIP_SOCKET_POLL
typedef int (*poll_func_t)(struct pollfd *, nfds_t, int);
#endif
typedef const char *(*inet_ntop_func_t)(int, const void *, char *, socklen_t);
typedef int (*inet_pton_func_t)(int, const char *, void *);

#if LWIP_POSIX_SOCKETS_IO_NAMES
typedef ssize_t (*read_func_t)(int, void *, size_t);
typedef ssize_t (*readv_func_t)(int, const struct iovec *, int);
typedef ssize_t (*write_func_t)(int, const void *, size_t);
typedef ssize_t (*writev_func_t)(int, const struct iovec *, int);
typedef int (*close_func_t)(int);
typedef int (*fcntl_func_t)(int, int, ...);
typedef int (*ioctl_func_t)(int, unsigned long int, ...);
#endif

extern accept_func_t real_accept;
extern bind_func_t real_bind;
extern shutdown_func_t real_shutdown;
extern getpeername_func_t real_getpeername;
extern getsockname_func_t real_getsockname;
extern getsockopt_func_t real_getsockopt;
extern setsockopt_func_t real_setsockopt;
extern connect_func_t real_connect;
extern listen_func_t real_listen;
extern recv_func_t real_recv;
extern recvfrom_func_t real_recvfrom;
extern recvmsg_func_t real_recvmsg;
extern send_func_t real_send;
extern sendmsg_func_t real_sendmsg;
extern sendto_func_t real_sendto;
extern socket_func_t real_socket;
#if LWIP_SOCKET_SELECT
extern select_func_t real_select;
#endif
#if LWIP_SOCKET_POLL
extern poll_func_t real_poll;
#endif
extern inet_ntop_func_t real_inet_ntop;
extern inet_pton_func_t real_inet_pton;

#if LWIP_POSIX_SOCKETS_IO_NAMES
extern read_func_t real_read;
extern readv_func_t real_readv;
extern write_func_t real_write;
extern writev_func_t real_writev;
extern close_func_t real_close;
extern fcntl_func_t real_fcntl;
extern ioctl_func_t real_ioctl;
#endif

/* override Linux APIs */
int accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int bind(int s, const struct sockaddr *name, socklen_t namelen);
int shutdown(int s, int how);
int getpeername(int s, struct sockaddr *name, socklen_t *namelen);
int getsockname(int s, struct sockaddr *name, socklen_t *namelen);
int getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen);
int setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen);
int connect(int s, const struct sockaddr *name, socklen_t namelen);
int listen(int s, int backlog);
ssize_t recv(int s, void *mem, size_t len, int flags);
ssize_t recvfrom(int s, void *mem, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);
ssize_t recvmsg(int s, struct msghdr *message, int flags);
ssize_t send(int s, const void *dataptr, size_t size, int flags);
ssize_t sendmsg(int s, const struct msghdr *message, int flags);
ssize_t sendto(int s, const void *dataptr, size_t size, int flags, const struct sockaddr *to, socklen_t tolen);
int socket(int domain, int type, int protocol);
#if LWIP_SOCKET_SELECT
/* int select(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset, struct timeval *timeout); */
#endif
#if LWIP_SOCKET_POLL
int poll(struct pollfd *fds, nfds_t nfds, int timeout);
#endif
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);
int inet_pton(int af, const char *src, void *dst);
#if LWIP_POSIX_SOCKETS_IO_NAMES
/* ssize_t read(int s, void *mem, size_t len); */
ssize_t readv(int s, const struct iovec *iov, int iovcnt);
/* ssize_t write(int s, const void *dataptr, size_t size); */
ssize_t writev(int s, const struct iovec *iov, int iovcnt);
/* int close(int s); */
int fcntl(int s, int cmd, int val);
int ioctl(int s, unsigned long int cmd, void *argp);
#endif /* LWIP_POSIX_SOCKETS_IO_NAMES */

void lwip_compat_init(void);

#endif /* LWIP_COMPAT_SOCKETS == 0 */
#endif /* LWIP_COMPAT_SOCKETS */

#endif /* SOCKET_OVERRIDES_H */
