#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>

/* lwIP core includes */
#include "lwip/opt.h"
#include "lwip/sockets.h"

/* include the port-dependent configuration */
#include "lwipcfg.h"

#include "socket_overrides.h"

/*
 *  LWIP socket fd large than linux "ulimit -n " value
 *
*/
#define LWIP_FD_BASE 2000

/* 1: redis socket will go through ANS stack, 0: go through linux stack */
int lwip_sock_enable = 1;

int lwipfd_debug_flag = 1;

#define LWIP_FD_DEBUG(args...)  \
  do {  \
    if (lwipfd_debug_flag == 1)  \
        printf(args);  \
  } while(0)

int lwip_sock_inited = 0;

#ifdef LWIP_COMPAT_SOCKETS
#if LWIP_COMPAT_SOCKETS == 0

accept_func_t real_accept;
bind_func_t real_bind;
shutdown_func_t real_shutdown;
getpeername_func_t real_getpeername;
getsockname_func_t real_getsockname;
getsockopt_func_t real_getsockopt;
setsockopt_func_t real_setsockopt;
connect_func_t real_connect;
listen_func_t real_listen;
recv_func_t real_recv;
recvfrom_func_t real_recvfrom;
recvmsg_func_t real_recvmsg;
send_func_t real_send;
sendmsg_func_t real_sendmsg;
sendto_func_t real_sendto;
socket_func_t real_socket;
#if LWIP_SOCKET_SELECT
select_func_t real_select;
#endif
#if LWIP_SOCKET_POLL
poll_func_t real_poll;
#endif
inet_ntop_func_t real_inet_ntop;
inet_pton_func_t real_inet_pton;

#if LWIP_POSIX_SOCKETS_IO_NAMES
read_func_t real_read;
readv_func_t real_readv;
write_func_t real_write;
writev_func_t real_writev;
close_func_t real_close;
fcntl_func_t real_fcntl;
ioctl_func_t real_ioctl;
#endif

void lwip_compat_init(void) {
#define INIT_FUNCTION(func) \
        real_##func = (func##_func_t) dlsym(RTLD_NEXT, #func); \
        assert(real_##func)

  INIT_FUNCTION(accept);
  INIT_FUNCTION(bind);
  INIT_FUNCTION(shutdown);
  INIT_FUNCTION(getpeername);
  INIT_FUNCTION(getsockname);
  INIT_FUNCTION(getsockopt);
  INIT_FUNCTION(setsockopt);
  INIT_FUNCTION(connect);
  INIT_FUNCTION(listen);
  INIT_FUNCTION(recv);
  INIT_FUNCTION(recvfrom);
  INIT_FUNCTION(recvmsg);
  INIT_FUNCTION(send);
  INIT_FUNCTION(sendmsg);
  INIT_FUNCTION(sendto);
  INIT_FUNCTION(socket);
#if LWIP_SOCKET_SELECT
  INIT_FUNCTION(select);
#endif
#if LWIP_SOCKET_POLL
  INIT_FUNCTION(poll);
#endif
  INIT_FUNCTION(inet_ntop);
  INIT_FUNCTION(inet_pton);

#if LWIP_POSIX_SOCKETS_IO_NAMES
  INIT_FUNCTION(read);
  INIT_FUNCTION(readv);
  INIT_FUNCTION(write);
  INIT_FUNCTION(writev);
  INIT_FUNCTION(close);
  INIT_FUNCTION(fcntl);
  INIT_FUNCTION(ioctl);
#endif

#undef INIT_FUNCTION

  if (lwip_sock_enable != 1) {
      printf("lwip socket is disabled\n");
      return;
  }

  lwip_sock_inited = 1;
  LWIP_FD_DEBUG("lwip socket is enabled\n");
}

int accept(int s, struct sockaddr *addr, socklen_t *addrlen) {
    int rc;

    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;

        rc = lwip_accept(s, addr, addrlen);
        addr->sa_family = AF_INET;
        if (rc > 0)
            rc += LWIP_FD_BASE;
        LWIP_FD_DEBUG("lwip accept fd %d\n", rc);
    } else {
        rc = real_accept(s, addr, addrlen);
        LWIP_FD_DEBUG("linux accept fd %d\n", rc);
    }

    return rc;
}

int bind(int s, const struct sockaddr *name, socklen_t namelen) {
    struct sockaddr_in in_addr;
    memcpy((void*)&in_addr, name, namelen);

    LWIP_FD_DEBUG("bind ip: %x , port %d, family:%d \n", in_addr.sin_addr.s_addr, ntohs(in_addr.sin_port), in_addr.sin_family);

    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        LWIP_FD_DEBUG("lwip bind fd %d\n", s);
        s -= LWIP_FD_BASE;
        return lwip_bind(s, name, namelen);
    } else {
        LWIP_FD_DEBUG("linux bind fd %d\n", s);
        return real_bind(s, name, namelen);
    }
}

int shutdown(int s, int how) {
    LWIP_FD_DEBUG("lwip shutdown fd %d, how %d, pid %d \n", s, how, getpid());

    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;
        return lwip_shutdown(s, how);;
    } else {
        return real_shutdown(s, how);
    }
}

int getpeername(int s, struct sockaddr *name, socklen_t *namelen) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;
        return lwip_getpeername(s, name, namelen);
    } else {
        return real_getpeername(s, name, namelen);
    }
}

int getsockname(int s, struct sockaddr *name, socklen_t *namelen) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;
        return lwip_getsockname(s, name, namelen);
    } else {
        return real_getsockname(s, name, namelen);
    }
}

int getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;
        return lwip_getsockopt(s, level, optname, optval, optlen);
    } else {
        return real_getsockopt(s, level, optname, optval, optlen);
    }
}

int setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        LWIP_FD_DEBUG("lwip setsockopt sock=%d level=%d optname=%d optlen=%d\n", s, level, optname, (int)optlen);
        s -= LWIP_FD_BASE;
        return lwip_setsockopt(s, level, optname, optval, optlen);
    } else {
        return real_setsockopt(s, level, optname, optval, optlen);
    }
}

int connect(int s, const struct sockaddr *name, socklen_t namelen) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;
        LWIP_FD_DEBUG("lwip fd(%d) start to connect \n", s);
        return lwip_connect(s, name, namelen);
    } else {
        LWIP_FD_DEBUG("linux fd(%d) start to connect \n", s);
        return real_connect(s, name, namelen);
    }
}

int listen(int s, int backlog) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;

        LWIP_FD_DEBUG("lwip listen fd %d, pid %d \n", s, getpid());

        return lwip_listen(s, backlog);
    } else {
        LWIP_FD_DEBUG("linux listen fd %d , pid %d \n", s, getpid());

        return real_listen(s, backlog);
    }
}

ssize_t recv(int s, void *mem, size_t len, int flags) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;
        return lwip_recv(s, mem, len, flags);
    } else {
        return real_recv(s, mem, len, flags);
    }
}

ssize_t recvfrom(int s, void *mem, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;
        return lwip_recvfrom(s, mem, len, flags, from, fromlen);
    } else {
        return real_recvfrom(s, mem, len, flags, from, fromlen);
    }
}

ssize_t recvmsg(int s, struct msghdr *message, int flags) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;
        return lwip_recvmsg(s, message, flags);
    } else {
        return real_recvmsg(s, message, flags);
    }
}

ssize_t send(int s, const void *dataptr, size_t size, int flags) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;
        return lwip_send(s, dataptr, size, flags);
    } else {
        return real_send(s, dataptr, size, flags);
    }
}

ssize_t sendmsg(int s, const struct msghdr *message, int flags) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;
        return lwip_sendmsg(s, message, flags);
    } else {
        return real_sendmsg(s, message, flags);
    }
}

ssize_t sendto(int s, const void *dataptr, size_t size, int flags, const struct sockaddr *to, socklen_t tolen) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;
        return lwip_sendto(s, dataptr, size, flags, to, tolen);
    } else {
        return real_sendto(s, dataptr, size, flags, to, tolen);
    }
}

int socket(int domain, int type, int protocol) {
    int rc;

    LWIP_FD_DEBUG("socket create start , domain %d, type %d \n", domain, type);

    if ((lwip_sock_inited == 0) ||
        (domain != AF_INET) ||
        (type != SOCK_STREAM && type != SOCK_DGRAM)) {
        rc = real_socket(domain, type, protocol);
        LWIP_FD_DEBUG("linux socket fd %d \n", rc);

        return rc;
    }

    assert(lwip_sock_inited);

    rc = lwip_socket(domain, type, protocol);
    if (rc > 0)
        rc += LWIP_FD_BASE;
    LWIP_FD_DEBUG("lwip socket fd %d\n", rc);

    return rc;
}

#if LWIP_SOCKET_SELECT
int select(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset, struct timeval *timeout) {
    if (maxfdp1 - 1 <= LWIP_FD_BASE) {
        return real_select(maxfdp1, readset, writeset, exceptset, timeout);
    }

    /* TODO: check each fd_set? */
    return -1;
}
#endif

#if LWIP_SOCKET_POLL
int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    unsigned long i;
    int all_lwip_sock = 1;

    if (lwip_sock_inited == 0) {
        return real_poll(fds, nfds, timeout);
    }

    for (i = 0; i < nfds; ++i) {
        if (fds[i].fd <= LWIP_FD_BASE) {
            all_lwip_sock = 0;
            break;
        }
    }

    if (all_lwip_sock == 0) {
        return real_poll(fds, nfds, timeout);
    }

    return lwip_poll(fds, nfds, timeout);
}
#endif

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size) {
    if (lwip_sock_inited && af == AF_INET) {
        return lwip_inet_ntop(af, src, dst, size);
    } else {
        return real_inet_ntop(af, src, dst, size);
    }
}

int inet_pton(int af, const char *src, void *dst) {
    if (lwip_sock_inited && af == AF_INET) {
        return lwip_inet_pton(af, src, dst);
    } else {
        return real_inet_pton(af, src, dst);
    }
}

#if LWIP_POSIX_SOCKETS_IO_NAMES
ssize_t read(int s, void *mem, size_t len) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;
        return lwip_read(s, mem, len);
    } else {
        return real_read(s, mem, len);
    }
}

ssize_t readv(int s, const struct iovec *iov, int iovcnt) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;
        return lwip_readv(s, iov, iovcnt);
    } else {
        return real_readv(s, iov, iovcnt);
    }
}

ssize_t write(int s, const void *dataptr, size_t size) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;
        return lwip_write(s, dataptr, size);
    } else {
        return real_write(s, dataptr, size);
    }
}

ssize_t writev(int s, const struct iovec *iov, int iovcnt) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;
        return lwip_writev(s, iov, iovcnt);
    } else {
        return real_writev(s, iov, iovcnt);
    }
}

int close(int s) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;
        return lwip_close(s);
    } else {
        return real_close(s);
    }
}

int fcntl(int s, int cmd, int val) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        s -= LWIP_FD_BASE;
        return lwip_fcntl(s, cmd, val);
    } else {
        return real_fcntl(s, cmd, val);
    }
}

int ioctl(int s, unsigned long int cmd, void *argp) {
    if (lwip_sock_inited && s > LWIP_FD_BASE) {
        LWIP_FD_DEBUG("lwip ioctl sock=%d\n", s);
        s -= LWIP_FD_BASE;
        return lwip_ioctl(s, (long)cmd, argp);
    } else {
        LWIP_FD_DEBUG("linux ioctl sock=%d, cmd=%ld, uid=%d, euid=%d\n", s, cmd, getuid(), geteuid());
        return real_ioctl(s, cmd, argp);
    }
}
#endif /* LWIP_POSIX_SOCKETS_IO_NAMES */

#endif /* LWIP_COMPAT_SOCKETS == 0 */
#endif /* LWIP_COMPAT_SOCKETS */
