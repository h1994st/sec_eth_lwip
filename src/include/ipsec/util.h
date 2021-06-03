/*
 * embedded IPsec
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 */

/** @file util.h
 *  @brief Header of common helper functions and macros
 *
 *  @author Niklaus Schild <n.schild@gmx.ch>
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.<BR>
 * This file contains code from the lwIP project by Adam Dunkels and others<BR>
 * Copyright (c) 2001, 2002 Swedish Institute of Computer Science.<BR>
 * All rights reserved.</EM><HR>
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#include "ipsec/types.h"

#define IPSEC_DES_KEY_LEN		(8)							/**< Defines the size of a DES key in bytes */
#define IPSEC_3DES_KEY_LEN		(IPSEC_DES_KEY_LEN*3)		/**< Defines the length of a 3DES key in bytes */
#define IPSEC_MAX_ENCKEY_LEN	(IPSEC_3DES_KEY_LEN)		/**< Defines the maximum encryption key length of our IPsec system */

#define IPSEC_AUTH_ICV			(12)						/**< Defines the authentication key length in bytes (12 bytes for 96bit keys) */
#define IPSEC_AUTH_MD5_KEY_LEN	(16)						/**< Length of MD5 secret key  */
#define IPSEC_AUTH_SHA1_KEY_LEN	(20)						/**< Length of SHA1 secret key */
#define IPSEC_MAX_AUTHKEY_LEN   (IPSEC_AUTH_SHA1_KEY_LEN) 	/**< Maximum length of authentication keys */

#define IPSEC_MIN_IPHDR_SIZE	(20) 	/**< Defines the minimum IP header size (in bytes).*/
#define IPSEC_SEQ_MAX_WINDOW	(32)	/**< Defines the maximum window for Sequence Number checks (used as anti-replay protection) */

#define IPSEC_IP4_MAX_ADDR_STRLEN (15)


/** 
 * IP related stuff
 *
 */
struct ipsec_ip_addr {
  __u32 addr;
};

struct ipsec_in_addr {
  __u32 s_addr_eis;
};

#define IPSEC_IP_ADDR_NONE    ((__u32) 0xffffffff)  /* 255.255.255.255 */
#define IPSEC_IP_ADDR_LOCALHOST    ((__u32) 0x7f000001)  /* 127.0.0.1 */
#define IPSEC_IP4_ADDR(ipaddr, a,b,c,d) ipaddr = ipsec_htonl(((__u32)(a & 0xff) << 24) | ((__u32)(b & 0xff) << 16) | \
                                                         ((__u32)(c & 0xff) << 8) | (__u32)(d & 0xff))

#define IPSEC_IP4_ADDR_2(a,b,c,d) ((__u32)(d & 0xff) << 24) | ((__u32)(c & 0xff) << 16) | ((__u32)(b & 0xff) << 8) | (__u32)(a & 0xff)														 
#define IPSEC_IP4_ADDR_NET(a,b,c,d) ((__u32)(d & 0xff) << 24) | ((__u32)(c & 0xff) << 16) | ((__u32)(b & 0xff) << 8) | (__u32)(a & 0xff)

#define IPSEC_HTONL(n) (((__u32)n & 0xff) << 24) | (((__u32)n & 0xff00) << 8) | (((__u32)n & 0xff0000) >> 8) | (((__u32)n & 0xff000000) >> 24)

#define IPSEC_HTONS(n) (((__u16)n & 0xff) << 8) | (((__u16)n & 0xff00) >> 8)


__u32 ipsec_inet_addr(const char *cp) ;
int ipsec_inet_aton(const char *cp, struct ipsec_in_addr *addr) ;
__u8 *ipsec_inet_ntoa(__u32 addr) ;

#define ipsec_ip_addr_maskcmp(addr1, addr2, mask) ((addr1 & mask) == (addr2 & mask ))
#define ipsec_ip_addr_cmp(addr1, addr2) (addr1 == addr2)



void ipsec_print_ip(ipsec_ip_header *header);
void ipsec_dump_buffer(char *, unsigned char *, int, int);

ipsec_audit ipsec_check_replay_window(__u32 seq, __u32 lastSeq, __u32 bitField);
ipsec_audit ipsec_update_replay_window(__u32 seq, __u32 *lastSeq, __u32 *bitField);


__u16 ipsec_htons(__u16 n);
__u16 ipsec_ntohs(__u16 n);
__u32 ipsec_htonl(__u32 n);
__u32 ipsec_ntohl(__u32 n);

__u16 ipsec_ip_chksum(void *dataptr, __u16 len);

#endif

