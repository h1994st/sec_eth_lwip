#
# Copyright (c) 2001, 2002 Swedish Institute of Computer Science.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
# SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE.
#
# This file is part of the lwIP TCP/IP stack.
#
# Author: Adam Dunkels <adam@sics.se>
################################################################################
# Fall 2020:
#	Author: Owen Webb (owebb@umich.edu)
#	Description: Heavily modified (and simplified!) Makefile compared to the
#	lwIP original used for building example apps under contrib/

################################################################################
# Constants ####################################################################
################################################################################
CONNECTION?=0
IPSEC?=0
MACSEC?=0
ADDR_BYTE_3?=1
ADDR_BYTE_4?=1
RECEIVER_ADDR?=127.0.0.1
LOG_LEVEL?=0

CC=gcc
AR=ar

LWIPDIR=../src
LWIPARCH=unix/port
APPLIB=libapps.a
LWIPLIB=liblwip.a

################################################################################
# Define program flags #########################################################
################################################################################
LDFLAGS+=-lutil -pthread -lrt -lpcap -lwolfssl
ARFLAGS=rs

# gcc warnings
CFLAGS+=-g -DLWIP_DEBUG -Wno-error
  # -Wall -pedantic -Werror \
	# -Wparentheses -Wsequence-point -Wswitch-default \
	# -Wextra -Wundef -Wshadow -Wpointer-arith -Wcast-qual \
	# -Wc++-compat -Wwrite-strings -Wold-style-definition -Wcast-align \
	# -Wmissing-prototypes -Wredundant-decls -Wnested-externs \
	# -Wunreachable-code -Wuninitialized -Wmissing-prototypes \
	# -Wredundant-decls -Waggregate-return -Wlogical-not-parentheses

# gcc other
CFLAGS+= -Wlogical-op -Wc90-c99-compat -Wtrampolines

# include dirs
CFLAGS+=-Iinclude \
	-I$(LWIPDIR)/include \
	-I$(LWIPARCH)/include \

# define macros
CFLAGS+=-DCONNECTION=$(CONNECTION) \
	-DADDR_BYTE_3=$(ADDR_BYTE_3) \
	-DADDR_BYTE_4=$(ADDR_BYTE_4) \
	-DRECEIVER_ADDR=\"$(RECEIVER_ADDR)\"

ifeq ($(IPSEC),1)
	CFLAGS+=-DEIPS=1
else
  CFLAGS+=-DEIPS=0
endif

ifeq ($(MACSEC),1)
	CFLAGS+=-DMACSEC=1
else
	CFLAGS+=-DMACSEC=0
endif

# turn on or turn off auxiliary logs
ifeq ($(LOG_LEVEL),1)
	CFLAGS+=-DIPSEC_AUDIT -DIPSEC_MESSAGE -DIPSEC_DEBUG -DIPSEC_TRACE \
	        -DMACSEC_AUDIT -DMACSEC_MESSAGE -DMACSEC_DEBUG -DMACSEC_TRACE \
					-DLWIP_DEBUG
endif

################################################################################
# Define source files ##########################################################
################################################################################
# Application files.
APPFILES=src/eips_test.c \
	src/lwip_driver.c \
	src/default_netif.c

SENDERFILES=src/eips_test.c \
	src/lwip_sender.c \
	src/default_netif.c

RECEIVERFILES=src/eips_test.c \
	src/lwip_receiver.c \
	src/default_netif.c

ALLAPPFILES=src/eips_test.c \
	src/lwip_driver.c \
	src/lwip_sender.c \
	src/lwip_receiver.c \
	src/default_netif.c

# lwIP source files.
include $(LWIPDIR)/Filelists.mk

# Architecture specific files.
SYSARCH=$(LWIPARCH)/sys_arch.c
ARCHFILES=$(LWIPARCH)/perf.c \
	$(SYSARCH) \
	$(LWIPARCH)/netif/tapif.c \
	$(LWIPARCH)/netif/list.c \
	$(LWIPARCH)/netif/sio.c \
	$(LWIPARCH)/netif/fifo.c
LWIPFILES+=$(ARCHFILES)

################################################################################
# Build object files ###########################################################
################################################################################
LWIPOBJS=$(notdir $(LWIPFILES:.c=.o))
$(LWIPLIB): $(LWIPOBJS)
	$(AR) $(ARFLAGS) $(LWIPLIB) $?

APPOBJS=$(notdir $(APPFILES:.c=.o))
SENDEROBJS=$(notdir $(SENDERFILES:.c=.o))
RECEIVEROBJS=$(notdir $(RECEIVERFILES:.c=.o))
ALLAPPOBJS=$(notdir $(ALLAPPFILES:.c=.o))

%.o:
	$(CC) $(CFLAGS) -c $< -o $@

################################################################################
# Build header file dependencies for all object files ##########################
################################################################################
.depend: $(LWIPFILES) $(ALLAPPFILES)
	@$(CC) $(CFLAGS) -MM $^ > .depend || rm -f .depend

include .depend

################################################################################
# Primary Targets ##############################################################
################################################################################
all: app sender receiver

app: .depend $(LWIPLIB) $(APPOBJS)
	$(CC) $(CFLAGS) -o app $(APPOBJS) $(LWIPLIB) $(LDFLAGS)

sender: .depend $(LWIPLIB) $(SENDEROBJS)
	$(CC) $(CFLAGS) -o sender $(SENDEROBJS) $(LWIPLIB) $(LDFLAGS)

receiver: .depend $(LWIPLIB) $(RECEIVEROBJS)
	$(CC) $(CFLAGS) -o receiver $(RECEIVEROBJS) $(LWIPLIB) $(LDFLAGS)

clean:
	rm -f *.o $(LWIPLIB) $(APPOBJS) .depend

.PHONY: all app sender receiver clean
