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

/** @file ipsec.c
 *  @brief embedded IPsec implementation (tunnel mode with manual keying only)
 *
 *  @author Christian Scheurer <http://www.christianscheurer.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *
 * The different IPsec functions are glued together at this place. All intercepted
 * inbound and outbound traffic which require IPsec processing is passed to this module.
 * The packets are then processed processes according their SA.
 *
 *  <B>IMPLEMENTATION:</B>
 *
 * For SA management code of the sa.c module was used. Then AH and ESP functionality out of
 * ah.c and esp.c was used to process the packets properly.
 *
 *  <B>NOTES:</B>
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */



#include "ipsec/debug.h"

#include "ipsec/ipsec.h"
#include "ipsec/util.h"
#include "ipsec/sa.h"
#include "ipsec/ah.h"
#include "ipsec/esp.h"



/**
 * IPsec input processing
 *
 * This function is called by the ipsec device driver when a packet arrives having AH or ESP in the
 * protocol field. A SA lookup gets the appropriate SA which is then passed to the packet processing
 * funciton ipsec_ah_check() or ipsec_esp_decapsulate(). After successfully processing an IPsec packet
 * an check together with an SPD lookup verifies if the packet was processed acording the right SA.
 *
 * @param  packet         pointer used to access the intercepted original packet
 * @param  packet_size    length of the intercepted packet
 * @param  payload_offset pointer used to return offset of the new IP packet relative to original packet pointer
 * @param  payload_size   pointer used to return total size of the new IP packet
 * @param  databases      Collection of all security policy databases for the active IPsec device
 * @return int 			  return status code
 */
int ipsec_input_impl(unsigned char *packet, int packet_size,
                int *payload_offset, int *payload_size,
				db_set_netif *databases) {
	int ret_val 	= IPSEC_STATUS_NOT_INITIALIZED;	/* by default, the return value is undefined  */
	sad_entry 		*sa ;
	spd_entry		*spd ;
	ipsec_ip_header	*ip ;
	ipsec_ip_header	*inner_ip ;
	__u32			spi ;

	/* Log messages */
	(void)packet_size;
	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER,
	              "ipsec_input",
				  ("*packet=%p, packet_size=%d, *payload_offset=%d, *payload_size=%d",
			      (void *)packet, packet_size, (int)*payload_offset, (int)*payload_size)
				 );
	IPSEC_DUMP_BUFFER(" INBOUND ESP or AH:", packet, 0, packet_size);

	/* Only supporting 20-byte IP headers */
	if (((ipsec_ip_header*)packet)->v_hl != 0x45) {
		IPSEC_LOG_ERR("ipsec_input", IPSEC_STATUS_NOT_IMPLEMENTED, ("embeddedIPSec only supports 20-byte IPv4 headers"));
		return IPSEC_STATUS_NOT_IMPLEMENTED;
	}

	/* Get SPI from inboud packet header and lookup corresponding SA */
	ip = (ipsec_ip_header*)packet ;
	spi = ipsec_sad_get_spi(ip) ;
	sa = ipsec_sad_lookup(ip->dest, ip->protocol, spi, &databases->inbound_sad) ;

	if(sa == NULL) {
		IPSEC_LOG_AUD("ipsec_input", IPSEC_AUDIT_FAILURE, ("no matching SA found")) ;
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_input", ("return = %d", IPSEC_STATUS_FAILURE) );
		return IPSEC_STATUS_FAILURE;
	}

	/* Ensure mode is one of IPSEC_TUNNEL or IPSEC_TRANSPORT */
	if ((sa->mode != IPSEC_TUNNEL) && (sa->mode != IPSEC_TRANSPORT)) {
		IPSEC_LOG_ERR("ipsec_input", IPSEC_STATUS_FAILURE, ("bad transmission mode"));
		return IPSEC_STATUS_FAILURE;
	}

	/* Apply AH or ESP processing (according to SA) */
	if(sa->protocol == IPSEC_PROTO_AH) {
		ret_val = ipsec_ah_check((ipsec_ip_header *)packet, payload_offset, payload_size, sa);
		if(ret_val != IPSEC_STATUS_SUCCESS) {
			IPSEC_LOG_ERR("ipsec_input", ret_val, ("ah_packet_check() failed") );
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_input", ("ret_val=%d", ret_val) );
			return ret_val;
		}
	} else if (sa->protocol == IPSEC_PROTO_ESP) {
		ret_val = ipsec_esp_decapsulate((ipsec_ip_header *)packet, payload_offset, payload_size, sa);
		if(ret_val != IPSEC_STATUS_SUCCESS) {
			IPSEC_LOG_ERR("ipsec_input", ret_val, ("ipsec_esp_decapsulate() failed") );
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_input", ("ret_val=%d", ret_val) );
			return ret_val;
		}
	} else {
		IPSEC_LOG_ERR("ipsec_input", IPSEC_STATUS_FAILURE, ("invalid protocol from SA") );
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_input", ("ret_val=%d", IPSEC_STATUS_FAILURE) );
		return IPSEC_STATUS_FAILURE;
	}

	/* this if cond does not exist in the orig embeddedIPSec code. Adding because, in transport mode,
	 * the packet dat is not guaranteed to be an IP packet and thus cannot be subject to SPD processing.
	 * HOWEVER, why is SPD processing be applied to the inner packet at all? Shouldn't it be applied to
	 * the outer packet only?
	 */
	if (sa->mode == IPSEC_TUNNEL) {
		/* Get decrypted packet (ie inner packet) header */
		inner_ip = (ipsec_ip_header*)(((unsigned char*)ip) + *payload_offset);

		/* Look for a SPD entry that corresponds to the info in the decrypted packet header */
		spd = ipsec_spd_lookup(inner_ip, &databases->inbound_spd);
		if (spd == NULL) {
			IPSEC_LOG_AUD("ipsec_input", IPSEC_AUDIT_FAILURE, ("no matching SPD found"));
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_input", ("ret_val=%d", IPSEC_STATUS_FAILURE));
			return IPSEC_STATUS_FAILURE;
		}

		/* Check that the found SPD entry does indeed specify IPSec processing */
		if (spd->policy == POLICY_APPLY) {
			if (spd->sa != sa) {
				IPSEC_LOG_AUD("ipsec_input", IPSEC_AUDIT_SPI_MISMATCH, ("SPI mismatch"));
				IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_input", ("return = %d", IPSEC_AUDIT_SPI_MISMATCH));
				return IPSEC_STATUS_FAILURE;
			}
		}
		else {
			IPSEC_LOG_AUD("ipsec_input", IPSEC_AUDIT_POLICY_MISMATCH, ("matching SPD does not permit IPsec processing"));
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_input", ("return = %d", IPSEC_STATUS_FAILURE));
			return IPSEC_STATUS_FAILURE;
		}
	}
	/* Success */
	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_input", ("return = %d", IPSEC_STATUS_SUCCESS));
	return IPSEC_STATUS_SUCCESS;
}


/**
 *  IPsec output processing
 *
 * This function is called when outbound packets need IPsec processing. Depending the SA, passed via
 * the SPD entry ipsec_ah_check() and ipsec_esp_encapsulate() is called to encapsulate the packet in a
 * IPsec header.
 *
 * @param  packet         pointer used to access the intercepted original packet
 * @param  packet_size    length of the intercepted packet
 * @param  payload_offset pointer used to return offset of the new IP packet relative to original packet pointer
 * @param  payload_size   pointer used to return total size of the new IP packet
 * @param  src            IP address of the local tunnel start point (external IP address)
 * @param  dst            IP address of the remote tunnel end point (external IP address)
 * @param  spd            pointer to security policy database where the rules for IPsec processing are stored
 * @return int 			  return status code
 */
int ipsec_output_impl(unsigned char *packet, int packet_size, int *payload_offset, int *payload_size,
                 __u32 src, __u32 dst, spd_entry *spd)
{
	int ret_val = IPSEC_STATUS_NOT_INITIALIZED;		/* by default, the return value is undefined */
	ipsec_ip_header		*ip ;

	/* Only supporting 20-byte IP headers */
	if (((ipsec_ip_header*)packet)->v_hl != 0x45) {
		IPSEC_LOG_ERR("ipsec_input", IPSEC_STATUS_NOT_IMPLEMENTED, ("embeddedIPSec only supports 20-byte IPv4 headers"));
		return IPSEC_STATUS_NOT_IMPLEMENTED;
	}

	/* Log message */
	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER,
	              "ipsec_output",
				  ("*packet=%p, packet_size=%d, *payload_offset=%d, *payload_size=%d src=%u dst=%u",
			      (void *)packet, packet_size, *payload_offset, *payload_size, (__u32) src, (__u32) dst)
				 );

	/* Check that valid packet was passed */
	ip = (ipsec_ip_header*)packet;
	if((ip == NULL) || (ipsec_ntohs(ip->len) > packet_size)) {
		IPSEC_LOG_DBG("ipsec_output", IPSEC_STATUS_NOT_IMPLEMENTED, ("bad packet ip=%p, ip->len=%d (must not be >%d bytes)", (void *)ip, ipsec_ntohs(ip->len), packet_size) );
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_output", ("return = %d", IPSEC_STATUS_BAD_PACKET) );
 	    return IPSEC_STATUS_BAD_PACKET;
	}

	/* Check that valid SPD and SAD entries were passed */
	if((spd == NULL) || (spd->sa == NULL)) {
		/** @todo invoke IKE to generate a proper SA for this SPD entry */
		IPSEC_LOG_DBG("ipsec_output", IPSEC_STATUS_NOT_IMPLEMENTED, ("unable to generate dynamically an SA (IKE not implemented)") );
		IPSEC_LOG_AUD("ipsec_output", IPSEC_STATUS_NO_SA_FOUND, ("no SA or SPD defined")) ;
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_output", ("return = %d", IPSEC_STATUS_NO_SA_FOUND) );
 	    return IPSEC_STATUS_NO_SA_FOUND;
	}

	/* Apply AH or ESP processing according to the SAD entry */
	switch(spd->sa->protocol) {
		case IPSEC_PROTO_AH:
				IPSEC_LOG_MSG("ipsec_output", ("have to encapsulate an AH packet")) ;
				ret_val = ipsec_ah_encapsulate((ipsec_ip_header *)packet, payload_offset, payload_size, spd->sa, src, dst);

				if(ret_val != IPSEC_STATUS_SUCCESS)
					IPSEC_LOG_ERR("ipsec_output", ret_val, ("ipsec_ah_encapsulate() failed"));
			break;
		case IPSEC_PROTO_ESP:
				IPSEC_LOG_MSG("ipsec_output", ("have to encapsulate an ESP packet")) ;
				ret_val = ipsec_esp_encapsulate((ipsec_ip_header *)packet, payload_offset, payload_size, spd->sa, src, dst);

				if(ret_val != IPSEC_STATUS_SUCCESS)
					IPSEC_LOG_ERR("ipsec_output", ret_val, ("ipsec_esp_encapsulate() failed"));
			break;
		default:
				ret_val = IPSEC_STATUS_BAD_PROTOCOL;
				IPSEC_LOG_ERR("ipsec_output", ret_val, ("unsupported protocol '%d' in spd->sa->protocol", spd->sa->protocol));
	}

	/* Success */
	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_output", ("ret_val=%d", ret_val) );
	return ret_val;
}
