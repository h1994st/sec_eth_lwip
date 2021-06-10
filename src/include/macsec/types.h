#ifndef __MACSEC_TYPES_H__
#define __MACSEC_TYPES_H__

#include "stdint.h"

typedef uint8_t		__u8;
typedef int8_t		__s8;
typedef uint16_t	__u16;
typedef int16_t		__s16;
typedef uint32_t	__u32;
typedef int32_t		__s32;


/** return code convention:
 *
 *  return code < 0 indicates globally defines error messages
 *  return code == 0 indicates success
 *  return code > 0 is used as error count (i.e. "return 20;" means there are 20 errors)
 *
 */
typedef enum macsec_status_list {				/** This value is returned if ... */
	MACSEC_STATUS_SUCCESS   			=  0,		/**<  processing was successful */
	MACSEC_STATUS_NOT_IMPLEMENTED 	= -1,		/**<  the function is already there but the functionality is not yet implemented */
	MACSEC_STATUS_FAILURE			= -2,		/**<  failure */
	MACSEC_STATUS_DATA_SIZE_ERROR	= -3,		/**<  buffer is (unexpectedly) empty or haves wrong size */
	MACSEC_STATUS_NO_SPACE_IN_SPD	= -4,		/**<  macsec_spd_add() failed because there was no space left in SPD */
	MACSEC_STATUS_NO_POLICY_FOUND	= -5,		/**<  no matching SPD policy was found */
	MACSEC_STATUS_NO_SA_FOUND		= -6,		/**<  no matching SA was found */
	MACSEC_STATUS_BAD_PACKET			= -7,		/**<  packet has a bad format or invalid fields */
	MACSEC_STATUS_BAD_PROTOCOL		= -8,		/**<  SA has an unsupported protocol */
	MACSEC_STATUS_BAD_KEY			= -9,		/**<  key is invalid or weak and was rejected */
	MACSEC_STATUS_TTL_EXPIRED		= -10,		/**<  TTL value of a packet reached 0 */
	MACSEC_STATUS_NOT_INITIALIZED   	= -100		/**<  variables has never been initialized */
} macsec_status;


typedef enum macsec_audit_list {					/** This value is returned if ... */
	MACSEC_AUDIT_SUCCESS   			=  0,		/**<  processing was successful */
	MACSEC_AUDIT_NOT_IMPLEMENTED 	=  1,		/**<  the function is already there but the functionality is not yet implemented */
	MACSEC_AUDIT_FAILURE				=  2,		/**<  failure  */
	MACSEC_AUDIT_APPLY				=  3,		/**<  packet must be processed by IPsec */
	MACSEC_AUDIT_BYPASS				=  4,		/**<  packet is forwarded (without IPsec processing) */
	MACSEC_AUDIT_DISCARD				=  5,		/**<  packet must be dropped */
	MACSEC_AUDIT_SPI_MISMATCH		=  6,		/**<  SPI does not match the SPD lookup */
	MACSEC_AUDIT_SEQ_MISMATCH		=  7,		/**<  Sequence Number differs more than MACSEC_SEQ_MAX_WINDOW from the previous packets */
	MACSEC_AUDIT_POLICY_MISMATCH		=  8		/**<  If a policy for an incoming IPsec packet does not specify APPLY */
} macsec_audit;


typedef enum macsec_ethernet_type_list {
	ETH_IPV4    = 0x0800,
	ETH_IPV6    = 0x86dd,
	ETH_ARP     = 0x0806,
	ETH_MACSEC  = 0x88e5
} macsec_ethernet_type;

typedef enum macsec_cipher_suite_list {
	AES_128_CBC = 0
} macsec_cipher_suite;

#pragma pack(push, 1)
/* #pragma bytealign */

typedef struct ethernet_hdr_struct
{
	__u8 dest[6];
	__u8 src[6];
	__u16 type;
} ethernet_header;

typedef struct macsec_hdr_struct
{
	__u8 dest[6];
	__u8 src[6];
	__u16 type;
	__u16 flags;
	__u32 pn;
	__u8 sci[8];
} macsec_header;

#pragma pack(pop)

#endif
