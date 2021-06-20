#include "lwip/opt.h"

#if defined(EIPS) && EIPS == 1

#include "ipsec/config.h"

/* -------- put statically initialized SA/SP entries and tables here -------- */
spd_entry outbound_spd[IPSEC_MAX_SPD_ENTRIES] = {
    /*           src          src mask    dst         dst mask    inner packet protocol   src port    dst port    IPSec processing flag   SPI */
#if defined(DUMMY_LOOPBACK_SA_SP) && DUMMY_LOOPBACK_SA_SP == 1
    { SPD_ENTRY( 127,0,0,1,   0,0,0,0,    127,0,0,1,  0,0,0,0,    IPSEC_PROTO_TCP,        0,          0,          POLICY_APPLY,           0) },
    { SPD_ENTRY( 127,0,0,1,   0,0,0,0,    127,0,0,1,  0,0,0,0,    IPSEC_PROTO_UDP,        0,          0,          POLICY_APPLY,           0) },
#else
    { SPD_ENTRY( 0,0,0,0,   0,0,0,0,    0,0,0,0,  0,0,0,0,    IPSEC_PROTO_TCP,        0,          0,          POLICY_APPLY,           0) },
    { SPD_ENTRY( 0,0,0,0,   0,0,0,0,    0,0,0,0,  0,0,0,0,    IPSEC_PROTO_UDP,        0,          0,          POLICY_APPLY,           0) },
#endif /* defined(DUMMY_LOOPBACK_SA_SP) && DUMMY_LOOPBACK_SA_SP == 1 */
    { 0 }
    /* { SPD_ENTRY( ... ) },
    * ...
    */
};
spd_entry inbound_spd[IPSEC_MAX_SPD_ENTRIES] = {
    /*           src          src mask    dst         dst mask    inner packet protocol   src port    dst port    IPSec processing flag   SPI */
#if defined(DUMMY_LOOPBACK_SA_SP) && DUMMY_LOOPBACK_SA_SP == 1
    { SPD_ENTRY( 127,0,0,1,   0,0,0,0,    127,0,0,1,  0,0,0,0,    IPSEC_PROTO_TCP,        0,          0,          POLICY_APPLY,           0) },
    { SPD_ENTRY( 127,0,0,1,   0,0,0,0,    127,0,0,1,  0,0,0,0,    IPSEC_PROTO_UDP,        0,          0,          POLICY_APPLY,           0) },
#else
    { SPD_ENTRY( 0,0,0,0,   0,0,0,0,    0,0,0,0,  0,0,0,0,    IPSEC_PROTO_TCP,        0,          0,          POLICY_APPLY,           0) },
    { SPD_ENTRY( 0,0,0,0,   0,0,0,0,    0,0,0,0,  0,0,0,0,    IPSEC_PROTO_UDP,        0,          0,          POLICY_APPLY,           0) },
#endif /* defined(DUMMY_LOOPBACK_SA_SP) && DUMMY_LOOPBACK_SA_SP == 1 */
    { 0 }
    /* { SPD_ENTRY( ... ) },
    * ...
    */
};

sad_entry outbound_sad[IPSEC_MAX_SAD_ENTRIES] = {
#if defined(DUMMY_LOOPBACK_SA_SP) && DUMMY_LOOPBACK_SA_SP == 1
    { SAD_ENTRY(
        127,0,0,1,              /* destination address          */
        0,0,0,0,                /* destination network mask     */
        0x1010,                 /* Security Parameter Index     */
        IPSEC_PROTO_ESP,         /* IPSec Protocol (AH or ESP)   */
        IPSEC_TRANSPORT,        /* IPSec Mode                   */
        IPSEC_AES,             /* Encryption Algorithm (followed by encryption key bytes) */
        0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
        IPSEC_HMAC_SHA256,         /* Authentication Algorithm (followed by authentication key bytes) */
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00
    ) },
#else
    { SAD_ENTRY(
        0,0,0,0,              /* destination address          */
        0,0,0,0,                /* destination network mask     */
        0x1010,                 /* Security Parameter Index     */
        IPSEC_PROTO_AH,         /* IPSec Protocol (AH or ESP)   */
        IPSEC_TRANSPORT,        /* IPSec Mode                   */
        IPSEC_AES,             /* Encryption Algorithm (followed by encryption key bytes) */
        0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
        IPSEC_HMAC_SHA256,         /* Authentication Algorithm (followed by authentication key bytes) */
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00
    ) },
#endif /* defined(DUMMY_LOOPBACK_SA_SP) && DUMMY_LOOPBACK_SA_SP == 1 */
    { 0 }
    /* { SAD_ENTRY( ... ) },
    * ...
    */
};
sad_entry inbound_sad[IPSEC_MAX_SAD_ENTRIES] = {
#if defined(DUMMY_LOOPBACK_SA_SP) && DUMMY_LOOPBACK_SA_SP == 1
    { SAD_ENTRY(
        127,0,0,1,              /* destination address          */
        0,0,0,0,                /* destination network mask     */
        0x1010,                 /* Security Parameter Index     */
        IPSEC_PROTO_ESP,         /* IPSec Protocol (AH or ESP)   */
        IPSEC_TRANSPORT,        /* IPSec Mode                   */
        IPSEC_AES,             /* Encryption Algorithm (followed by encryption key bytes) */
        0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
        IPSEC_HMAC_SHA256,         /* Authentication Algorithm (followed by authentication key bytes) */
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00
    ) },
#else
    { SAD_ENTRY(
        0,0,0,0,              /* destination address          */
        0,0,0,0,                /* destination network mask     */
        0x1010,                 /* Security Parameter Index     */
        IPSEC_PROTO_AH,         /* IPSec Protocol (AH or ESP)   */
        IPSEC_TRANSPORT,        /* IPSec Mode                   */
        IPSEC_AES,             /* Encryption Algorithm (followed by encryption key bytes) */
        0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
        IPSEC_HMAC_SHA256,         /* Authentication Algorithm (followed by authentication key bytes) */
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00
    ) },
#endif /* defined(DUMMY_LOOPBACK_SA_SP) && DUMMY_LOOPBACK_SA_SP == 1 */
    { 0 }
    /* { SAD_ENTRY( ... ) },
    * ...
    */
};
/* ------------------------------------------------------------------------- */

/* (owebb@umich.edu) Initialize the Embedded IPSec Security Policies and
 * Associations database. Statically defined policies and associations should
 * be added above */
void sa_sp_db_init(void) {
    spd_entry* free_inbound_sp;
    sad_entry* free_inbound_sa;
    spd_entry* free_outbound_sp;
    sad_entry* free_outbound_sa;

    /* Add any necessary initialization code for user-defined SA/SP entries here *
     * At the least, each SA should be associated with an SP. */
     (void)free_outbound_sp;
     (void)free_outbound_sa;
     (void)free_inbound_sp;
     (void)free_inbound_sa;
    /*
     * ...
     * ipsec_spd_add_sa(..., ...)
     * ...
     * --------------------------------------------------------------------------*/

    db = ipsec_spd_load_dbs(&inbound_spd[0], &outbound_spd[0], &inbound_sad[0], &outbound_sad[0]);

#if defined(DUMMY_LOOPBACK_SA_SP) && DUMMY_LOOPBACK_SA_SP == 1
    ipsec_spd_add_sa(&(db->inbound_spd.table[0]), &(db->inbound_sad.table[0]));
    ipsec_spd_add_sa(&(db->outbound_spd.table[0]), &(db->outbound_sad.table[0]));
    ipsec_spd_add_sa(&(db->inbound_spd.table[1]), &(db->inbound_sad.table[0]));
    ipsec_spd_add_sa(&(db->outbound_spd.table[1]), &(db->outbound_sad.table[0]));
    ipsec_spd_add_sa(&(db->inbound_spd.table[2]), &(db->inbound_sad.table[0]));
    ipsec_spd_add_sa(&(db->outbound_spd.table[2]), &(db->outbound_sad.table[0]));
    ipsec_spd_add_sa(&(db->inbound_spd.table[3]), &(db->inbound_sad.table[0]));
    ipsec_spd_add_sa(&(db->outbound_spd.table[3]), &(db->outbound_sad.table[0]));
    ipsec_spd_add_sa(&(db->inbound_spd.table[4]), &(db->inbound_sad.table[0]));
    ipsec_spd_add_sa(&(db->outbound_spd.table[4]), &(db->outbound_sad.table[0]));
    ipsec_spd_add_sa(&(db->inbound_spd.table[5]), &(db->inbound_sad.table[0]));
    ipsec_spd_add_sa(&(db->outbound_spd.table[5]), &(db->outbound_sad.table[0]));
#else
    ipsec_spd_add_sa(&(db->outbound_spd.table[0]), &(db->outbound_sad.table[0]));
    ipsec_spd_add_sa(&(db->outbound_spd.table[1]), &(db->outbound_sad.table[0]));

    ipsec_spd_add_sa(&(db->inbound_spd.table[0]), &(db->inbound_sad.table[0]));
    ipsec_spd_add_sa(&(db->inbound_spd.table[1]), &(db->inbound_sad.table[0]));
#endif /* defined(DUMMY_LOOPBACK_SA_SP) && DUMMY_LOOPBACK_SA_SP == 1 */
}

#endif /* defined(EIPS) && EIPS == 1 */
