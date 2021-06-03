#include "ipsec/config.h"

/* -------- put statically initialized SA/SP entries and tables here -------- */
spd_entry outbound_spd[IPSEC_MAX_SPD_ENTRIES] = {
    /*           src          src mask    dst         dst mask    inner packet protocol   src port    dst port    IPSec processing flag   SPI */
    #if DUMMY_LOOPBACK_SA_SP
    { SPD_ENTRY( 127,0,0,1,   0,0,0,0,    127,0,0,1,  0,0,0,0,    IPSEC_PROTO_TCP,        0,          0,          POLICY_APPLY,           0) },
    #endif /* DUMMY_LOOPBACK_SA_SP */
    { 0 }
    /* { SPD_ENTRY( ... ) },
    * ...
    */
};
spd_entry inbound_spd[IPSEC_MAX_SPD_ENTRIES] = {
    /*           src          src mask    dst         dst mask    inner packet protocol   src port    dst port    IPSec processing flag   SPI */
    #if DUMMY_LOOPBACK_SA_SP
    { SPD_ENTRY( 127,0,0,1,   0,0,0,0,    127,0,0,1,  0,0,0,0,    IPSEC_PROTO_TCP,        0,          0,          POLICY_APPLY,           0) },
    #endif /* DUMMY_LOOPBACK_SA_SP */
    { 0 }
    /* { SPD_ENTRY( ... ) },
    * ...
    */
};

sad_entry outbound_sad[IPSEC_MAX_SAD_ENTRIES] = {
    #if DUMMY_LOOPBACK_SA_SP
    { SAD_ENTRY(
        127,0,0,1,              /* destination address          */
        0,0,0,0,                /* destination network mask     */
        0x1010,                 /* Security Parameter Index     */
        IPSEC_PROTO_ESP,         /* IPSec Protocol (AH or ESP)   */
        IPSEC_TRANSPORT,        /* IPSec Mode                   */
        IPSEC_3DES,             /* Encryption Algorithm (followed by encryption key bytes) */
        0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
        IPSEC_HMAC_MD5,         /* Authentication Algorithm (followed by authentication key bytes) */
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00
    ) },
    #endif /* DUMMY_LOOPBACK_SA_SP */
    { 0 }
    /* { SAD_ENTRY( ... ) },
    * ...
    */
};
sad_entry inbound_sad[IPSEC_MAX_SAD_ENTRIES] = {
    #if DUMMY_LOOPBACK_SA_SP
    { SAD_ENTRY(
        127,0,0,1,              /* destination address          */
        0,0,0,0,                /* destination network mask     */
        0x1010,                 /* Security Parameter Index     */
        IPSEC_PROTO_ESP,         /* IPSec Protocol (AH or ESP)   */
        IPSEC_TRANSPORT,        /* IPSec Mode                   */
        IPSEC_3DES,             /* Encryption Algorithm (followed by encryption key bytes) */
        0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
        IPSEC_HMAC_MD5,         /* Authentication Algorithm (followed by authentication key bytes) */
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00
    ) },
    #endif /* DUMMY_LOOPBACK_SA_SP */
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

    #if DUMMY_LOOPBACK_SA_SP
    ipsec_spd_add_sa(&(db->inbound_spd.table[0]), &(db->inbound_sad.table[0]));
    ipsec_spd_add_sa(&(db->outbound_spd.table[0]), &(db->outbound_sad.table[0]));
    #endif /* DUMMY_LOOPBACK_SA_SP */
}
