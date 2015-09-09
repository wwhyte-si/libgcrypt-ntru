/* ntru-grcrypt-wrapper.h
 * Copyright (C) 2015, Security Innovation.
 * Author Zhenfei Zhang <zzhang@securityinnovation.com>
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* This code is a wrapper for libgcrypt to be linked with libntruencrypt
 * NTRUEncrypt is a lattice-based public key encryption algorithm.
 * For the latest version of the NTRUEncrypt specs, visit
 *  https://github.com/NTRUOpenSourceProject/NTRUEncrypt
 */



#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "g10lib.h"
#include "gcrypt.h"
#include "cipher.h"
#include "bufhelp.h"
#include "gcrypt-int.h"
#include "base64.h"
#include <libntruencrypt/ntru_crypto.h>
#include "ntru-gcrypt-wrapper.h"

static const char *ntru_names[] =
{
	"ntru",
	NULL,
};

gcry_pk_spec_t _gcry_pubkey_spec_ntru = {
	GCRY_PK_NTRU,               /*  algo;                           */
	{0,0},                      /*  struct {
								    unsigned int disabled:1;
								    unsigned int fips:1;
								    } flags;                        */
	GCRY_PK_USAGE_ENCR,         /*  int use;                        */
	"ntru",                     /*  const char *name;               */
	ntru_names,                 /*  const char **aliases;           */
	NULL,                       /*  const char *elements_pkey;      */
	NULL,                       /*  const char *elements_skey;      */
	NULL,                       /*  const char *elements_enc;       */
	NULL,                       /*  const char *elements_sig;       */
	NULL,                       /*  const char *elements_grip;      */
	gcry_ntru_keygen,           /*  gcry_pk_generate_t generate;    */
	gcry_ntru_check_secret_key, /*  gcry_pk_check_secret_key_t
	                                        check_secret_key;       */
	gcry_ntru_encrypt,          /*  gcry_pk_encrypt_t encrypt;      */
	gcry_ntru_decrypt,          /*  gcry_pk_decrypt_t decrypt;      */
	NULL,                       /*  gcry_pk_sign_t sign;            */
	NULL,                       /*  gcry_pk_verify_t verify;        */
	gcry_ntru_get_nbits,        /*  gcry_pk_get_nbits_t get_nbits;  */
	NULL,						/*  selftest_func_t selftest;       */
	gcry_ntru_comp_keygrip,     /*  pk_comp_keygrip_t comp_keygrip; */
	NULL,                       /*  pk_get_curve_t get_curve;       */
	NULL                        /*  pk_get_curve_param_t
	                                       get_curve_param;         */
};

static gpg_err_code_t gcry_ntru_comp_keygrip (gcry_md_hd_t md, gcry_sexp_t keyparms)
{
    log_info("NTRU compute keygrip function not required/implemented\n");
	return 0;
}

static unsigned int gcry_ntru_get_nbits (gcry_sexp_t parms)
{
    log_info("NTRU get nbits function not required/implemented\n");
	return 0;
}
static gcry_err_code_t gcry_ntru_check_secret_key (gcry_sexp_t keyparms)
{
    log_info("NTRU check secret key function not required/implemented\n");
	return 0;
}


NTRU_ENCRYPT_PARAM_SET_ID gcry_ntru_get_param_id (gcry_sexp_t genparms)
{
    if ((_gcry_sexp_find_token(genparms, "n439", 4)!= NULL) ||
            (_gcry_sexp_find_token(genparms, "b128", 4)!= NULL))
        return     NTRU_EES439EP1;

    if ((_gcry_sexp_find_token(genparms, "n593", 4)!= NULL) ||
            (_gcry_sexp_find_token(genparms, "b192", 4)!= NULL))
        return     NTRU_EES593EP1;

    if ((_gcry_sexp_find_token(genparms, "n743", 4)!= NULL) ||
            (_gcry_sexp_find_token(genparms, "b256", 4)!= NULL))
        return     NTRU_EES743EP1;

    return -1;
}


/* Type for the pk_generate function.  */
/* typedef gcry_err_code_t (*gcry_pk_generate_t) (gcry_sexp_t genparms,
                                                  gcry_sexp_t *r_skey);*/
gcry_err_code_t gcry_ntru_keygen (gcry_sexp_t genparms, gcry_sexp_t *r_skey)
{

    NTRU_ENCRYPT_PARAM_SET_ID   paramid;
    int                         rc;                                     /* return code */
    unsigned char               *public_key;                            /* sized for EES401EP2 */
    u16                         public_key_len;                         /* no. of octets in public key */
    unsigned char               *private_key;                           /* sized for EES401EP2 */
    u16                         private_key_len;                        /* no. of octets in private key */
    DRBG_HANDLE                 drbg;                                   /* handle for instantiated DRBG */
    unsigned char               *pers_str;
    gcry_sexp_t                 temp_pk, temp_sk;

    /* start key generation */
    paramid = gcry_ntru_get_param_id (genparms);

    if (paramid <0)
    {
        log_error ("gcry_ntru: unrecognized parameter id\n");
        return GPG_ERR_INV_VALUE;
    }
/*
    if (paramid == NTRU_EES439EP1)
        printf("using NTRU_EES439EP1\n");
    if (paramid == NTRU_EES593EP1)
        printf("using NTRU_EES593EP1\n");
    if (paramid == NTRU_EES743EP1)
        printf("using NTRU_EES743EP1\n");
*/
    /* optional personal string for DRBG */

    /* use this prg for best security */
    /* pers_str    = (uint8_t*)_gcry_random_bytes (32, GCRY_STRONG_RANDOM); */

    /* use this one to improve performance */
    pers_str    = _gcry_random_bytes (32, GCRY_WEAK_RANDOM);


    public_key  = malloc (_MAX_NTRU_BUF_SIZE_);
    if (public_key  == NULL)
    {
        log_error ( "malloc failed\n");
        return(-1);
    }

    private_key = malloc (_MAX_NTRU_BUF_SIZE_);
    if (private_key  == NULL)
    {
        log_error ( "malloc failed\n");
        return(-1);
    }

    memset(public_key, 0, _MAX_NTRU_BUF_SIZE_);
    memset(private_key, 0, _MAX_NTRU_BUF_SIZE_);

    /* generating NTRU keys */

    rc = ntru_crypto_drbg_instantiate(256, pers_str, sizeof(pers_str), (ENTROPY_FN) &get_entropy, &drbg);
    if (rc!=0)
    {
        log_error ("drbg error, ntru code: %d\n", rc);
        return rc;
    }
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, paramid , &public_key_len, NULL, &private_key_len, NULL);
    if (rc!=0)
    {
        log_error ("key gen error, ntru code: %d\n", rc);
        return rc;
    }
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, paramid , &public_key_len, public_key, &private_key_len, private_key);
    if (rc!=0)
    {
        log_error ("key gen error, ntru code: %d\n", rc);
        return rc;
    }

    /* extract the key pair */
    temp_pk = convert_ntru_data_to_sexp (public_key, public_key_len);
    temp_sk = convert_ntru_data_to_sexp (private_key, private_key_len);
    rc = _gcry_sexp_build (r_skey, NULL,
         "(key-data(public-key(ntru%S))(private-key(ntru%S)))", temp_pk, temp_sk);
    if (rc!=0)
    {
        log_error ("gcry_sexp_build error: %s\n",  _gcry_strerror (rc));
        return rc;
    }

    /* _gcry_sexp_dump(*r_skey); */

    /* cleaning up */
    rc = ntru_crypto_drbg_uninstantiate(drbg);
    if (rc!=0)
    {
        log_error ("drbg error, ntru code: %d\n", rc);
        return rc;
    }
    free(public_key);
    free(private_key);
    free(pers_str);
    xfree(temp_sk);
    xfree(temp_pk);
    return rc;
}

/* Type for the pk_encrypt function.  */
/* typedef gcry_err_code_t (*gcry_pk_encrypt_t) (gcry_sexp_t *r_ciph,
                                                 gcry_sexp_t s_data,
                                                 gcry_sexp_t keyparms);*/
gcry_err_code_t gcry_ntru_encrypt (gcry_sexp_t *r_ciph, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    int             rc;
    unsigned char   *msg_buf;
    unsigned char   *key_buf;
    unsigned char   *working_buf;
    size_t          msg_len;
    size_t          key_len;
    size_t          working_buf_len;
    DRBG_HANDLE     drbg;

    working_buf = malloc (_MAX_NTRU_BUF_SIZE_);
    if (working_buf  == NULL)
    {
        log_error ("malloc failed\n");
        return(-1);
    }
    msg_buf     = malloc (_MAX_NTRU_BUF_SIZE_);
    if (msg_buf  == NULL)
    {
        log_error ("malloc failed\n");
        return(-1);
    }
    key_buf     = malloc (_MAX_NTRU_BUF_SIZE_);
    if (key_buf  == NULL)
    {
        log_error ("malloc failed\n");
        return(-1);
    }

    memset(msg_buf, 0, _MAX_NTRU_BUF_SIZE_);
    memset(key_buf, 0, _MAX_NTRU_BUF_SIZE_);
    memset(working_buf, 0, _MAX_NTRU_BUF_SIZE_);
    msg_len     = _MAX_NTRU_BUF_SIZE_;
    key_len     = _MAX_NTRU_BUF_SIZE_;
    working_buf_len = _MAX_NTRU_BUF_SIZE_;

    /* extracting the message */
    msg_buf     = _gcry_sexp_nth_data (_gcry_sexp_find_token(s_data, "value", 0), 1, &msg_len);
    /* extracting the public key; removing ntru header */
    working_buf = _gcry_sexp_nth_data (_gcry_sexp_cadr (keyparms), 0, &working_buf_len);
    base64_decode(key_buf, &key_len, working_buf+4, working_buf_len-4);

    /* performing ntru encryption */
    rc = ntru_crypto_drbg_instantiate(256, NULL, 0, (ENTROPY_FN) &get_entropy, &drbg);
    if (rc!=0)
    {
        log_error ("drbg error, ntru code: %d\n", rc);
        return rc;
    }
    rc = ntru_crypto_ntru_encrypt(drbg, key_len, key_buf, msg_len, msg_buf, &working_buf_len, NULL);
    if (rc!=0)
    {
        log_error ("encryption error, ntru code: %d\n", rc);
        return rc;
    }
    rc = ntru_crypto_ntru_encrypt(drbg, key_len, key_buf, msg_len, msg_buf, &working_buf_len, working_buf);
    if (rc!=0)
    {
        log_error ("encryption error, ntru code: %d\n", rc);
        return rc;
    }

    *r_ciph     = convert_ntru_data_to_sexp (working_buf, working_buf_len);
    /* _gcry_sexp_dump(*r_ciph); */

    /* cleaning up */
    rc = ntru_crypto_drbg_uninstantiate(drbg);
    if (rc!=0)
    {
        log_error ("drbg error, ntru code: %d\n", rc);
        return rc;
    }
    free(key_buf);

    return rc;
}



/* Type for the pk_decrypt function.  */
/* typedef gcry_err_code_t (*gcry_pk_decrypt_t) (gcry_sexp_t *r_plain,
                                                 gcry_sexp_t s_data,
                                                 gcry_sexp_t keyparms);*/
gcry_err_code_t gcry_ntru_decrypt (gcry_sexp_t *r_msg, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    int             rc;
    unsigned char   *cipher_buf;
    unsigned char   *key_buf;
    unsigned char   *working_buf;
    size_t          cipher_len;
    size_t          key_len;
    size_t          working_buf_len;
    gcry_sexp_t     key;

    working_buf = malloc (_MAX_NTRU_BUF_SIZE_);
    if (working_buf  == NULL)
    {
        log_error ("malloc failed\n");
        return(-1);
    }
    cipher_buf     = malloc (_MAX_NTRU_BUF_SIZE_);
    if (cipher_buf  == NULL)
    {
        log_error ("malloc failed\n");
        return(-1);
    }
    key_buf     = malloc (_MAX_NTRU_BUF_SIZE_);
    if (key_buf  == NULL)
    {
        log_error ("malloc failed\n");
        return(-1);
    }


    memset(cipher_buf, 0, _MAX_NTRU_BUF_SIZE_);
    memset(key_buf, 0, _MAX_NTRU_BUF_SIZE_);
    memset(working_buf, 0, _MAX_NTRU_BUF_SIZE_);
    cipher_len  = _MAX_NTRU_BUF_SIZE_;
    key_len     = _MAX_NTRU_BUF_SIZE_;
    working_buf_len = _MAX_NTRU_BUF_SIZE_;

    /* extracting the cipher; removing ntru header */
    working_buf =  _gcry_sexp_nth_data (s_data, 0, &working_buf_len);
    base64_decode(cipher_buf, &cipher_len, working_buf+4, working_buf_len-4);

    /* extracting the private key; removing ntru header */
    key         =  _gcry_sexp_cadr (keyparms);
    working_buf =  _gcry_sexp_nth_data (key, 0, &working_buf_len);
    base64_decode(key_buf, &key_len, working_buf+4, working_buf_len-4);

    /* performing ntru decryption */
    rc = ntru_crypto_ntru_decrypt(key_len, key_buf, cipher_len, cipher_buf, &working_buf_len, NULL);
    if (rc!=0)
    {
        log_error ("decryption error, ntru code: %d\n", rc);
        return rc;
    }
    rc = ntru_crypto_ntru_decrypt(key_len, key_buf, cipher_len, cipher_buf, &working_buf_len, working_buf);
    if (rc!=0)
    {
        log_error ("decryption error, ntru code: %d\n", rc);
        return rc;
    }
    working_buf[working_buf_len] = '\0';
    rc = _gcry_sexp_build (r_msg, NULL, "%s", working_buf);
    if (rc!=0)
    {
        log_error ("gcry_sexp_build error: %s\n",  _gcry_strerror (rc));
        return rc;
    }
    /* cleaning up */
    free(cipher_buf);
    free(key_buf);
    xfree(key);
    return rc;
}

/*
 * convert an ntru blob in ntru_data to a s-expression:
 * 1. convert ASCII coded ntru blob into base64 encoding string
 * 2. add guard string "NTRU" to the start of the string
 *    (if the base64 encoded string starts with a non-alphabetic
 *    char, sexp builder will bug)
 * 3. form the sexp
 */
gcry_sexp_t convert_ntru_data_to_sexp (const uint8_t* ntru_data, const size_t ntru_data_len)
{
    int             rc;
    gcry_sexp_t     sexp_data;
    unsigned char   *base64_data;
    size_t          base64_data_len;
    unsigned char   *tmp_str;

    base64_data_len = _MAX_NTRU_BUF_SIZE_;
    base64_data = malloc (ntru_data_len*2);
    if (base64_data  == NULL)
    {
        log_error ("malloc failed\n");
        return NULL;
    }
    tmp_str     = malloc (base64_data_len+2);
    if (tmp_str   == NULL)
    {
        log_error ("malloc failed\n");
        return  NULL;
    }
    rc = base64_encode(base64_data, &base64_data_len, ntru_data, ntru_data_len);

    tmp_str[0] = '(';
    tmp_str[1] = 'N';
    tmp_str[2] = 'T';
    tmp_str[3] = 'R';
    tmp_str[4] = 'U';
    memcpy(tmp_str+5, base64_data, base64_data_len);
    tmp_str[base64_data_len+5]  = ')';
    tmp_str[base64_data_len+6]  = '\0';

    rc = _gcry_sexp_sscan (&sexp_data, NULL, tmp_str, strlen(tmp_str));
    if (rc!=0)
    {
        log_error ("gcry_sexp_new: %s\n",  _gcry_strerror (rc));
        return NULL;
    }
    /* _gcry_sexp_dump(sexp_data);*/

    free(tmp_str);
    free(base64_data);
    return sexp_data;
}
/*
 *  turns out those two functions are no longer required
 *
void convert_sexp_data_to_ntru (const gcry_sexp_t sexp_data, uint8_t* ntru_data, size_t* ntru_data_len)
{
    uint8_t *buffer           = (uint8_t*) malloc(_MAX_NTRU_BUF_SIZE_);
    uint8_t *ntru_data_buf    = (uint8_t*) malloc(_MAX_NTRU_BUF_SIZE_);
    uint8_t *buffer_pt        = buffer;
    size_t  length;
    *ntru_data_len = _MAX_NTRU_BUF_SIZE_;
    _gcry_sexp_sprint (sexp_data, 3, buffer, ntru_data_len);
    int i=0;
    printf("buffer: ");
    while(buffer[i]!='\0'){
        printf("%c ",buffer[i]);i++;}
    printf("\n");
    length              = my_strlen(buffer) - 7 ;   // one for '(', four for "NTRU", one for ')', one for '\0'
    buffer_pt           = buffer+5;                 // removing the first five chars '(NTRU'
    buffer_pt [length]  = '\0';                     // removing the last char ')'

    base64_decode( (uint8_t*)ntru_data_buf, ntru_data_len, buffer_pt, length);

    free (buffer);
    free (ntru_data_buf);
}

size_t my_strlen(const uint8_t *str)
{
  size_t i;
  for (i = 0; str[i]; i++);
  return i;
}
*/

static uint8_t get_entropy( ENTROPY_CMD cmd,  uint8_t *out)
{

    int             num_bytes;
    uint8_t         *seed;
    static size_t   index;


    /*
     * dimension        number of bytes
     * 439              24
     * 593              36
     * 743              48
     */

    num_bytes = 48;

    /* use this prng for best security */
    /* uint8_t *seed = (uint8_t*)_gcry_random_bytes (num_bytes, GCRY_STRONG_RANDOM); */
    /* use this prng to improve performance */
    seed = _gcry_random_bytes (num_bytes, GCRY_WEAK_RANDOM);


    if (cmd == INIT) {
        /* Any initialization for a real entropy source goes here. */
        index = 0;
        return 1;
    }

    if (out == NULL)
        return 0;

    if (cmd == GET_NUM_BYTES_PER_BYTE_OF_ENTROPY) {
        /* Here we return the number of bytes needed from the entropy
         * source to obtain 8 bits of entropy.  Maximum is 8.
         */
        *out = 1;                       /* this is a perfectly random source */
        return 1;
    }

    if (cmd == GET_BYTE_OF_ENTROPY) {
        if (index == 128)
            return 0;                   /* used up all our entropy */

        *out = seed[index++];           /* deliver an entropy byte */
        return 1;
    }
    return 0;
}
