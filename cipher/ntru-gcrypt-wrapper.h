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


#ifndef NTRU_GCRYPT_WRAPPER_H
#define NTRU_GCRYPT_WRAPPER_H


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


#ifndef _MAX_NTRU_BUF_SIZE_
#define _MAX_NTRU_BUF_SIZE_ 2000
#endif

/* NTRUEncrypt keygen function, input genparms, output a keypair in r_skey
 * sample genparms:
 * (genkey(ntru(b256))), (genkey(ntru(n743))) = 256 bits security with dimension 743
 * (genkey(ntru(b192))), (genkey(ntru(n593))) = 192 bits security with dimension 593
 * (genkey(ntru(b128))), (genkey(ntru(n439))) = 128 bits security with dimension 439
 */
gcry_err_code_t gcry_ntru_keygen (gcry_sexp_t genparms, gcry_sexp_t *r_skey);

gcry_err_code_t gcry_ntru_encrypt (gcry_sexp_t *r_ciph, gcry_sexp_t s_data, gcry_sexp_t keyparms);
gcry_err_code_t gcry_ntru_decrypt (gcry_sexp_t *r_ciph, gcry_sexp_t s_data, gcry_sexp_t keyparms);

/* data conversion: S expression <---> ntru data*/
gcry_sexp_t convert_ntru_data_to_sexp (const uint8_t* ntru_data, const size_t ntru_data_len);
/* void convert_sexp_data_to_ntru (const gcry_sexp_t sexp_data, uint8_t* ntru_data, size_t* ntru_data_len);*/

/*
 * dump functions
 */
static gpg_err_code_t gcry_ntru_comp_keygrip (gcry_md_hd_t md, gcry_sexp_t keyparms);
static unsigned int gcry_ntru_get_nbits (gcry_sexp_t parms);
static gcry_err_code_t gcry_ntru_check_secret_key (gcry_sexp_t keyparms);
/*static gcry_err_code_t gcry_ntru_self_tests (int algo, int extended, selftest_report_func_t report);*/
/*static gcry_err_code_t ntru_self_tests (selftest_report_func_t report);*/

/*
 * misc functions
 */
static uint8_t get_entropy(ENTROPY_CMD  cmd, uint8_t *out);
/*size_t my_strlen(const unsigned char *str);*/

#endif /*NTRU_GCRYPT_WRAPPER_H*/
