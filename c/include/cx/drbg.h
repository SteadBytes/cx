/*
 * Copyright (C) 2020 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * In addition, as a special exception, the copyright holders of this
 * program give you permission to combine this program with code
 * included in the standard release of OpenSSL (or modified versions
 * of such code, with unchanged license).  You may copy and distribute
 * such a system following the terms of the GNU GPL for this program
 * and the licenses of the other code concerned.
 */

#ifndef _CX_DRBG_H
#define _CX_DRBG_H

#include <stddef.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <cx.h>

struct cx_drbg;

extern size_t cx_drbg_seed_len ( enum cx_generator_type type );

extern unsigned int cx_drbg_max_iterations ( enum cx_generator_type type );

extern struct cx_drbg *
cx_drbg_instantiate_split ( enum cx_generator_type type, const void *entropy,
			    size_t entropy_len, const void *nonce,
			    size_t nonce_len, const void *personal,
			    size_t personal_len );

extern struct cx_drbg * cx_drbg_instantiate ( enum cx_generator_type type,
					      const void *input, size_t len,
					      X509_PUBKEY *key );

extern struct cx_drbg *
cx_drbg_instantiate_fresh ( enum cx_generator_type type );

extern int cx_drbg_generate ( struct cx_drbg *drbg, void *output, size_t len );

extern void cx_drbg_invalidate ( struct cx_drbg *drbg );

extern void cx_drbg_uninstantiate ( struct cx_drbg *drbg );

#endif /* _CX_DRBG_H */
