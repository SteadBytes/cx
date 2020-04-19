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

/******************************************************************************
 *
 * Self-tests
 *
 ******************************************************************************
 */

#include <stdio.h>
#include "gentest.h"
#include "seedcalctest.h"
#include "preseedtest.h"

/**
 * Main entry point
 *
 * @ret exit		Exit status
 */
int main ( void ) {
	int ok = 1;

	/* Run generator self-tests */
	ok &= gentests();

	/* Run seed calculator self-tests */
	ok &= seedcalctests();

	/* Run preseed self-tests */
	ok &= preseedtests();

	/* Report failure */
	if ( ! ok ) {
		fprintf ( stderr, "Self-tests failed\n" );
		return 1;
	}

	fprintf ( stderr, "Self-tests passed\n" );
	return 0;
}
