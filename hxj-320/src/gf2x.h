/* gf2x.h.  Generated from gf2x.h.in by configure.  */
/* This file is part of the gf2x library.

   Copyright 2007, 2008, 2009, 2010, 2013, 2014, 2015
   Richard Brent, Pierrick Gaudry, Emmanuel Thome', Paul Zimmermann

   This program is free software; you can redistribute it and/or modify it
   under the terms of either:
    - If the archive contains a file named toom-gpl.c (not a trivial
    placeholder), the GNU General Public License as published by the Free
    Software Foundation; either version 3 of the License, or (at your
    option) any later version.
    - If the archive contains a file named toom-gpl.c which is a trivial
    placeholder, the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2.1 of the License, or
    (at your option) any later version.

   This program is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
   FITNESS FOR A PARTICULAR PURPOSE.  See the license text for more details.

   You should have received a copy of the GNU General Public License as
   well as the GNU Lesser General Public License along with this program;
   see the files COPYING and COPYING.LIB.  If not, write to the Free
   Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
   02110-1301, USA.
*/

/* Multiplication over GF(2)[x] */

#ifndef GF2X_H_
#define GF2X_H_

/* This section of the header file is modified by ./configure */
#define GF2X_VERSION_MAJOR 1
#define GF2X_VERSION_MINOR 3
#define GF2X_VERSION_PATCHLEVEL 0
/* For example, 10300 is gf2x-1.3.0
 * Versions before gf2x-1.3.0 had no version code */
#define GF2X_VERSION_CODE (((GF2X_VERSION_MAJOR) * 10000) + ((GF2X_VERSION_MINOR) * 100) + (GF2X_VERSION_PATCHLEVEL))

/* This is defined if gf2x was configured with --enable-fft-interface */
/* If it was, then the header file gf2x/gf2x-fft.h may be included */
/* #undef GF2X_HAS_FFT_INTERFACE_SUPPORT */

/* This is defined if gf2x was compiled from an LGPL tarball */
/* #undef GF2X_IS_LGPL_VARIANT */

/* End of the section that is modified by ./configure */

#ifndef GF2X_EXPORTED
#define GF2X_EXPORTED
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h> /* size_t */

#define GF2X_ERROR_INVALID_ARGUMENTS -1
#define GF2X_ERROR_OUT_OF_MEMORY -2

    /* This is the toplevel multiplication routine, the only one that really
     * matters. a and b point to polynomials whose coefficients span an and
     * bn machine words (unsigned longs).
     *
     * c must have enough room to hold an+bn words.
     *
     * The destination pointer c may alias either a or b (that is, one may
     * have c==a or c==b), but any other kind of overlap is unsupported).
     *
     * Returns 0 on success, or a negative error code among the GF2X_ERROR_*
     * codes above if an error occurred.
     */
    extern int GF2X_EXPORTED gf2x_mul(unsigned long *c,
                                      const unsigned long *a, unsigned long an,
                                      const unsigned long *b, unsigned long bn);

#include "parameters.h"
#include "string.h"
#include <stdint.h>
    extern void vect_mul(uint64_t *o, const uint64_t *v1, const uint64_t *v2);

    /* The second version is reentrant */
    struct gf2x_mul_pool_s
    {
        unsigned long *stk;
        size_t stk_size;
    };
    typedef struct gf2x_mul_pool_s gf2x_mul_pool_t[1];
    extern void GF2X_EXPORTED gf2x_mul_pool_init(gf2x_mul_pool_t);
    extern void GF2X_EXPORTED gf2x_mul_pool_clear(gf2x_mul_pool_t);

    /* If the gf2x_mul_pool_t arg is passed as NULL, a new pool is created
     * (and freed) for that multiplication */
    extern int GF2X_EXPORTED gf2x_mul_r(unsigned long *c,
                                        const unsigned long *a, unsigned long an,
                                        const unsigned long *b, unsigned long bn, gf2x_mul_pool_t);

    extern const char *gf2x_toom_gpl_status GF2X_EXPORTED;
    extern int gf2x_lib_version_code GF2X_EXPORTED;

    /* multiply with a guarantee than no fft (and no extra allocation) is
     * done. stk must point to at least gf2x_toomspace unsigned longs
     */
    extern void GF2X_EXPORTED gf2x_mul_toom(unsigned long *c, const unsigned long *a,
                                            const unsigned long *b, long n,
                                            unsigned long *stk);
    extern long GF2X_EXPORTED gf2x_toomspace(long n);

#ifdef __cplusplus
}
#endif

/* vim: set ft=cpp: */
#endif /* GF2X_H_ */
