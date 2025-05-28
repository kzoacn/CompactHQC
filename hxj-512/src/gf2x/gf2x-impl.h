

#ifndef GF2X_IMPL_H_
#define GF2X_IMPL_H_

#include "gf2x.h"

#include "gf2x/gf2x-impl-export.h"


#include "gf2x/gf2x-config.h"
#include "gf2x/gf2x-thresholds.h"


#define	GF2X_SELECT_KARA	0	
#define	GF2X_SELECT_TC3		1
#define	GF2X_SELECT_TC3W	2
#define	GF2X_SELECT_TC4		3
#define	GF2X_SELECT_KARAX	4
#define	GF2X_SELECT_TC3X	5

#define	GF2X_SELECT_UNB_DFLT	0
#define	GF2X_SELECT_UNB_TC3U	1	

#include <assert.h>
#ifndef ASSERT
#define ASSERT(x)	assert(x)
#endif


#ifndef GF2X_ATTRIBUTE_WARN_UNUSED_RESULT

#ifndef GF2X_GNUC_VERSION_ATLEAST
#define GF2X_LEXGE2(X,Y,A,B) (X>A || (X == A && Y >= B))
#define GF2X_LEXGE3(X,Y,Z,A,B,C) (X>A || (X == A && GF2X_LEXGE2(Y,Z,B,C)))
#define GF2X_LEXLE2(X,Y,A,B) GF2X_LEXGE2(A,B,X,Y)
#define GF2X_LEXLE3(X,Y,Z,A,B,C) GF2X_LEXGE3(A,B,C,X,Y,Z)
#ifndef GF2X_GNUC_VERSION_ATLEAST
#ifndef __GNUC__
#define GF2X_GNUC_VERSION_ATLEAST(X,Y,Z) 0
#else
#define GF2X_GNUC_VERSION_ATLEAST(X,Y,Z)     \
    GF2X_LEXGE3(__GNUC__,__GNUC_MINOR__,__GNUC_PATCHLEVEL__,X,Y,Z)
#endif
#endif
#endif
#if GF2X_GNUC_VERSION_ATLEAST(3,4,0)
#define GF2X_ATTRIBUTE_WARN_UNUSED_RESULT __attribute__ ((warn_unused_result))
#else
#define GF2X_ATTRIBUTE_WARN_UNUSED_RESULT
#endif
#endif
#ifndef MAX
#define MAX(a,b)        ((a)<(b) ? (b) : (a))
#endif


#ifdef __cplusplus
extern "C" {
#endif

extern long gf2x_toomuspace(long n);

extern void gf2x_mul_basecase_inner(unsigned long * c, const unsigned long * a,
			 long na, const unsigned long * b, long nb);
#if GF2X_GNUC_VERSION_ATLEAST(3, 4, 0)
#define gf2x_is_static_true(x) (__builtin_constant_p((x)) && (x))
#define gf2x_static_assert(name, x) char name[gf2x_is_static_true(x)] GF2X_MAYBE_UNUSED
#else
#define gf2x_static_assert(name, x) 
#endif
#define gf2x_mul_basecase(c,a,na,b,nb) do {			        \
    if (MAX(na, nb) >= GF2X_MUL_KARA_THRESHOLD) {  \
        fprintf(stderr, "Error: MAX(%ld,%ld) >= %d\n", na, nb, GF2X_MUL_KARA_THRESHOLD); \
        abort(); \
    } \
    gf2x_mul_basecase_inner(c, a, na, b, nb);				\
} while (0)

extern void gf2x_mul_kara(unsigned long *c, const unsigned long *a, const unsigned long *b,
			long n, unsigned long *stk);
#if GF2X_HAVE_SSE2_SUPPORT && (GF2X_WORDSIZE == 64)
#define HAVE_KARAX
extern void gf2x_mul_karax(unsigned long *c, const unsigned long *a, const unsigned long *b,
                           long n, unsigned long *stk);
extern void gf2x_mul_tc3x(unsigned long *c, const unsigned long *a, const unsigned long *b,
                          long n, unsigned long *stk);
#endif
#if GPL_CODE_PRESENT
extern void gf2x_mul_tc3(unsigned long *c, const unsigned long *a, const unsigned long *b,
		 	long n, unsigned long *stk);
extern void gf2x_mul_tc3w(unsigned long *c, const unsigned long *a, const unsigned long *b,
		        long n, unsigned long *stk);
extern void gf2x_mul_tc4(unsigned long *c, const unsigned long *a, const unsigned long *b,
			long n, unsigned long *stk);
extern void gf2x_mul_tc3u(unsigned long * c, const unsigned long * a, long sa,
	      const unsigned long * b, unsigned long * stk);
#endif 

extern short gf2x_best_toom(unsigned long);

extern short gf2x_best_utoom(unsigned long);






#define GF2X_MUL_FFT_MINIMUM_SIZE GF2X_TERNARY_FFT_MINIMUM_SIZE

extern int gf2x_mul_fft(unsigned long *c, const unsigned long *a, size_t an,
		            const unsigned long *b, size_t bn, long K)
                        GF2X_ATTRIBUTE_WARN_UNUSED_RESULT;



extern short best_tab[GF2X_TOOM_TUNING_LIMIT];
extern short best_utab[GF2X_TOOM_TUNING_LIMIT];

#ifdef __cplusplus
}
#endif

#endif	
