

#ifndef GF2X_IMPL_EXPORT_H_
#define GF2X_IMPL_EXPORT_H_

#include "gf2x/gf2x-config-export.h"



#ifndef	GF2X_MAYBE_UNUSED
#if defined(__GNUC__)
#define GF2X_MAYBE_UNUSED __attribute__ ((unused))
#else
#define GF2X_MAYBE_UNUSED
#endif
#endif

#include <stdint.h>

#ifdef  GF2X_HAVE_SSE2_SUPPORT
#include <emmintrin.h>
#if defined(__GNUC__) && __GNUC__ == 4 &&__GNUC_MINOR__ == 1
#define _gf2x_mm_cvtsi64_m64(u) _mm_cvtsi64x_m64((u))
#else
#define _gf2x_mm_cvtsi64_m64(u) _mm_cvtsi64_m64((u))
#endif

#define _gf2x_mm_setr_epi64(lo, hi)                      		\
    _mm_setr_epi64(                                      		\
            _gf2x_mm_cvtsi64_m64((int64_t) (lo)),       		\
            _gf2x_mm_cvtsi64_m64((int64_t) (hi))        		\
        )

#define _gf2x_mm_set1_epi64(u) _mm_set1_epi64( _gf2x_mm_cvtsi64_m64((int64_t) (u)))

#define _gf2x_mm_setr_epi64_c(lo, hi)                    		\
    _mm_setr_epi64(                                      		\
            _gf2x_mm_cvtsi64_m64(INT64_C(lo)),          		\
            _gf2x_mm_cvtsi64_m64(INT64_C(hi))           		\
        )

#define _gf2x_mm_set1_epi64_c(u) _mm_set1_epi64( _gf2x_mm_cvtsi64_m64(INT64_C(u)))

#define _gf2x_mm_setr_epi32(a0, a1, a2, a3)				\
    _mm_setr_epi32(                                      		\
            (int32_t) (a0),						\
            (int32_t) (a1),						\
            (int32_t) (a2),						\
            (int32_t) (a3)						\
            )
#define _gf2x_mm_set1_epi32(u) _mm_set1_epi32( (int32_t) (u))
#define _gf2x_mm_setr_epi32_c(a0, a1, a2, a3)				\
    _mm_setr_epi32(                                      		\
            (INT32_C(a0)),          					\
            (INT32_C(a1)),           					\
            (INT32_C(a2)),          					\
            (INT32_C(a3))           					\
        )
#define _gf2x_mm_set1_epi32_c(u) _mm_set1_epi32(INT32_C(u))
#endif

#ifdef  GF2X_HAVE_PCLMUL_SUPPORT
#include <wmmintrin.h>
#endif

#endif	
