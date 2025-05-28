



#ifndef GF2X_SMALL_H_
#define GF2X_SMALL_H_

#include "gf2x.h"


#include "gf2x/gf2x-config-export.h"    
#include "gf2x/gf2x-impl-export.h"      
#include "gf2x/gf2x-thresholds.h"       

#ifdef __cplusplus
extern "C" {
#endif

GF2X_STORAGE_CLASS_mul1 void
gf2x_mul1(unsigned long *c, unsigned long a, unsigned long b)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul_1_n unsigned long
gf2x_mul_1_n(unsigned long *cp, const unsigned long *bp, long sb, unsigned long a)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_addmul_1_n unsigned long
gf2x_addmul_1_n(unsigned long *dp,
        const unsigned long *cp, const unsigned long* bp,
        long sb, unsigned long a)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul2 void
gf2x_mul2(unsigned long *c, const unsigned long *a, const unsigned long *b)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul3 void
gf2x_mul3(unsigned long *c, const unsigned long *a, const unsigned long *b)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul4 void
gf2x_mul4(unsigned long *c, const unsigned long *a, const unsigned long *b)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul5 void
gf2x_mul5(unsigned long *c, const unsigned long *a, const unsigned long *b)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul6 void
gf2x_mul6(unsigned long *c, const unsigned long *a, const unsigned long *b)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul7 void
gf2x_mul7(unsigned long *c, const unsigned long *a, const unsigned long *b)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul8 void
gf2x_mul8(unsigned long *c, const unsigned long *a, const unsigned long *b)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul9 void
gf2x_mul9(unsigned long *c, const unsigned long *a, const unsigned long *b)
        GF2X_MAYBE_UNUSED;

#ifdef __cplusplus
}
#endif


#ifndef GF2X_FUNC
#define GF2X_FUNC(x)       reserved_ ## x
#endif



#include "gf2x/gf2x_mul1.h"
#include "gf2x/gf2x_mul2.h"
#include "gf2x/gf2x_mul3.h"
#include "gf2x/gf2x_mul4.h"
#include "gf2x/gf2x_mul5.h"
#include "gf2x/gf2x_mul6.h"
#include "gf2x/gf2x_mul7.h"
#include "gf2x/gf2x_mul8.h"
#include "gf2x/gf2x_mul9.h"

#ifdef TUNING
#include "tuning_undef_wrapper.h"
#endif

#endif  
