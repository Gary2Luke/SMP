#ifndef CPI_H
#define CPI_H

// =============================================
// This file describes the implementation independet
// CPI interface.
//
// General settings:
// =============================================

#define CPI_SIMPLE_TABLE
//#define CPI_USE_HUGETLB


# define CPI_USE_SEGMENT    // Use segment register
# define CPI_MMAP_MIN_ADDR 0x1000 // Minimum mmap'able address

#define CPI_DEBUG       // Debug output
// #define CPI_NOINLINE       // Disable inlining



#define CPI_DO_DELETE      // Clean arrays on free/bzero/calloc/etc.
#define CPI_DELETE_ON_ALLOC


// #define CPI_INLINES_ONLY   // Are we compiling the inline functions only?

// =============================================
// Includes
// =============================================
#include <stdint.h>
#include <stddef.h>

// =============================================
// Common defines
// =============================================
// Visibility / inlining

// If we are not on FreeBSD, we don't compile inlines separately, only
// link the runtime, so we need to keep the "inline functions" in the module.
// This definition will prevents them from being static:
#if !defined(__FreeBSD__) && !defined(CPI_INLINES_ONLY)
# define CPI_INLINES_ONLY
#endif

#if defined(CPI_DEBUG) 
# define __CPI_INLINE __attribute__ ((noinline)) __attribute__((weak))
#elif defined(CPI_INLINES_ONLY)
# define __CPI_INLINE __attribute__((always_inline)) __attribute__((weak)) __attribute__ ((visibility ("hidden")))
#else
# define __CPI_INLINE __attribute__((always_inline)) static
#endif

#define __CPI_NOINLINE __attribute__((noinline))
#define __CPI_EXPORT __attribute__((visibility("default")))
#define __CPI_HIDDEN

// Branch prediction information
#define CPI_EXPECT(x) __builtin_expect((long) (x), 1)
#define CPI_EXPECTNOT(x) __builtin_expect((long) (x), 0)

// Mmaping
#if defined(CPI_USE_HUGETLB)
# define CPI_MMAP_FLAGS \
  (MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_HUGETLB)
# define CPI_TBL_MMAP_FLAGS \
  (MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_HUGETLB | MAP_POPULATE)
#else
# define CPI_MMAP_FLAGS \
  (MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE)
# define CPI_TBL_MMAP_FLAGS \
  (MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_POPULATE)
#endif // end if CPI_NO_HUGETLB

# define CPI_NULLTBL_MMAP_FLAGS \
  (MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED)



// Debug output
#ifdef CPI_DEBUG
# include <stdio.h>
# define DEBUG(...)                 \
    do {                            \
      fprintf(stderr, __VA_ARGS__); \
    } while (0)
#else
# define DEBUG(...) do {} while (0)
#endif // defined(CPI_DEBUG)

// =============================================
// Type definitions for the CPI interface
// =============================================

// We use vector type to store bounds because it can be loaded from memory
// slightly faster (using single instruction) and doesn't occupy general-purpose
// register when not used (it's stored in SIMD register instead).
// Note: bounds are inclusive, that is valid_addr \in [bounds[0], bounds[1]]

typedef uintptr_t __llvm__cpi_bounds
    __attribute__((vector_size(2 * sizeof(uintptr_t)),
                   aligned(2 * sizeof(uintptr_t))));

#define __llvm__cpi_bounds_infty ((__llvm__cpi_bounds) { 0UL, ~0UL })
#define __llvm__cpi_bounds_empty ((__llvm__cpi_bounds) { ~0UL, 0UL })
#define __llvm__cpi_bounds_null ((__llvm__cpi_bounds) { 0UL, 0UL })

// =============================================
// Declaration of the CPI interface functions
// =============================================

// Implementation dependent functions

__CPI_EXPORT void __llvm__cpi_init(void);

__CPI_INLINE void __llvm__cpi_set(void **fptr, void *val);

__CPI_INLINE void __llvm__cpi_assert(void **fptr, void *val);

__CPI_EXPORT void __llvm__cpi_delete_range(unsigned char *fptr, size_t size);

__CPI_EXPORT void __llvm__cpi_copy_range(unsigned char *fptr_dst,
                                         unsigned char *fptr, size_t size);
__CPI_EXPORT void __llvm__cpi_move_range(unsigned char *fptr_dst,
                                         unsigned char *fptr, size_t size);

__CPI_INLINE unsigned long __llvm__cpi_malloc_size(unsigned char *fptr);

__CPI_INLINE void __llvm__cpi_alloc(unsigned char *fptr);

__CPI_EXPORT void __llvm__cpi_realloc(unsigned char *fptr_new,
                                      unsigned long size_new,
                                      unsigned char *fptr_old,
                                      unsigned long size_old);

__CPI_EXPORT __CPI_NOINLINE void __llvm__cpi_assert_fail();


// =============================================
#endif // CPI_H
