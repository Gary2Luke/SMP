#ifndef CPI_SIMPLE_TABLE_H
#define CPI_SIMPLE_TABLE_H

#include "cpi.h"

//-----------------------------------------------
// Type definitions
//-----------------------------------------------

typedef struct {
  void *ptr_value;
} tbl_entry;

//-----------------------------------------------
// Constants
//-----------------------------------------------

#ifdef __x86_64__

# if defined(__gnu_linux__)
// The following mask works for linux, it maps typical address space into
// a rage of non-overlapping addresses between 0 and 1<<40.
#  define CPI_ADDR_MASK (0x00fffffffff8ull) // this is ((1<<40)-1)&~7
#  define CPI_TABLE_NUM_ENTRIES (1ull<<(40 - 3))
#  define CPI_TABLE_ADDR (1ull<<45)
# else
#  error Not implemented yet
# endif

#define alignment_bits 3
#endif //  __x86_64__

#define pointer_size sizeof(void *)
#define pointer_mask (~(pointer_size-1))
#define tbl_entry_size_mult (sizeof(tbl_entry) / pointer_size)

// =============================================
// Global variable declarations
// =============================================
extern int __llvm__cpi_inited;


# define IMM_MODE "ir"

# define __CPI_TBL_GET(off)    \
  ({ size_t val;                \
      __asm__ volatile ("movq %%gs:(%1),%0"  \
               : "=r" (val)         \
               : "r" (off));        \
     val; })

# define __CPI_TBL_SET(off, val)                     \
  do { __asm__ volatile ("movq %0,%%gs:(%1)" :        \
                         : IMM_MODE (val),            \
                         "r" (off));                  \
  } while(0)



//-----------------------------------------------
// Helper functions for indexing
//-----------------------------------------------
#define tbl_offset(ptr_address) \
  ((((size_t)(ptr_address)) & CPI_ADDR_MASK) * tbl_entry_size_mult)

#define tbl_address(ptr_address) \
  ((tbl_entry*) (((char*) __llvm__cpi_table) + tbl_offset(ptr_address)))

#endif // CPI_SIMPLE_TABLE_H
