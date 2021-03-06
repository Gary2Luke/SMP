//=====================================================
// Inlined functions for the simpletable
//=====================================================
#include <assert.h>
#include <sys/mman.h>
#include <malloc.h>

#include "simpletable.h"

// =============================================
// Store functions
// =============================================

/*** Interface function ***/
__CPI_INLINE
void __llvm__smp_set(void **ptr_address, void *ptr_value) {

  DEBUG("[SMP] Store [%p] : %p\n", ptr_address, ptr_value);

  size_t off = tbl_offset(ptr_address);
  __CPI_TBL_SET(off, ptr_value);
}


/*** Interface function ***/
__CPI_INLINE
void __llvm__smp_assert(void **ptr_address, void *ptr_value) {

  DEBUG("[SMP] Check [%p] : %p \n", ptr_address, ptr_value);

  size_t off = tbl_offset(ptr_address);
  void *tbl_value = (void*) __CPI_TBL_GET(off);

  // If the pointer value does not match -> fail!
  if (CPI_EXPECTNOT(tbl_value != ptr_value)) {
    __llvm__smp_assert_fail();

  }

}

