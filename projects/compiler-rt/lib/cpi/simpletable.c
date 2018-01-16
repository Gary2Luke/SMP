#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/mman.h>

#include "simpletable.h"
#include <stdio.h>

# include <asm/prctl.h>
# include <sys/prctl.h>


int __llvm__cpi_inited = 0;
void* __llvm__cpi_table = 0;

// =============================================
// Initialization
// =============================================

/*** Interface function ***/
__attribute__((constructor(0)))
__CPI_EXPORT
void __llvm__cpi_init() {
  if (__llvm__cpi_inited)
    return;

  __llvm__cpi_inited = 1;

  __llvm__cpi_table = mmap((void*) CPI_TABLE_ADDR,
                      CPI_TABLE_NUM_ENTRIES*sizeof(tbl_entry),
                      PROT_READ | PROT_WRITE,
                      CPI_MMAP_FLAGS, -1, 0);
  if (__llvm__cpi_table == (void*) -1) {
    perror("Cannot map __llvm__cpi_dir");
    abort();
  }
  
  int res = arch_prctl(ARCH_SET_GS, __llvm__cpi_table);
  if (res != 0) {
    perror("arch_prctl failed");
    abort();
  }
  DEBUG("[CPI] Initialization completed\n");
  return;
}

__attribute__((destructor(0)))
__CPI_EXPORT
void __llvm__cpi_destroy(void) {
  DEBUG("[CPI] Finalizatoin completed\n");
}


// =============================================
// Deletion functions
// =============================================
static __attribute__((always_inline))
void __llvm__cpi_do_delete_range(unsigned char *src, size_t size) {
  DEBUG("[CPI] Do delete [%p, %p)\n", src, src + size);

  unsigned char *end = (unsigned char*)
      ((((size_t)src) + size + pointer_size-1) & pointer_mask);

  src = (void*) (((size_t) src) & pointer_mask);
  memset(tbl_address(src), 0, (end - src) * tbl_entry_size_mult);
}

/*** Interface function ***/
__CPI_EXPORT
void __llvm__cpi_delete_range(unsigned char *src, size_t size) {
  DEBUG("[CPI] Delete [%p, %p)%s%s\n", src, src + size,
        (((size_t)src)&(pointer_size-1)) ? " src misaligned":"",
        (size&(pointer_size-1)) ? " size misaligned":"");
#ifdef CPI_DO_DELETE
  __llvm__cpi_do_delete_range(src, size);
#endif // CPI_DO_DELETE
}

// =============================================
// Data movement functions
// =============================================

/*** Interface function ***/
__CPI_EXPORT
void __llvm__cpi_copy_range(unsigned char *dst, unsigned char *src,
                            size_t size) {
  DEBUG("[CPI] memcpy [%p, %p) -> [%p, %p)%s%s%s\n",
        src, src + size, dst, dst + size,
        (((size_t)src)&(pointer_size-1)) ? " src misaligned":"",
        (((size_t)dst)&(pointer_size-1)) ? " dst misaligned":"",
        (size&(pointer_size-1)) ? " size misaligned":"");

  if (CPI_EXPECTNOT((dst-src) & (pointer_size-1))) {
    // Misaligned copy; we can't support it so let's just delete dst
    __llvm__cpi_do_delete_range(dst, size);
    return;
  }

  // FIXME: in case of misaligned copy, we should clobber first and last entry
  unsigned char *src_end = (unsigned char*)
      ((((size_t)src) + size + pointer_size-1) & pointer_mask);

  src = (void*) (((size_t) src) & pointer_mask);
  memcpy(tbl_address(dst), tbl_address(src),
         (src_end - src) * tbl_entry_size_mult);
}

// ---------------------------------------------

/*** Interface function ***/
__CPI_EXPORT
void __llvm__cpi_move_range(unsigned char *dst, unsigned char *src,
                            size_t size) {
  DEBUG("[CPI] memmove [%p, %p) -> [%p, %p)%s%s%s\n",
        src, src + size, dst, dst + size,
        (((size_t)src)&(pointer_size-1)) ? " src misaligned":"",
        (((size_t)dst)&(pointer_size-1)) ? " dst misaligned":"",
        (size&(pointer_size-1)) ? " size misaligned":"");

  if (CPI_EXPECTNOT((dst-src) & (pointer_size-1))) {
    // Misaligned copy; we can't support it so let's just delete dst
    __llvm__cpi_do_delete_range(dst, size);
    return;
  }

  // FIXME: in case of misaligned copy, we should clobber first and last entry
  unsigned char *src_end = (unsigned char*)
      ((((size_t)src) + size + pointer_size-1) & pointer_mask);

  src = (void*) (((size_t) src) & pointer_mask);
  memmove(tbl_address(dst), tbl_address(src),
          (src_end - src) * tbl_entry_size_mult);
}


// =============================================
// Memory management related functions
// =============================================

/*** Interface function ***/
__CPI_EXPORT
void __llvm__cpi_realloc(unsigned char *fptr_new, unsigned long size_new,
                         unsigned char *fptr_old, unsigned long size_old) {
    if (CPI_EXPECTNOT(fptr_old == NULL || fptr_new == NULL)) {
        return;
    } else if (fptr_old == fptr_new) {

#ifdef CPI_DELETE_ON_ALLOC
        /*
        if (size_new > size_old) // enlarge
            __llvm__cpi_delete_range(fptr_old + size_new, size_old - size_new);
        */
#endif
    } else { // data was moved
        __llvm__cpi_move_range(fptr_new, fptr_old,
                               size_old < size_new ? size_old : size_new);
    }
}


// =============================================
// Failure reporting functions
// =============================================

__CPI_EXPORT __CPI_NOINLINE
    __attribute__((noreturn))
    void __llvm__cpi_assert_fail() {

  fprintf(stderr, "CPI check fail\n");
  abort();

}



