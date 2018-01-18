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
// Failure reporting functions
// =============================================

__CPI_EXPORT __CPI_NOINLINE
    __attribute__((noreturn))
    void __llvm__cpi_assert_fail() {

  fprintf(stderr, "CPI check fail\n");
  abort();

}



