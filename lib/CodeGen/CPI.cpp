//===-- CPI.cpp - CPI and CPS Instrumentation Pass ------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This pass inserts CPI or CPS instumentation
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "cpi"
#include "llvm/CodeGen/Passes.h"
#include "llvm/Analysis/Dominators.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Pass.h"
#include "llvm/DebugInfo.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Target/TargetLowering.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/Target/TargetLibraryInfo.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/ADT/Triple.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/PointerIntPair.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/Support/InstIterator.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/TargetFolder.h"
#include "llvm/Support/Debug.h"

#include <vector>

// Uncomment the following to enable the runtime stats collection
// instrumentation. Remember to enable in cpi.cc in compiler-rt as well
// Both switches must be active or not at the same time!


using namespace llvm;

// Validate the result of Module::getOrInsertFunction called for an interface
// function of CPI. If the instrumented module defines a function
// with the same name, their prototypes must match, otherwise
// getOrInsertFunction returns a bitcast.
static Function *CheckInterfaceFunction(Constant *FuncOrBitcast) {
  if (isa<Function>(FuncOrBitcast)) return cast<Function>(FuncOrBitcast);
  FuncOrBitcast->dump();
  report_fatal_error("trying to redefine an CPI "
                     "interface function");
}

namespace {

// XXX: increase this!
#define CPI_LOOP_UNROLL_TRESHOLD 2


  cl::opt<bool> ShowStats("cpi-stats",
        cl::desc("Show CPI compile-time statistics"),
        cl::init(true));

  cl::opt<bool> CPIDebugMode("cpi-debug",
        cl::desc("Enable CPI debug mode"),
        cl::init(true));


  STATISTIC(NumStores, "Total number of memory stores");
  STATISTIC(NumProtectedStores, "Number of protected memory stores");

  STATISTIC(NumLoads, "Total number of memory loads");
  STATISTIC(NumProtectedLoads, "Number of protected memory loads");  

  STATISTIC(NumInitStores,
            "Total number of all initialization stores");
  STATISTIC(NumProtectedInitStores,
            "Number of all protected initialization stores");

  STATISTIC(NumCalls, "Total number of function calls");
  STATISTIC(NumIndirectCalls, "Total number of indirect function calls");
  
  STATISTIC(NumReturnAddress, "Total number of protected return address");
  STATISTIC(UnsafeStackAlloc, "Total number of UnsafeStackAlloc");
  

  static void PrintStat(raw_ostream &OS, Statistic &S) {
    OS << format("%8u %s - %s\n", S.getValue(), S.getName(), S.getDesc());
  }

  struct CPIInterfaceFunctions {
    Function *CPIInitFn;
    Function *CPISetFn;
    Function *CPIAssertFn;

  };

  class CPIPrepare : public ModulePass {
  public:
    static char ID;

    CPIPrepare() : ModulePass(ID) {
      initializeCPIPreparePass(*PassRegistry::getPassRegistry());
    }

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.addRequired<DataLayout>();
    }

    bool runOnModule(Module &M);
  };

  /** A pass that instruments every load/store that can modify pointer in a
      transitive closure of function pointers under the points-to
      relationship. */
  class CPI : public ModulePass {
    DataLayout *DL;
    TargetLibraryInfo *TLI;
    AliasAnalysis *AA;

    CPIInterfaceFunctions IF;

    bool HasCPIFullFunctions;

    DenseMap<StructType*, MDNode*> StructsTBAA;
    DenseMap<StructType*, MDNode*> UnionsTBAA;

    IntegerType *IntPtrTy;
    VectorType *BoundsTy;
    StructType *PtrValBoundsTy;
    Constant *InftyBounds;
    Constant *EmptyBounds;

    DenseMap<Function*, bool> MayBeCalledExternally;

    typedef DenseMap<PointerIntPair<Type*, 1>, bool> TypesProtectInfoTy;
    TypesProtectInfoTy StructTypesProtectInfo;
    bool shouldProtectType(Type *Ty, bool IsStore, bool CPSOnly,
                           MDNode *TBAATag = NULL);

    // Check whether a pointer Ptr needs protection
    bool shouldProtectValue(Value *Val, bool IsStore, bool CPSOnly,
                            MDNode *TBAATag = NULL, Type *RealType = NULL);

    // Check whether storage location pointed to by Ptr needs protection
    bool shouldProtectLoc(Value *Ptr, bool IsStore);    

    void buildMetadataReload(IRBuilder<true, TargetFolder> &IRB, Value *VPtr,
                             Value *EndPtr, BasicBlock *ExitBB, Value *PPt);

    void insertChecks(DenseMap<Value*, Value*> &BM,
                      Value *V, bool IsDereferenced,
                      SetVector<std::pair<Instruction*,
                                          Instruction*> > &ReplMap);

  public:
    static char ID;             // Pass identification, replacement for typeid.
    CPI() : ModulePass(ID), HasCPIFullFunctions(false) {
      initializeCPIPass(*PassRegistry::getPassRegistry());
    }

    void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.addRequired<DataLayout>();
      AU.addRequired<TargetLibraryInfo>();
      AU.addRequired<AliasAnalysis>();
    }

    bool runOnFunction(Function &F);    
    bool doCPIInitialization(Module &M);
    bool doCPIFinalization(Module &M);

    Function *createGlobalsReload(Module &M, StringRef N,
                                  bool OnlyDeclarations);

    bool mayBeCalledExternally(Function *F);

    virtual bool runOnModule(Module &M) {
      DL = &getAnalysis<DataLayout>();
      TLI = &getAnalysis<TargetLibraryInfo>();
      AA = &getAnalysis<AliasAnalysis>();

      NamedMDNode *STBAA = M.getNamedMetadata("clang.tbaa.structs");
      for (size_t i = 0, e = STBAA->getNumOperands(); i != e; ++i) {
        MDNode *MD = STBAA->getOperand(i);
        MDNode *TBAATag = dyn_cast_or_null<MDNode>(MD->getOperand(1));
        if (TBAATag)
          StructsTBAA[cast<StructType>(MD->getOperand(0)->getType())] = TBAATag;
      }

      NamedMDNode *UTBAA = M.getNamedMetadata("clang.tbaa.unions");
      for (size_t i = 0, e = UTBAA->getNumOperands(); i != e; ++i) {
        MDNode *MD = UTBAA->getOperand(i);
        MDNode *TBAATag = dyn_cast_or_null<MDNode>(MD->getOperand(1));
        if (TBAATag)
          UnionsTBAA[cast<StructType>(MD->getOperand(0)->getType())] = TBAATag;
      }

      HasCPIFullFunctions = false;

      IntPtrTy = DL->getIntPtrType(M.getContext());
      BoundsTy = VectorType::get(IntPtrTy, 2);
      PtrValBoundsTy = StructType::get(IntPtrTy, IntPtrTy, BoundsTy, NULL);      

      doCPIInitialization(M);

      // Fill in MayBeCalledExternally map
      for (Module::iterator It = M.begin(), Ie = M.end(); It != Ie; ++It) {
        Function *F = &*It;
        MayBeCalledExternally[F] = mayBeCalledExternally(F);
      }

      for (Module::iterator It = M.begin(), Ie = M.end(); It != Ie; ++It) {
        Function &F = *It;
        if (!F.isDeclaration() && !F.getName().startswith("llvm.") &&
            !F.getName().startswith("__llvm__")) {
          runOnFunction(F);
        }	
      }

      doCPIFinalization(M);

      if (ShowStats) {
        outs() << "CPI FPTR Statistics:\n";
		
        PrintStat(outs(), NumCalls);
        PrintStat(outs(), NumIndirectCalls);

        PrintStat(outs(), NumStores);
        PrintStat(outs(), NumProtectedStores);
        PrintStat(outs(), NumLoads);
        PrintStat(outs(), NumProtectedLoads);
        PrintStat(outs(), NumInitStores);
        PrintStat(outs(), NumProtectedInitStores);

		PrintStat(outs(), NumReturnAddress);
		PrintStat(outs(), UnsafeStackAlloc);
      }

      return true;
    }
  };
} // end anonymous namespace

char CPIPrepare::ID = 0;
INITIALIZE_PASS(CPIPrepare, "cpi-prepare", "CPI preparation pass", false, false)

Pass *llvm::createCPIPreparePass() {
  return new CPIPrepare();
}

char CPI::ID = 0;
INITIALIZE_PASS(CPI, "cpi", "CPI instrumentation pass", false, false)

Pass *llvm::createCPIPass() {
  return new CPI();
}

static void CreateCPIInterfaceFunctions(DataLayout *DL, Module &M,
                                         CPIInterfaceFunctions &IF) {
  LLVMContext &C = M.getContext();
  Type *VoidTy = Type::getVoidTy(C);
  Type *Int8PtrTy = Type::getInt8PtrTy(C);
  Type *Int8PtrPtrTy = Int8PtrTy->getPointerTo();   

  IF.CPIInitFn = CheckInterfaceFunction(M.getOrInsertFunction(
      "__llvm__cpi_init", VoidTy, NULL));

  IF.CPISetFn = CheckInterfaceFunction(M.getOrInsertFunction(
      "__llvm__cpi_set", VoidTy, Int8PtrPtrTy, Int8PtrTy, NULL));

  IF.CPIAssertFn = CheckInterfaceFunction(M.getOrInsertFunction(
      "__llvm__cpi_assert", VoidTy, Int8PtrPtrTy,
      Int8PtrTy, NULL)); 

}

bool CPIPrepare::runOnModule(Module &M) {
  const unsigned NumCPIGVs = sizeof(CPIInterfaceFunctions)/sizeof(Function*);
  union {
    CPIInterfaceFunctions IF;
    GlobalValue *GV[NumCPIGVs];
  };

  CreateCPIInterfaceFunctions(&getAnalysis<DataLayout>(), M, IF);

  Type *Int8PtrTy = Type::getInt8PtrTy(M.getContext());
  for (unsigned i = 0; i < NumCPIGVs; ++i) {
    if (GV[i]) appendToGlobalArray(M, "llvm.compiler.used",
                        ConstantExpr::getBitCast(GV[i], Int8PtrTy));
  }

  M.getGlobalVariable("llvm.compiler.used")->setSection("llvm.metadata");

  return true;
}

static MDNode *getNextElTBAATag(size_t &STBAAIndex, Type *ElTy,
                                const StructLayout *SL, unsigned idx,
                                MDNode *STBAATag) {
  if (ElTy->isSingleValueType() && STBAATag) {
    size_t Off = SL->getElementOffset(idx);
    size_t STBAASize = STBAATag->getNumOperands();

    // skip over embedded structs (if any)
    while (STBAAIndex+2 < STBAASize &&
           cast<ConstantInt>(STBAATag->getOperand(STBAAIndex))
              ->getValue().ult(Off)) STBAAIndex += 3;

    if (STBAAIndex+2 < STBAASize &&
        cast<ConstantInt>(STBAATag->getOperand(STBAAIndex))
          ->equalsInt(Off)) {
      // The struct type might be union, in which case we'll have >1 tags
      // for the same offset.
      if (STBAAIndex+3+2 < STBAASize &&
          cast<ConstantInt>(STBAATag->getOperand(STBAAIndex+3))
            ->equalsInt(Off)) {
        // FIXME: support unions
      } else {
        //FIXME: the following assertion seems to not hold for bitfields
        //assert(cast<ConstantInt>(STBAATag->getOperand(STBAAIndex+1))
        //       ->equalsInt(DL->getTypeAllocSize(ElTy)));
        return cast<MDNode>(STBAATag->getOperand(STBAAIndex+2));
      }
    }
  }

  return NULL;
}

bool CPI::shouldProtectType(Type *Ty, bool IsStore,
                                                 bool CPSOnly,
                                                 MDNode *TBAATag) {
  if (Ty->isFunctionTy() ||
      (Ty->isPointerTy() &&
       cast<PointerType>(Ty)->getElementType()->isFunctionTy())) {
    return true;

  } else if (Ty->isPrimitiveType() || Ty->isIntegerTy()) {
    return false;

  } else if (PointerType *PTy = dyn_cast<PointerType>(Ty)) {
    // FIXME: for unknown reason, clang sometimes generates function pointer
    // items in structs as {}* (e.g., in struct _citrus_iconv_ops). However,
    // clang keeps correct TBAA tags even in such cases, so we look at it first.
    if (IsStore && PTy->getElementType()->isStructTy() &&
        cast<StructType>(PTy->getElementType())->getNumElements() == 0 &&
        TBAATag && TBAATag->getNumOperands() > 1 &&
        cast<MDString>(TBAATag->getOperand(0))->getString() ==
            "function pointer") {
      return true;
    }   

    if (IsStore && PTy->getElementType()->isIntegerTy(8)) {
      // We want to instrument all stores of void* pointers, as those
      // might later be casted to protected pointers. Unfortunately,
      // LLVM represents all void* pointers as i8*, so we do something
      // very over-approximate here.

      if (TBAATag) {
        assert(TBAATag->getNumOperands() > 1);
        MDString *TagName = cast<MDString>(TBAATag->getOperand(0));
        return TagName->getString() == "void pointer" ||
               TagName->getString() == "function pointer";
      }

      return true;
    }

    return shouldProtectType(PTy->getElementType(), IsStore, CPSOnly);

  } else if (SequentialType *PTy = dyn_cast<SequentialType>(Ty)) {
    return shouldProtectType(PTy->getElementType(), IsStore, CPSOnly);

  } else if (StructType *STy = dyn_cast<StructType>(Ty)) {
    if (STy->isOpaque())
      return IsStore;

    TypesProtectInfoTy::key_type Key(Ty, IsStore);
    TypesProtectInfoTy::iterator TIt = StructTypesProtectInfo.find(Key);
    if (TIt != StructTypesProtectInfo.end())
      return TIt->second;

    // Avoid potential infinite recursion due to recursive types
    // FIXME: support recursive types with sensitive members
    StructTypesProtectInfo[Key] = false;

    if (MDNode *UTBAATag = UnionsTBAA.lookup(STy)) {
      // This is a union, try casting it to all components
      for (unsigned i = 0, e = UTBAATag->getNumOperands(); i+1 < e; i += 2) {
        assert(isa<UndefValue>(UTBAATag->getOperand(i)));
        assert(isa<MDNode>(UTBAATag->getOperand(i+1)));

        Type *ElTy = UTBAATag->getOperand(i)->getType();
        MDNode *ElTBAATag = cast<MDNode>(UTBAATag->getOperand(i+1));
        if (shouldProtectType(ElTy, IsStore, CPSOnly, ElTBAATag)) {
          StructTypesProtectInfo[Key] = true;
          return true;
        }
      }

      return false;
    } else {
      // Tnis is not a union, go through all fields
      MDNode *STBAATag = StructsTBAA.lookup(STy);     

      const StructLayout *SL = STBAATag ? DL->getStructLayout(STy) : NULL;
      size_t STBAAIndex = 0;

      for (unsigned i = 0, e = STy->getNumElements(); i != e; ++i) {
        Type *ElTy = STy->getElementType(i);
        MDNode *ElTBAATag =
            getNextElTBAATag(STBAAIndex, ElTy, SL, i, STBAATag);

        if (shouldProtectType(ElTy, IsStore, CPSOnly, ElTBAATag)) {
          // Cache the results to speedup future queries
          StructTypesProtectInfo[Key] = true;
          return true;
        }
      }

      return false;
    }

  } else {

    llvm_unreachable("Unhandled type");
  }
}

/// Check whether a given alloca instructino (AI) should be put on the safe
/// stack or not. The function analyzes all uses of AI and checks whether it is
/// only accessed in a memory safe way (as decided statically).
bool IsSafeStackAlloc(AllocaInst *AI, DataLayout *) {
  // Go through all uses of this alloca and check whether all accesses to the
  // allocated object are statically known to be memory safe and, hence, the
  // object can be placed on the safe stack.

  SmallPtrSet<Value*, 16> Visited;
  SmallVector<Instruction*, 8> WorkList;
  WorkList.push_back(AI);

  // A DFS search through all uses of the alloca in bitcasts/PHI/GEPs/etc.
  while (!WorkList.empty()) {
    Instruction *V = WorkList.pop_back_val();
    for (Value::use_iterator UI = V->use_begin(),
                             UE = V->use_end(); UI != UE; ++UI) {
      Use *U = &UI.getUse();
      Instruction *I = cast<Instruction>(U->getUser());
      assert(V == U->get());

      switch (I->getOpcode()) {
      case Instruction::Load:
        // Loading from a pointer is safe
        break;
      case Instruction::VAArg:
        // "va-arg" from a pointer is safe
        break;
      case Instruction::Store:
        if (V == I->getOperand(0))
          // Stored the pointer - conservatively assume it may be unsafe
          return false;
        // Storing to the pointee is safe
        break;

      case Instruction::GetElementPtr:
        if (!cast<GetElementPtrInst>(I)->hasAllConstantIndices())
          // GEP with non-constant indices can lead to memory errors
          return false;

        // We assume that GEP on static alloca with constant indices is safe,
        // otherwise a compiler would detect it and warn during compilation.

        if (!isa<ConstantInt>(AI->getArraySize()))
          // However, if the array size itself is not constant, the access
          // might still be unsafe at runtime.
          return false;

        /* fallthough */

      case Instruction::BitCast:
      case Instruction::PHI:
      case Instruction::Select:
        // The object can be safe or not, depending on how the result of the
        // BitCast/PHI/Select/GEP/etc. is used.
        if (Visited.insert(I))
          WorkList.push_back(cast<Instruction>(I));
        break;

      case Instruction::Call:
      case Instruction::Invoke: {
        CallSite CS(I);

        // Given we don't care about information leak attacks at this point,
        // the object is considered safe if a pointer to it is passed to a
        // function that only reads memory nor returns any value. This function
        // can neither do unsafe writes itself nor capture the pointer (or
        // return it) to do unsafe writes to it elsewhere. The function also
        // shouldn't unwind (a readonly function can leak bits by throwing an
        // exception or not depending on the input value).
        if (CS.onlyReadsMemory() /* && CS.doesNotThrow()*/ &&
            I->getType()->isVoidTy())
          continue;

        // LLVM 'nocapture' attribute is only set for arguments whose address
        // is not stored, passed around, or used in any other non-trivial way.
        // We assume that passing a pointer to an object as a 'nocapture'
        // argument is safe.
        // FIXME: a more precise solution would require an interprocedural
        // analysis here, which would look at all uses of an argument inside
        // the function being called.
        CallSite::arg_iterator B = CS.arg_begin(), E = CS.arg_end();
        for (CallSite::arg_iterator A = B; A != E; ++A)
          if (A->get() == V && !CS.doesNotCapture(A - B))
            // The parameter is not marked 'nocapture' - unsafe
            return false;
        continue;
      }

      default:
        // The object is unsafe if it is used in any other way.
        return false;
      }
    }
  }

  // All uses of the alloca are safe, we can place it on the safe stack.
  return true;
}


bool CPI::shouldProtectLoc(Value *Loc, bool IsStore) {
  if (!IsStore && AA->pointsToConstantMemory(Loc))
    return false; // Do not protect loads from constant memory

  SmallPtrSet<Value *, 8> Visited;
  SmallVector<Value *, 8> Worklist;
  Worklist.push_back(Loc);
  do {
    Value *P = Worklist.pop_back_val();
    P = GetUnderlyingObject(P, DL, 0);

    if (!Visited.insert(P))
      continue;

    if (SelectInst *SI = dyn_cast<SelectInst>(P)) {
      Worklist.push_back(SI->getTrueValue());
      Worklist.push_back(SI->getFalseValue());
      continue;
    }

    if (PHINode *PN = dyn_cast<PHINode>(P)) {
      for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; ++i)
        Worklist.push_back(PN->getIncomingValue(i));
      continue;
    }

    if (AllocaInst *AI = dyn_cast<AllocaInst>(P)) {
      if (!IsSafeStackAlloc(AI, DL)) {
        // Pointers on unsafe stack must be instrumented
        ++UnsafeStackAlloc;
        return true;
      }

      // Pointers on the safe stack can never be overwritten, no need to
      // instrument them.
      continue;

    } else if (isa<GlobalVariable>(P) &&
               cast<GlobalVariable>(P)->isConstant()) {
      if (IsStore) {
        errs() << "CPI: a store to a constant?\n";
        return true; // Be conservative
      }

      // Constant globals never change, no need to instrument.

    } else {
      if (IsStore || !AA->pointsToConstantMemory(P))
        return true; // Stores or non-constant loads must be instrumented

      // Do not instrument constant loads
    }

  } while (!Worklist.empty());

  return false;
}

bool CPI::shouldProtectValue(Value *Val, bool IsStore,
                                                  bool CPSOnly,
                                                  MDNode *TBAATag,
                                                  Type *RealTy) {
  return shouldProtectType(RealTy ? RealTy : Val->getType(),
                           IsStore, CPSOnly, TBAATag);
}

bool CPI::doCPIInitialization(Module &M) {
  CreateCPIInterfaceFunctions(DL, M, IF);  
  return true;
}

bool CPI::mayBeCalledExternally(Function *F) {
  // FIXME: the following is only a heuristic...

  SmallSet<Value*, 16> Visited;
  SmallVector<Value*, 16> WorkList;
  WorkList.push_back(F);

  while (!WorkList.empty()) {
    Value *V = WorkList.pop_back_val();

    for (Value::use_iterator I = V->use_begin(),
                             E = V->use_end(); I != E; ++I) {
      User *U = *I;
      if (isa<BlockAddress>(U))
        continue;

      CallSite CS(U);
      if (CS) {
        if (CS.getCalledValue() != V && CS.getCalledFunction() &&
            CS.getCalledFunction()->isDeclaration())
          // May be passed to an external function
          return true;

        continue;
      }

      Operator *OP = dyn_cast<Operator>(U);
      if (OP) {
        switch (OP->getOpcode()) {
        case Instruction::BitCast:
        case Instruction::PHI:
        case Instruction::Select:
          if (Visited.insert(U))
            WorkList.push_back(U);
          break;
        default:
          break;
        }
      }
    }
  }

  return false;
}

#warning FIXME: this should take CPSOnly as an argument
void CPI::buildMetadataReload(
                IRBuilder<true, TargetFolder> &IRB, Value *VPtr,
                Value *EndPtr, BasicBlock *ExitBB, Value *PPt) {
  assert(VPtr->getType()->isPointerTy());

  Type *VTy = cast<PointerType>(VPtr->getType())->getElementType();

  if (isa<PointerType>(VTy)) {
    assert((cast<PointerType>(VTy)->getElementType()->isStructTy() &&
            cast<StructType>(cast<PointerType>(VTy)->getElementType())
              ->getNumElements() == 0)/* FIXME: requires TBAATag */
           || shouldProtectType(VTy, true, false));

   
  
    IRB.CreateCall2(IF.CPISetFn,
        IRB.CreatePointerCast(VPtr, IRB.getInt8PtrTy()->getPointerTo()),
        IRB.CreatePointerCast(IRB.CreateLoad(VPtr), IRB.getInt8PtrTy()));

  } else if (ArrayType *STy = dyn_cast<ArrayType>(VTy)) {
    if (isa<CompositeType>(STy->getElementType())) {
      if (STy->getArrayNumElements() <= CPI_LOOP_UNROLL_TRESHOLD) {
        for (uint64_t i = 0, e = STy->getArrayNumElements(); i != e; ++i) {
          Value *Idx[2] = { IRB.getInt64(0), IRB.getInt64(i) };
          buildMetadataReload(IRB, IRB.CreateGEP(VPtr, Idx),
                              EndPtr, ExitBB, PPt);
        }
      } 
    }

  } else if (VectorType *VecTy = dyn_cast<VectorType>(VTy)) {
    if (isa<CompositeType>(VecTy->getElementType())) {
      for (uint64_t i = 0, e = VecTy->getNumElements(); i != e; ++i) {
        Value *Idx[2] = { IRB.getInt64(0), IRB.getInt64(i) };
        buildMetadataReload(IRB, IRB.CreateGEP(VPtr, Idx), EndPtr, ExitBB, PPt);
      }
    }

  } else if (StructType *STy = dyn_cast<StructType>(VTy)) {
    if (MDNode *UTBAATag = UnionsTBAA.lookup(STy)) {
      // This is a union, try casting it to all components
      for (unsigned i = 0, e = UTBAATag->getNumOperands(); i+1 < e; i += 2) {
        assert(isa<UndefValue>(UTBAATag->getOperand(i)));
        assert(isa<MDNode>(UTBAATag->getOperand(i+1)));

        Type *ElTy = UTBAATag->getOperand(i)->getType();
        MDNode *ElTBAATag = cast<MDNode>(UTBAATag->getOperand(i+1));
        if (shouldProtectType(ElTy, true, false, ElTBAATag)) {
          buildMetadataReload(IRB,
                              IRB.CreateBitCast(VPtr, ElTy->getPointerTo()),
                              EndPtr, ExitBB, PPt);
          // FIXME: more than one field might contain metadata
          return;
        }
      }

    } else {
      MDNode *STBAATag = StructsTBAA.lookup(STy);
      const StructLayout *SL = STBAATag ? DL->getStructLayout(STy) : NULL;
      size_t STBAAIndex = 0;

      for (unsigned i = 0, e = STy->getNumElements(); i != e; ++i) {
        Type *ElTy = STy->getElementType(i);
        MDNode *ElTBAATag =
            getNextElTBAATag(STBAAIndex, ElTy, SL, i, STBAATag);
        if (shouldProtectType(ElTy, true, false, ElTBAATag)) {
          Value *Idx[2] = { IRB.getInt64(0), IRB.getInt32(i) };
          buildMetadataReload(IRB, IRB.CreateGEP(VPtr, Idx),
                              EndPtr, ExitBB, PPt);
        }
      }
    }
  }
}

static bool isUsedAsFPtr(Value *FPtr) {
  // XXX: in povray spec benchmark, llvm creates spurious loads of
  // function pointers when it casts some classes into freelists.
  // We avoid this by checking whether the loaded value actually ends
  // up being used as a function pointer later on.

  SmallVector<Value*, 16> WorkList;
  WorkList.push_back(FPtr);

  while (!WorkList.empty()) {
    Value *Val = WorkList.pop_back_val();
    for (Value::use_iterator It = Val->use_begin(),
                             Ie = Val->use_end(); It != Ie; ++It) {
      User *U = *It;
      if (CastInst *CI = dyn_cast<CastInst>(U)) {
        if (PointerType *PTy = dyn_cast<PointerType>(CI->getType()))
          if (PTy->getElementType()->isFunctionTy())
            return true; // cast to another function pointer type
      } else if (isa<CmpInst>(U)) {
        continue;
      } else if (isa<PHINode>(U) || isa<SelectInst>(U)) {
        WorkList.push_back(U);
      } else {
        // Any non-cast instruction
        return true;
      }
    }
  }

  // FPtr is only used in cast insts to non-function-pointer types
  return false;
}

void CPI::insertChecks(DenseMap<Value*, Value*> &BM,
        Value *V, bool IsDereferenced,
        SetVector<std::pair<Instruction*, Instruction*> > &ReplMap) {
  if (BM.count(V)) {
    return; // Already visited
  }

  BM[V] = NULL;
  if (LoadInst *LI = dyn_cast<LoadInst>(V)) {
    // Check whether our load is of instrumentable type
    // and is from instrumentable location
    if (LI->getType()->isPointerTy() &&
        !LI->getMetadata("vaarg.load") &&
        shouldProtectLoc(LI->getPointerOperand(), false) &&
        shouldProtectValue(LI, /* IsStore= */ false, /* CPSOnly = */ true,
                           LI->getMetadata(LLVMContext::MD_tbaa)) &&        
        isUsedAsFPtr(V)) {

      ++NumProtectedLoads;
      IRBuilder<> IRB(LI->getNextNode());
      IRB.SetCurrentDebugLocation(LI->getDebugLoc());
            
        IRB.CreateCall2(IF.CPIAssertFn,
              IRB.CreatePointerCast(LI->getPointerOperand(),
                                    IRB.getInt8PtrTy()->getPointerTo()),
              IRB.CreatePointerCast(LI, IRB.getInt8PtrTy()));
     
    }

  } else if (isa<CallInst>(V) || isa<InvokeInst>(V) || isa<Argument>(V) ||
             isa<AllocaInst>(V) || isa<Constant>(V)) {
    // Do nothing
  } else if (PHINode *PHI = dyn_cast<PHINode>(V)) {
    unsigned N = PHI->getNumIncomingValues();
    for (unsigned i = 0; i < N; ++i)
      insertChecks(BM, PHI->getIncomingValue(i), IsDereferenced, ReplMap);
  } else if (SelectInst *SI = dyn_cast<SelectInst>(V)) {
    insertChecks(BM, SI->getTrueValue(), IsDereferenced, ReplMap);
    insertChecks(BM, SI->getFalseValue(), IsDereferenced, ReplMap);
  } else if (BitCastInst *CI = dyn_cast<BitCastInst>(V)) {
    insertChecks(BM, CI->getOperand(0), IsDereferenced, ReplMap);
  } else if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(V)) {
    insertChecks(BM, GEP->getPointerOperand(), IsDereferenced, ReplMap);
  } else if (isa<IntToPtrInst>(V)) {
    // XXX: this happens when the program contains unions with ints and fptrs.
    // When program stores ints to the union, LLVM sometimes transformes it
    // into casting an int to fptr and then storing the fptr. We should fix it
    // by either adding metadata or disabling such transformations. For now,
    // let's silently allow it.

  } else if (isa<InlineAsm>(V)) {
    // XXX: we can't do much about inline asm. Perhaps we should warn the user ?

  }
}

bool CPI::runOnFunction(Function &F) {
  LLVMContext &C = F.getContext();

  bool CPSOnly;
  if (F.hasFnAttribute("cpi")) {
    assert(!F.hasFnAttribute("cps"));
    F.addFnAttr("has-cpi");
    CPSOnly = false;
    HasCPIFullFunctions = true;
  } else if (F.hasFnAttribute("cps")) {
    assert(!F.hasFnAttribute("cpi"));
    F.addFnAttr("has-cps");
    CPSOnly = true;
  } else {
    return false;
  }

  {
    AttrBuilder B; B.addAttribute("cps").addAttribute("cpi").addAttribute(Attribute::SafeStack);
    F.removeAttributes(AttributeSet::FunctionIndex,
        AttributeSet::get(C, AttributeSet::FunctionIndex, B));
  }

  Type *Int8PtrTy = Type::getInt8PtrTy(C);
  Type *Int8PtrPtrTy = Int8PtrTy->getPointerTo();


  // A list of all values that require bounds information
  SetVector<Value*> NeedBounds;

  // Store each value from NeedBounds that is dereferenced in the code.
  // For such values, the metadata get code might be simplified by allowing it
  // to crash when the metadata is absent or null.
  SmallPtrSet<Value*, 64> IsDereferenced;

  // A list of (insert point, loc, var) of all places where bounds
  // should be stored.
  std::vector<std::pair<Instruction*,
      std::pair<Value*, Value*> > > BoundsSTabStores;

  // A listof (insert point, idx, var) of all places where argument bounds
  // should be stored. Empty for CPSOnly.
  std::vector<std::pair<Instruction*,
      std::pair<unsigned, Value*> > > BoundsArgsStores;

  // A list of (insert point, var, size) of all places where bounds checks
  // should be inserted. Empty for CPSOnly.
  std::vector<std::pair<Instruction*,
      std::pair<Value*, uint64_t> > > BoundsChecks;

  // Collect all values that require bounds information
  for (inst_iterator It = inst_begin(F), Ie = inst_end(F); It != Ie; ++It) {
    Instruction *I = &*It;

    if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
      ++NumLoads;
      // On load, we do NOT check whether to protect the loaded value or not.
      // Instead, we will protect it only if used in a context that requires
      // protection. E.g. imagine we do p->q->i = 0. Even if p and p->q requires
      // protection, we will only insert it if p->q->i also needs it.

      // However, in CPS mode, we do check the vtable ptr load
      // instructions and instrument them.
      if (CPSOnly) {
        MDNode *TBAATag = LI->getMetadata(LLVMContext::MD_tbaa);
        if (TBAATag &&
            cast<MDString>(TBAATag->getOperand(0))
              ->getString() == "vtable pointer") {
          NeedBounds.insert(LI);
          IsDereferenced.insert(LI);
        }
      }


    } else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
      ++NumStores;
      // If we store a protected value, then we need to make sure the store
      // address is protected, and also store the protection information
      // for the store value.
#warning support aggregate stores
      if (SI->getValueOperand()->getType()->isPointerTy() &&
          (shouldProtectValue(SI->getValueOperand(), true, CPSOnly,
                              SI->getMetadata(LLVMContext::MD_tbaa)) ||
           // XXX: the optimizer sometimes lifts the bitcast out of the store
           (isa<Operator>(SI->getValueOperand()) &&
            cast<Operator>(SI->getValueOperand())->getOpcode() ==
              Instruction::BitCast &&
            shouldProtectValue(
              cast<Operator>(SI->getValueOperand())->getOperand(0),
              true, CPSOnly)))) {
        

        // Store bounds information for the stored value
        NeedBounds.insert(SI->getValueOperand());
        BoundsSTabStores.push_back(std::make_pair(SI,
            std::make_pair(SI->getPointerOperand(), SI->getValueOperand())));
      }
    } else if (isa<CallInst>(I) || isa<InvokeInst>(I)) {
      // If we call through a pointer, check the pointer
      CallSite CS(I);
      if (!isa<Constant>(CS.getCalledValue())) {
        NeedBounds.insert(CS.getCalledValue());
        IsDereferenced.insert(CS.getCalledValue());
      }

      Function *CF = CS.getCalledFunction();

      if (CF && (CF->getName().startswith("llvm.") ||
                 CF->getName().startswith("__llvm__")))
        continue;

      ++NumCalls;
	 // errs().write_escaped(F.getName()) << "  call  " << CF->getName() << '\n';
	//outs() << F.getName() << "  call  " << CF->getName() << '\n';
	
      if (!isa<Constant>(CS.getCalledValue()))
        ++NumIndirectCalls;

      for (unsigned i = 0, e = CS.arg_size(); i != e; ++i) {
        Value *A = CS.getArgument(i);
        if (shouldProtectValue(A, true, CPSOnly)) {
          // If we pass a value that needs protection as an arg, check it
          if (!isa<Constant>(A))
            NeedBounds.insert(A);
          
        }
      }
    } else if (ReturnInst *RI = dyn_cast<ReturnInst>(I)) {
      Value *RV = RI->getReturnValue();
      if (RV && !isa<Constant>(RV) && shouldProtectValue(RV, true, CPSOnly)) {
        // If we return a value that needs protectoin, check it
        NeedBounds.insert(RV);
       
      }
    }
  }

  // Cache bounds information for every value in the function
  DenseMap<Value*, Value*> BoundsMap;
  SetVector<std::pair<Instruction*, Instruction*> > ReplMap;

  if (CPSOnly) {
    // Insert load checks along the way, using BoundsMap as a visited set
    for (unsigned i = 0, e = NeedBounds.size(); i != e; ++i)
      insertChecks(BoundsMap, NeedBounds[i],
                   IsDereferenced.count(NeedBounds[i]), ReplMap);
  } 

  // Add stab values and bounds stores
  for (unsigned i = 0, e = BoundsSTabStores.size(); i != e; ++i) {
    IRBuilder<> IRB(BoundsSTabStores[i].first);
    
    Value *Loc = IRB.CreateBitCast(BoundsSTabStores[i].second.first,
                                   Int8PtrPtrTy);
    Value *Val = IRB.CreateBitCast(BoundsSTabStores[i].second.second,
                                   Int8PtrTy);

    ++NumProtectedStores;
    if (CPSOnly) {
      IRB.CreateCall2(IF.CPISetFn, Loc, Val);
    } 
  }  

 
/*  /shadow stack failed??*/

    for (Function::iterator I = F.begin(), E = F.end(); I != E;) {
	  Module *MM = F.getParent();
	  BasicBlock *BB = &*I++;
	  ReturnInst *RI = dyn_cast<ReturnInst>(BB->getTerminator());
	  if (!RI)
		continue;
	  IRBuilder<> B2(&F.getEntryBlock().front());
	  Value *RetAddr = B2.CreateCall(Intrinsic::getDeclaration(MM, Intrinsic::returnaddress),B2.getInt32(0), "returnaddr");
	  Value *Loc = B2.CreateBitCast(RetAddr, Int8PtrPtrTy);
	  Value *Val = B2.CreateBitCast(RetAddr, Int8PtrTy);		  	  
          B2.CreateCall2(IF.CPISetFn, Loc, Val);

	  IRBuilder<> Builder2(RI);	  
	  Builder2.CreateCall2(IF.CPIAssertFn, Loc, Val);
	  	
	  ++NumReturnAddress;
	/*有问题 一个函数插桩的返回地址检查不止一个？？？？  没问题 貌似是函数优化的问题,将一些函数合并了*/
/*

	  StringRef AsmStore = "addq $$0x8, %fs:0x28\n\t";// this stack grows up
 	  StringRef ConStore = "";
 	  FunctionType* FtStore = FunctionType::get(Type::getVoidTy(F.getContext()),{}, false);
 	  InlineAsm* Store = InlineAsm::get(FtStore, AsmStore, ConStore, false, false, InlineAsm::AD_ATT);
 	  Builder2.CreateCall(Store);
  */        

	/*不能清0，会出错（例如一个函数调用自己）*/
	  //errs().write_escaped(F.getName()) << "  ret" << '\n';
	  //Value *const222 = Builder2.getInt64(0x0);
	  //Value *Val222 = Builder2.CreateIntToPtr(const222, Int8PtrTy, "aa");
	  //Builder2.CreateCall2(IF.CPISetFn, Loc, Val222);
	  return true;
   }
          
 

  return true;
}

Function *CPI::createGlobalsReload(Module &M, StringRef N,
                                                        bool OnlyDeclarations) {
  LLVMContext &C = M.getContext();
  Function *F = Function::Create(
      FunctionType::get(Type::getVoidTy(C), false),
      GlobalValue::InternalLinkage, N, &M);

  TargetFolder TF(DL);
  IRBuilder<true, TargetFolder> IRB(C, TF);

  BasicBlock *Entry = BasicBlock::Create(C, "", F);
  IRB.SetInsertPoint(Entry);

  IRB.CreateCall(IF.CPIInitFn);
  
  Value *PPt = NULL;  
  IRB.CreateRetVoid();
  IRB.SetInsertPoint(IRB.GetInsertBlock(),
                     IRB.GetInsertBlock()->getTerminator());

  for (Module::global_iterator It = M.global_begin(),
                               Ie = M.global_end(); It != Ie; ++It) {
    GlobalVariable *GV = &*It;

    if (GV->getName().startswith("llvm.") ||
        GV->getName().startswith("__llvm__"))
      continue;

    if (OnlyDeclarations && !GV->isDeclaration())
      continue;

    ++NumInitStores;

    // FIXME: in fact, we might not want to protect i8 pointers when
    // loading globals, as those are likely to have correct type anyway.
    if (!shouldProtectType(GV->getType()->getElementType(), true, false)) {
                           //!HasCPIFullFunctions)) {
      //outs() << "NOT Protect: " << GV->getName() << "\n";
      continue;
    }

    ++NumProtectedInitStores;

    //outs() << "Protect: " << GV->getName() << "\n";
    buildMetadataReload(IRB, GV, NULL, NULL, PPt);
  }

  return F;
}

bool CPI::doCPIFinalization(Module &M) {
  Function *F1 = createGlobalsReload(M, "__llvm__cpi.module_init", false);
  appendToGlobalCtors(M, F1, 0);


  // FIXME: this is a hack that only works with lto
  if (HasCPIFullFunctions) {
    Function *Main = M.getFunction("main");
    if (Main != NULL && !Main->isDeclaration()) {
      Function *F2 = createGlobalsReload(M,
                                         "__llvm__cpi.module_pre_main", true);
      F2->addFnAttr(Attribute::NoInline);
      CallInst::Create(F2, Twine(),
                 cast<Instruction>(Main->getEntryBlock().getFirstNonPHI()));
    }
  }

  
  return true;
}
