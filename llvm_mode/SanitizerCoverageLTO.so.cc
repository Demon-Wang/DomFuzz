/* SanitizeCoverage.cpp ported to afl++ LTO :-) */

#define AFL_LLVM_PASS

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

#include <list>
#include <string>
#include <fstream>
#include <set>
#include <iostream>

#include "llvm/Transforms/Instrumentation/SanitizerCoverage.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/EHPersonalities.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Mangler.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "../config.h"
#include "../debug.h"
#include "afl-llvm-common.h"

using namespace llvm;

#define DEBUG_TYPE "sancov"

const char SanCovTracePCIndirName[] = "__sanitizer_cov_trace_pc_indir";
const char SanCovTracePCName[] = "__sanitizer_cov_trace_pc";
// const char SanCovTracePCGuardName =
//    "__sanitizer_cov_trace_pc_guard";
const char SanCovGuardsSectionName[] = "sancov_guards";
const char SanCovCountersSectionName[] = "sancov_cntrs";
const char SanCovBoolFlagSectionName[] = "sancov_bools";
const char SanCovPCsSectionName[] = "sancov_pcs";

static cl::opt<int> ClCoverageLevel(
    "lto-coverage-level",
    cl::desc("Sanitizer Coverage. 0: none, 1: entry block, 2: all blocks, "
             "3: all blocks and critical edges"),
    cl::Hidden, cl::init(3));

static cl::opt<bool> ClTracePC("lto-coverage-trace-pc",
                               cl::desc("Experimental pc tracing"), cl::Hidden,
                               cl::init(false));

static cl::opt<bool> ClTracePCGuard("lto-coverage-trace-pc-guard",
                                    cl::desc("pc tracing with a guard"),
                                    cl::Hidden, cl::init(false));

// If true, we create a global variable that contains PCs of all instrumented
// BBs, put this global into a named section, and pass this section's bounds
// to __sanitizer_cov_pcs_init.
// This way the coverage instrumentation does not need to acquire the PCs
// at run-time. Works with trace-pc-guard, inline-8bit-counters, and
// inline-bool-flag.
static cl::opt<bool> ClCreatePCTable("lto-coverage-pc-table",
                                     cl::desc("create a static PC table"),
                                     cl::Hidden, cl::init(false));

static cl::opt<bool> ClInline8bitCounters(
    "lto-coverage-inline-8bit-counters",
    cl::desc("increments 8-bit counter for every edge"), cl::Hidden,
    cl::init(false));

static cl::opt<bool> ClInlineBoolFlag(
    "lto-coverage-inline-bool-flag",
    cl::desc("sets a boolean flag for every edge"), cl::Hidden,
    cl::init(false));

static cl::opt<bool> ClPruneBlocks(
    "lto-coverage-prune-blocks",
    cl::desc("Reduce the number of instrumented blocks"), cl::Hidden,
    cl::init(true));

namespace {

SanitizerCoverageOptions getOptions(int LegacyCoverageLevel) {

  SanitizerCoverageOptions Res;
  switch (LegacyCoverageLevel) {

    case 0:
      Res.CoverageType = SanitizerCoverageOptions::SCK_None;
      break;
    case 1:
      Res.CoverageType = SanitizerCoverageOptions::SCK_Function;
      break;
    case 2:
      Res.CoverageType = SanitizerCoverageOptions::SCK_BB;
      break;
    case 3:
      Res.CoverageType = SanitizerCoverageOptions::SCK_Edge;
      break;
    case 4:
      Res.CoverageType = SanitizerCoverageOptions::SCK_Edge;
      Res.IndirectCalls = true;
      break;

  }

  return Res;

}

SanitizerCoverageOptions OverrideFromCL(SanitizerCoverageOptions Options) {

  // Sets CoverageType and IndirectCalls.
  SanitizerCoverageOptions CLOpts = getOptions(ClCoverageLevel);
  Options.CoverageType = std::max(Options.CoverageType, CLOpts.CoverageType);
  Options.IndirectCalls |= CLOpts.IndirectCalls;
  Options.TracePC |= ClTracePC;
  Options.TracePCGuard |= ClTracePCGuard;
  Options.Inline8bitCounters |= ClInline8bitCounters;
  Options.InlineBoolFlag |= ClInlineBoolFlag;
  Options.PCTable |= ClCreatePCTable;
  Options.NoPrune |= !ClPruneBlocks;
  if (!Options.TracePCGuard && !Options.TracePC &&
      !Options.Inline8bitCounters && !Options.InlineBoolFlag)
    Options.TracePCGuard = true;  // TracePCGuard is default.
  return Options;

}

using DomTreeCallback = function_ref<const DominatorTree *(Function &F)>;
using PostDomTreeCallback =
    function_ref<const PostDominatorTree *(Function &F)>;

class ModuleSanitizerCoverage {

 public:
  ModuleSanitizerCoverage(
      const SanitizerCoverageOptions &Options = SanitizerCoverageOptions())
      : Options(OverrideFromCL(Options)) {

    /* ,
    const SpecialCaseList *         Allowlist = nullptr,
    const SpecialCaseList *         Blocklist = nullptr)
      ,
      Allowlist(Allowlist),
      Blocklist(Blocklist) {

    */

  }

  bool instrumentModule(Module &M, DomTreeCallback DTCallback,
                        PostDomTreeCallback PDTCallback);

 private:
  void            instrumentFunction(Function &F, DomTreeCallback DTCallback,
                                     PostDomTreeCallback PDTCallback);
  void            InjectCoverageForIndirectCalls(Function &              F,
                                                 ArrayRef<Instruction *> IndirCalls);
  bool            InjectCoverage(Function &F, ArrayRef<BasicBlock *> AllBlocks,
                                 bool IsLeafFunc = true);
  GlobalVariable *CreateFunctionLocalArrayInSection(size_t    NumElements,
                                                    Function &F, Type *Ty,
                                                    const char *Section);
  GlobalVariable *CreatePCArray(Function &F, ArrayRef<BasicBlock *> AllBlocks);
  void CreateFunctionLocalArrays(Function &F, ArrayRef<BasicBlock *> AllBlocks);
  void InjectCoverageAtBlock(Function &F, BasicBlock &BB, size_t Idx,
                             bool IsLeafFunc = true);
  //  std::pair<Value *, Value *> CreateSecStartEnd(Module &M, const char
  //  *Section,
  //                                                Type *Ty);

  void SetNoSanitizeMetadata(Instruction *I) {

    I->setMetadata(I->getModule()->getMDKindID("nosanitize"),
                   MDNode::get(*C, None));

  }

  std::string getSectionName(const std::string &Section) const;
  //  std::string    getSectionStart(const std::string &Section) const;
  //  std::string    getSectionEnd(const std::string &Section) const;
  FunctionCallee SanCovTracePCIndir;
  FunctionCallee SanCovTracePC /*, SanCovTracePCGuard*/;
  Type *IntptrTy, *IntptrPtrTy, *Int64Ty, *Int64PtrTy, *Int32Ty, *Int32PtrTy,
      *Int16Ty, *Int8Ty, *Int8PtrTy, *Int1Ty, *Int1PtrTy;
  Module *          CurModule;
  std::string       CurModuleUniqueId;
  Triple            TargetTriple;
  LLVMContext *     C;
  const DataLayout *DL;

  GlobalVariable *FunctionGuardArray;        // for trace-pc-guard.
  GlobalVariable *Function8bitCounterArray;  // for inline-8bit-counters.
  GlobalVariable *FunctionBoolArray;         // for inline-bool-flag.
  GlobalVariable *FunctionPCsArray;          // for pc-table.
  SmallVector<GlobalValue *, 20> GlobalsToAppendToUsed;
  SmallVector<GlobalValue *, 20> GlobalsToAppendToCompilerUsed;

  SanitizerCoverageOptions Options;

  // afl++ START
  // const SpecialCaseList *          Allowlist;
  // const SpecialCaseList *          Blocklist;
  uint32_t                         inst = 0;
  uint32_t                         afl_global_id = 0;
  uint32_t                         unhandled = 0;
  uint32_t                         select_cnt = 0;
  const char *                     skip_nozero = NULL;
  const char *                     use_threadsafe_counters = nullptr;
  std::vector<BasicBlock *>        BlockList;
  DenseMap<Value *, std::string *> valueMap;
  IntegerType *                    Int8Tyi = NULL;
  IntegerType *                    Int32Tyi = NULL;
  IntegerType *                    Int64Tyi = NULL;
  ConstantInt *                    Zero = NULL;
  ConstantInt *                    One = NULL;
  LLVMContext *                    Ct = NULL;
  Module *                         Mo = NULL;
  GlobalVariable *                 AFLMapPtr = NULL;
  std::ofstream                    dFile;
  // afl++ END

};

class ModuleSanitizerCoverageLegacyPass : public ModulePass {

 public:
  static char ID;
  StringRef   getPassName() const override {

    return "sancov";

  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {

    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<PostDominatorTreeWrapperPass>();

  }

  ModuleSanitizerCoverageLegacyPass(
      const SanitizerCoverageOptions &Options = SanitizerCoverageOptions())
      : ModulePass(ID), Options(Options) {

    /* ,
          const std::vector<std::string> &AllowlistFiles =
              std::vector<std::string>(),
          const std::vector<std::string> &BlocklistFiles =
              std::vector<std::string>())
        if (AllowlistFiles.size() > 0)
          Allowlist = SpecialCaseList::createOrDie(AllowlistFiles,
                                                   *vfs::getRealFileSystem());
        if (BlocklistFiles.size() > 0)
          Blocklist = SpecialCaseList::createOrDie(BlocklistFiles,
                                                   *vfs::getRealFileSystem());
    */
    initializeModuleSanitizerCoverageLegacyPassPass(
        *PassRegistry::getPassRegistry());

  }

  bool runOnModule(Module &M) override {

    ModuleSanitizerCoverage ModuleSancov(Options);
    // , Allowlist.get(), Blocklist.get());
    auto DTCallback = [this](Function &F) -> const DominatorTree * {

      return &this->getAnalysis<DominatorTreeWrapperPass>(F).getDomTree();

    };

    auto PDTCallback = [this](Function &F) -> const PostDominatorTree * {

      return &this->getAnalysis<PostDominatorTreeWrapperPass>(F)
                  .getPostDomTree();

    };

    return ModuleSancov.instrumentModule(M, DTCallback, PDTCallback);

  }

 private:
  SanitizerCoverageOptions Options;

  // std::unique_ptr<SpecialCaseList> Allowlist;
  // std::unique_ptr<SpecialCaseList> Blocklist;

};

}  // namespace

PreservedAnalyses ModuleSanitizerCoveragePass::run(Module &               M,
                                                   ModuleAnalysisManager &MAM) {

  ModuleSanitizerCoverage ModuleSancov(Options);
  // Allowlist.get(), Blocklist.get());
  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  auto  DTCallback = [&FAM](Function &F) -> const DominatorTree * {

    return &FAM.getResult<DominatorTreeAnalysis>(F);

  };

  auto PDTCallback = [&FAM](Function &F) -> const PostDominatorTree * {

    return &FAM.getResult<PostDominatorTreeAnalysis>(F);

  };

  if (ModuleSancov.instrumentModule(M, DTCallback, PDTCallback))
    return PreservedAnalyses::none();

  return PreservedAnalyses::all();

}

/*
std::pair<Value *, Value *> ModuleSanitizerCoverage::CreateSecStartEnd(
    Module &M, const char *Section, Type *Ty) {

  GlobalVariable *SecStart =
      new GlobalVariable(M, Ty, false, GlobalVariable::ExternalLinkage, nullptr,
                         getSectionStart(Section));
  SecStart->setVisibility(GlobalValue::HiddenVisibility);
  GlobalVariable *SecEnd =
      new GlobalVariable(M, Ty, false, GlobalVariable::ExternalLinkage, nullptr,
                         getSectionEnd(Section));
  SecEnd->setVisibility(GlobalValue::HiddenVisibility);
  IRBuilder<> IRB(M.getContext());
  Value *     SecEndPtr = IRB.CreatePointerCast(SecEnd, Ty);
  if (!TargetTriple.isOSBinFormatCOFF())
    return std::make_pair(IRB.CreatePointerCast(SecStart, Ty), SecEndPtr);

  // Account for the fact that on windows-msvc __start_* symbols actually
  // point to a uint64_t before the start of the array.
  auto SecStartI8Ptr = IRB.CreatePointerCast(SecStart, Int8PtrTy);
  auto GEP = IRB.CreateGEP(Int8Ty, SecStartI8Ptr,
                           ConstantInt::get(IntptrTy, sizeof(uint64_t)));
  return std::make_pair(IRB.CreatePointerCast(GEP, Ty), SecEndPtr);

}

*/

bool ModuleSanitizerCoverage::instrumentModule(
    Module &M, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {

  if (Options.CoverageType == SanitizerCoverageOptions::SCK_None) return false;
  /*
    if (Allowlist &&
        !Allowlist->inSection("coverage", "src", MNAME))
      return false;
    if (Blocklist &&
        Blocklist->inSection("coverage", "src", MNAME))
      return false;
  */
  BlockList.clear();
  valueMap.clear();
  C = &(M.getContext());
  DL = &M.getDataLayout();
  CurModule = &M;
  CurModuleUniqueId = getUniqueModuleId(CurModule);
  TargetTriple = Triple(M.getTargetTriple());
  FunctionGuardArray = nullptr;
  Function8bitCounterArray = nullptr;
  FunctionBoolArray = nullptr;
  FunctionPCsArray = nullptr;
  IntptrTy = Type::getIntNTy(*C, DL->getPointerSizeInBits());
  IntptrPtrTy = PointerType::getUnqual(IntptrTy);
  Type *      VoidTy = Type::getVoidTy(*C);
  IRBuilder<> IRB(*C);
  Int64PtrTy = PointerType::getUnqual(IRB.getInt64Ty());
  Int32PtrTy = PointerType::getUnqual(IRB.getInt32Ty());
  Int8PtrTy = PointerType::getUnqual(IRB.getInt8Ty());
  Int1PtrTy = PointerType::getUnqual(IRB.getInt1Ty());
  Int64Ty = IRB.getInt64Ty();
  Int32Ty = IRB.getInt32Ty();
  Int16Ty = IRB.getInt16Ty();
  Int8Ty = IRB.getInt8Ty();
  Int1Ty = IRB.getInt1Ty();

  /* afl++ START */
  char *       ptr;
  LLVMContext &Ctx = M.getContext();
  Ct = &Ctx;
  Int8Tyi = IntegerType::getInt8Ty(Ctx);
  Int32Tyi = IntegerType::getInt32Ty(Ctx);
  Int64Tyi = IntegerType::getInt64Ty(Ctx);

  /* Show a banner */
  setvbuf(stdout, NULL, _IONBF, 0);
  if (getenv("AFL_DEBUG")) debug = 1;

  if ((isatty(2) && !getenv("AFL_QUIET")) || debug) {

    SAYF(cCYA "afl-llvm-lto" VERSION cRST
              " by Marc \"vanHauser\" Heuse <mh@mh-sec.de>\n");

  } else

    be_quiet = 1;

  skip_nozero = getenv("AFL_LLVM_SKIP_NEVERZERO");
  use_threadsafe_counters = getenv("AFL_LLVM_THREADSAFE_INST");

  if ((ptr = getenv("AFL_LLVM_LTO_STARTID")) != NULL)
    if ((afl_global_id = atoi(ptr)) < 0)
      FATAL("AFL_LLVM_LTO_STARTID value of \"%s\" is negative\n", ptr);

  if ((ptr = getenv("AFL_LLVM_DOCUMENT_IDS")) != NULL) {

    dFile.open(ptr, std::ofstream::out | std::ofstream::app);
    if (dFile.is_open()) WARNF("Cannot access document file %s", ptr);

  }

  /* Get/set the globals for the SHM region. */


    AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Tyi, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");


  Zero = ConstantInt::get(Int8Tyi, 0);
  One = ConstantInt::get(Int8Tyi, 1);

  initInstrumentList();
  scanForDangerousFunctions(&M);
  Mo = &M;


  // afl++ END

  SanCovTracePCIndir =
      M.getOrInsertFunction(SanCovTracePCIndirName, VoidTy, IntptrTy);
  // Make sure smaller parameters are zero-extended to i64 as required by the
  // x86_64 ABI.
  AttributeList SanCovTraceCmpZeroExtAL;
  if (TargetTriple.getArch() == Triple::x86_64) {

    SanCovTraceCmpZeroExtAL =
        SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 0, Attribute::ZExt);
    SanCovTraceCmpZeroExtAL =
        SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 1, Attribute::ZExt);

  }

  SanCovTracePC = M.getOrInsertFunction(SanCovTracePCName, VoidTy);

  // SanCovTracePCGuard =
  //    M.getOrInsertFunction(SanCovTracePCGuardName, VoidTy, Int32PtrTy);

  for (auto &F : M)
    instrumentFunction(F, DTCallback, PDTCallback);

  // afl++ START
  if (dFile.is_open()) dFile.close();

  if (!getenv("AFL_LLVM_LTO_DONTWRITEID")) {

    // yes we could create our own function, insert it into ctors ...
    // but this would be a pain in the butt ... so we use afl-llvm-rt-lto.o

    Function *f = M.getFunction("__afl_auto_init_globals");

    if (!f) {

      fprintf(stderr,
              "Error: init function could not be found (this should not "
              "happen)\n");
      exit(-1);

    }

    BasicBlock *bb = &f->getEntryBlock();
    if (!bb) {

      fprintf(stderr,
              "Error: init function does not have an EntryBlock (this should "
              "not happen)\n");
      exit(-1);

    }

    BasicBlock::iterator IP = bb->getFirstInsertionPt();
    IRBuilder<>          IRB(&(*IP));


    if (getenv("AFL_LLVM_LTO_DONTWRITEID") == NULL) {

      uint32_t write_loc = afl_global_id;

      write_loc = (((afl_global_id + 8) >> 3) << 3);

      GlobalVariable *AFLFinalLoc =
          new GlobalVariable(M, Int32Tyi, true, GlobalValue::ExternalLinkage, 0,
                             "__afl_final_loc");
      ConstantInt *const_loc = ConstantInt::get(Int32Tyi, write_loc);
      StoreInst *  StoreFinalLoc = IRB.CreateStore(const_loc, AFLFinalLoc);
      ModuleSanitizerCoverage::SetNoSanitizeMetadata(StoreFinalLoc);

    }

  }

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst)
      WARNF("No instrumentation targets found.");
    else {

      char modeline[100];
      snprintf(modeline, sizeof(modeline), "%s%s%s%s%s%s",
               getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
               getenv("AFL_USE_ASAN") ? ", ASAN" : "",
               getenv("AFL_USE_MSAN") ? ", MSAN" : "",
               getenv("AFL_USE_TSAN") ? ", TSAN" : "",
               getenv("AFL_USE_CFISAN") ? ", CFISAN" : "",
               getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");
      OKF("Instrumented %u locations (%u selects) without collisions (%llu "
          "collisions have been avoided) (%s mode).",
          inst, select_cnt, calculateCollisions(inst), modeline);

    }

  }

  // afl++ END

  // We don't reference these arrays directly in any of our runtime functions,
  // so we need to prevent them from being dead stripped.
  if (TargetTriple.isOSBinFormatMachO()) appendToUsed(M, GlobalsToAppendToUsed);
  appendToCompilerUsed(M, GlobalsToAppendToCompilerUsed);
  return true;

}

// True if block has successors and it dominates all of them.
static bool isFullDominator(const BasicBlock *BB, const DominatorTree *DT) {

  if (succ_begin(BB) == succ_end(BB)) return false;

  for (const BasicBlock *SUCC : make_range(succ_begin(BB), succ_end(BB))) {

    if (!DT->dominates(BB, SUCC)) return false;

  }

  return true;

}

// True if block has predecessors and it postdominates all of them.
static bool isFullPostDominator(const BasicBlock *       BB,
                                const PostDominatorTree *PDT) {

  if (pred_begin(BB) == pred_end(BB)) return false;

  for (const BasicBlock *PRED : make_range(pred_begin(BB), pred_end(BB))) {

    if (!PDT->dominates(BB, PRED)) return false;

  }

  return true;

}

static bool shouldInstrumentBlock(const Function &F, const BasicBlock *BB,
                                  const DominatorTree *           DT,
                                  const PostDominatorTree *       PDT,
                                  const SanitizerCoverageOptions &Options) {

  // Don't insert coverage for blocks containing nothing but unreachable: we
  // will never call __sanitizer_cov() for them, so counting them in
  // NumberOfInstrumentedBlocks() might complicate calculation of code coverage
  // percentage. Also, unreachable instructions frequently have no debug
  // locations.
  if (isa<UnreachableInst>(BB->getFirstNonPHIOrDbgOrLifetime())) return false;

  // Don't insert coverage into blocks without a valid insertion point
  // (catchswitch blocks).
  if (BB->getFirstInsertionPt() == BB->end()) return false;

  // afl++ START
  if (!Options.NoPrune && &F.getEntryBlock() == BB && F.size() > 1)
    return false;
  // afl++ END

  if (Options.NoPrune || &F.getEntryBlock() == BB) return true;

  if (Options.CoverageType == SanitizerCoverageOptions::SCK_Function &&
      &F.getEntryBlock() != BB)
    return false;

  // Do not instrument full dominators, or full post-dominators with multiple
  // predecessors.
  return !isFullDominator(BB, DT) &&
         !(isFullPostDominator(BB, PDT) && !BB->getSinglePredecessor());

}

void ModuleSanitizerCoverage::instrumentFunction(
    Function &F, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {

  if (F.empty()) return;
  if (F.getName().find(".module_ctor") != std::string::npos)
    return;  // Should not instrument sanitizer init functions.
  if (F.getName().startswith("__sanitizer_"))
    return;  // Don't instrument __sanitizer_* callbacks.
  // Don't touch available_externally functions, their actual body is elsewhere.
  if (F.getLinkage() == GlobalValue::AvailableExternallyLinkage) return;
  // Don't instrument MSVC CRT configuration helpers. They may run before normal
  // initialization.
  if (F.getName() == "__local_stdio_printf_options" ||
      F.getName() == "__local_stdio_scanf_options")
    return;
  if (isa<UnreachableInst>(F.getEntryBlock().getTerminator())) return;
  // Don't instrument functions using SEH for now. Splitting basic blocks like
  // we do for coverage breaks WinEHPrepare.
  // FIXME: Remove this when SEH no longer uses landingpad pattern matching.
  if (F.hasPersonalityFn() &&
      isAsynchronousEHPersonality(classifyEHPersonality(F.getPersonalityFn())))
    return;
  // if (Allowlist && !Allowlist->inSection("coverage", "fun", F.getName()))
  //  return;
  // if (Blocklist && Blocklist->inSection("coverage", "fun", F.getName()))
  // return;

  // afl++ START
  if (!F.size()) return;
  if (!isInInstrumentList(&F, FMNAME)) return;
  // afl++ END

  if (Options.CoverageType >= SanitizerCoverageOptions::SCK_Edge)
    SplitAllCriticalEdges(
        F, CriticalEdgeSplittingOptions().setIgnoreUnreachableDests());
  SmallVector<Instruction *, 8> IndirCalls;
  SmallVector<BasicBlock *, 16> BlocksToInstrument;

  const DominatorTree *    DT = DTCallback(F);
  const PostDominatorTree *PDT = PDTCallback(F);
  bool                     IsLeafFunc = true;
  uint32_t                 skip_next = 0;

  for (auto &BB : F) {

    for (auto &IN : BB) {

      CallInst *callInst = nullptr;

      if ((callInst = dyn_cast<CallInst>(&IN))) {

        Function *Callee = callInst->getCalledFunction();
        if (!Callee) continue;
        if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
        StringRef FuncName = Callee->getName();
        if (!FuncName.compare(StringRef("dlopen")) ||
            !FuncName.compare(StringRef("_dlopen"))) {

          fprintf(stderr,
                  "WARNING: dlopen() detected. To have coverage for a library "
                  "that your target dlopen()'s this must either happen before "
                  "__AFL_INIT() or you must use AFL_PRELOAD to preload all "
                  "dlopen()'ed libraries!\n");
          continue;

        }

        if (FuncName.compare(StringRef("__afl_coverage_interesting"))) continue;

        Value *val = ConstantInt::get(Int32Ty, ++afl_global_id);
        callInst->setOperand(1, val);
        ++inst;

      }

      SelectInst *selectInst = nullptr;

      /*
            std::string errMsg;
            raw_string_ostream os(errMsg);
            IN.print(os);
            fprintf(stderr, "X(%u): %s\n", skip_next, os.str().c_str());
      */
      if (!skip_next && (selectInst = dyn_cast<SelectInst>(&IN))) {

        uint32_t    vector_cnt = 0;
        Value *     condition = selectInst->getCondition();
        Value *     result;
        auto        t = condition->getType();
        IRBuilder<> IRB(selectInst->getNextNode());

        ++select_cnt;

        if (t->getTypeID() == llvm::Type::IntegerTyID) {

          Value *val1 = ConstantInt::get(Int32Ty, ++afl_global_id);
          Value *val2 = ConstantInt::get(Int32Ty, ++afl_global_id);
          result = IRB.CreateSelect(condition, val1, val2);
          skip_next = 1;
          inst += 2;

        } else

#if LLVM_VERSION_MAJOR >= 14
            if (t->getTypeID() == llvm::Type::FixedVectorTyID) {

          FixedVectorType *tt = dyn_cast<FixedVectorType>(t);
          if (tt) {

            uint32_t elements = tt->getElementCount().getFixedValue();
            vector_cnt = elements;
            inst += vector_cnt * 2;
            if (elements) {

              FixedVectorType *GuardPtr1 =
                  FixedVectorType::get(Int32Ty, elements);
              FixedVectorType *GuardPtr2 =
                  FixedVectorType::get(Int32Ty, elements);
              Value *x, *y;

              Value *val1 = ConstantInt::get(Int32Ty, ++afl_global_id);
              Value *val2 = ConstantInt::get(Int32Ty, ++afl_global_id);
              x = IRB.CreateInsertElement(GuardPtr1, val1, (uint64_t)0);
              y = IRB.CreateInsertElement(GuardPtr2, val2, (uint64_t)0);

              for (uint64_t i = 1; i < elements; i++) {

                val1 = ConstantInt::get(Int32Ty, ++afl_global_id);
                val2 = ConstantInt::get(Int32Ty, ++afl_global_id);
                x = IRB.CreateInsertElement(GuardPtr1, val1, i);
                y = IRB.CreateInsertElement(GuardPtr2, val2, i);

              }

              result = IRB.CreateSelect(condition, x, y);
              skip_next = 1;

            }

          }

        } else

#endif
        {

          unhandled++;
          continue;

        }

        uint32_t vector_cur = 0;
        /* Load SHM pointer */
        LoadInst *MapPtr =
            IRB.CreateLoad(PointerType::get(Int8Ty, 0), AFLMapPtr);
        ModuleSanitizerCoverage::SetNoSanitizeMetadata(MapPtr);

        while (1) {

          /* Get CurLoc */
          Value *MapPtrIdx = nullptr;

          /* Load counter for CurLoc */
          if (!vector_cnt) {

            MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, result);

          } else {

            auto element = IRB.CreateExtractElement(result, vector_cur++);
            MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, element);

          }

          if (use_threadsafe_counters) {

            IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
#if LLVM_VERSION_MAJOR >= 13
                                llvm::MaybeAlign(1),
#endif
                                llvm::AtomicOrdering::Monotonic);

          } else {

            LoadInst *Counter = IRB.CreateLoad(IRB.getInt8Ty(), MapPtrIdx);
            ModuleSanitizerCoverage::SetNoSanitizeMetadata(Counter);

            /* Update bitmap */

            Value *Incr = IRB.CreateAdd(Counter, One);

            if (skip_nozero == NULL) {

              auto cf = IRB.CreateICmpEQ(Incr, Zero);
              auto carry = IRB.CreateZExt(cf, Int8Ty);
              Incr = IRB.CreateAdd(Incr, carry);

            }

            auto nosan = IRB.CreateStore(Incr, MapPtrIdx);
            ModuleSanitizerCoverage::SetNoSanitizeMetadata(nosan);

          }

          if (!vector_cnt || vector_cnt == vector_cur) { break; }

        }

        skip_next = 1;

      } else {

        skip_next = 0;

      }

    }

    if (shouldInstrumentBlock(F, &BB, DT, PDT, Options))
      BlocksToInstrument.push_back(&BB);
    for (auto &Inst : BB) {

      if (Options.IndirectCalls) {

        CallBase *CB = dyn_cast<CallBase>(&Inst);
        if (CB && !CB->getCalledFunction()) IndirCalls.push_back(&Inst);

      }

    }

  }

  InjectCoverage(F, BlocksToInstrument, IsLeafFunc);
  InjectCoverageForIndirectCalls(F, IndirCalls);

}

GlobalVariable *ModuleSanitizerCoverage::CreateFunctionLocalArrayInSection(
    size_t NumElements, Function &F, Type *Ty, const char *Section) {

  ArrayType *ArrayTy = ArrayType::get(Ty, NumElements);
  auto       Array = new GlobalVariable(
      *CurModule, ArrayTy, false, GlobalVariable::PrivateLinkage,
      Constant::getNullValue(ArrayTy), "__sancov_gen_");

#if LLVM_VERSION_MAJOR >= 13
  if (TargetTriple.supportsCOMDAT() &&
      (TargetTriple.isOSBinFormatELF() || !F.isInterposable()))
    if (auto Comdat = getOrCreateFunctionComdat(F, TargetTriple))
      Array->setComdat(Comdat);
#else
  if (TargetTriple.supportsCOMDAT() && !F.isInterposable())
    if (auto Comdat =
            GetOrCreateFunctionComdat(F, TargetTriple, CurModuleUniqueId))
      Array->setComdat(Comdat);
#endif
  Array->setSection(getSectionName(Section));
  Array->setAlignment(Align(DL->getTypeStoreSize(Ty).getFixedSize()));
  GlobalsToAppendToUsed.push_back(Array);
  GlobalsToAppendToCompilerUsed.push_back(Array);
  MDNode *MD = MDNode::get(F.getContext(), ValueAsMetadata::get(&F));
  Array->addMetadata(LLVMContext::MD_associated, *MD);

  return Array;

}

GlobalVariable *ModuleSanitizerCoverage::CreatePCArray(
    Function &F, ArrayRef<BasicBlock *> AllBlocks) {

  size_t N = AllBlocks.size();
  assert(N);
  SmallVector<Constant *, 32> PCs;
  IRBuilder<>                 IRB(&*F.getEntryBlock().getFirstInsertionPt());
  for (size_t i = 0; i < N; i++) {

    if (&F.getEntryBlock() == AllBlocks[i]) {

      PCs.push_back((Constant *)IRB.CreatePointerCast(&F, IntptrPtrTy));
      PCs.push_back((Constant *)IRB.CreateIntToPtr(
          ConstantInt::get(IntptrTy, 1), IntptrPtrTy));

    } else {

      PCs.push_back((Constant *)IRB.CreatePointerCast(
          BlockAddress::get(AllBlocks[i]), IntptrPtrTy));
      PCs.push_back((Constant *)IRB.CreateIntToPtr(
          ConstantInt::get(IntptrTy, 0), IntptrPtrTy));

    }

  }

  auto *PCArray = CreateFunctionLocalArrayInSection(N * 2, F, IntptrPtrTy,
                                                    SanCovPCsSectionName);
  PCArray->setInitializer(
      ConstantArray::get(ArrayType::get(IntptrPtrTy, N * 2), PCs));
  PCArray->setConstant(true);

  return PCArray;

}

void ModuleSanitizerCoverage::CreateFunctionLocalArrays(
    Function &F, ArrayRef<BasicBlock *> AllBlocks) {

  if (Options.TracePCGuard)
    FunctionGuardArray = CreateFunctionLocalArrayInSection(
        AllBlocks.size(), F, Int32Ty, SanCovGuardsSectionName);
  if (Options.Inline8bitCounters)
    Function8bitCounterArray = CreateFunctionLocalArrayInSection(
        AllBlocks.size(), F, Int8Ty, SanCovCountersSectionName);
  if (Options.InlineBoolFlag)
    FunctionBoolArray = CreateFunctionLocalArrayInSection(
        AllBlocks.size(), F, Int1Ty, SanCovBoolFlagSectionName);
  if (Options.PCTable) FunctionPCsArray = CreatePCArray(F, AllBlocks);

}

bool ModuleSanitizerCoverage::InjectCoverage(Function &             F,
                                             ArrayRef<BasicBlock *> AllBlocks,
                                             bool IsLeafFunc) {

  if (AllBlocks.empty()) return false;
  CreateFunctionLocalArrays(F, AllBlocks);

  for (size_t i = 0, N = AllBlocks.size(); i < N; i++) {

    // afl++ START
    if (BlockList.size()) {

      int skip = 0;
      for (uint32_t k = 0; k < BlockList.size(); k++) {

        if (AllBlocks[i] == BlockList[k]) {

          if (debug)
            fprintf(stderr,
                    "DEBUG: Function %s skipping BB with/after __afl_loop\n",
                    F.getName().str().c_str());
          skip = 1;

        }

      }

      if (skip) continue;

    }

    // afl++ END

    InjectCoverageAtBlock(F, *AllBlocks[i], i, IsLeafFunc);

  }

  return true;

}

// On every indirect call we call a run-time function
// __sanitizer_cov_indir_call* with two parameters:
//   - callee address,
//   - global cache array that contains CacheSize pointers (zero-initialized).
//     The cache is used to speed up recording the caller-callee pairs.
// The address of the caller is passed implicitly via caller PC.
// CacheSize is encoded in the name of the run-time function.
void ModuleSanitizerCoverage::InjectCoverageForIndirectCalls(
    Function &F, ArrayRef<Instruction *> IndirCalls) {

  if (IndirCalls.empty()) return;
  assert(Options.TracePC || Options.TracePCGuard ||
         Options.Inline8bitCounters || Options.InlineBoolFlag);
  for (auto I : IndirCalls) {

    IRBuilder<> IRB(I);
    CallBase &  CB = cast<CallBase>(*I);
    Value *     Callee = CB.getCalledOperand();
    if (isa<InlineAsm>(Callee)) continue;
    IRB.CreateCall(SanCovTracePCIndir, IRB.CreatePointerCast(Callee, IntptrTy));

  }

}

void ModuleSanitizerCoverage::InjectCoverageAtBlock(Function &F, BasicBlock &BB,
                                                    size_t Idx,
                                                    bool   IsLeafFunc) {

  BasicBlock::iterator IP = BB.getFirstInsertionPt();
  bool                 IsEntryBB = &BB == &F.getEntryBlock();

  if (IsEntryBB) {

    // Keep static allocas and llvm.localescape calls in the entry block.  Even
    // if we aren't splitting the block, it's nice for allocas to be before
    // calls.
    IP = PrepareToSplitEntryBlock(BB, IP);

  }

  IRBuilder<> IRB(&*IP);
  if (Options.TracePC) {

    IRB.CreateCall(SanCovTracePC)
#if LLVM_VERSION_MAJOR >= 12
        ->setCannotMerge();  // gets the PC using GET_CALLER_PC.
#else
        ->cannotMerge();  // gets the PC using GET_CALLER_PC.
#endif

  }

  if (Options.TracePCGuard) {

    // afl++ START
    ++afl_global_id;

    if (dFile.is_open()) {

      unsigned long long int moduleID =
          (((unsigned long long int)(rand() & 0xffffffff)) << 32) | getpid();
      dFile << "ModuleID=" << moduleID << " Function=" << F.getName().str()
            << " edgeID=" << afl_global_id << "\n";

    }

    /* Set the ID of the inserted basic block */

    ConstantInt *CurLoc = ConstantInt::get(Int32Tyi, afl_global_id);

    /* Load SHM pointer */

    Value *MapPtrIdx;


      LoadInst *MapPtr = IRB.CreateLoad(PointerType::get(Int8Ty, 0), AFLMapPtr);
      ModuleSanitizerCoverage::SetNoSanitizeMetadata(MapPtr);
      MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, CurLoc);


    /* Update bitmap */
    if (use_threadsafe_counters) {                                /* Atomic */

      IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
#if LLVM_VERSION_MAJOR >= 13
                          llvm::MaybeAlign(1),
#endif
                          llvm::AtomicOrdering::Monotonic);

    } else {

      LoadInst *Counter = IRB.CreateLoad(IRB.getInt8Ty(), MapPtrIdx);
      ModuleSanitizerCoverage::SetNoSanitizeMetadata(Counter);

      Value *Incr = IRB.CreateAdd(Counter, One);

      if (skip_nozero == NULL) {

        auto cf = IRB.CreateICmpEQ(Incr, Zero);
        auto carry = IRB.CreateZExt(cf, Int8Tyi);
        Incr = IRB.CreateAdd(Incr, carry);

      }

      auto nosan = IRB.CreateStore(Incr, MapPtrIdx);
      ModuleSanitizerCoverage::SetNoSanitizeMetadata(nosan);

    }

    // done :)

    inst++;
    // afl++ END

    /*
    XXXXXXXXXXXXXXXXXXX

        auto GuardPtr = IRB.CreateIntToPtr(
            IRB.CreateAdd(IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                          ConstantInt::get(IntptrTy, Idx * 4)),
            Int32PtrTy);

        IRB.CreateCall(SanCovTracePCGuard, GuardPtr)->setCannotMerge();
    */

  }

  if (Options.Inline8bitCounters) {

    auto CounterPtr = IRB.CreateGEP(
        Function8bitCounterArray->getValueType(), Function8bitCounterArray,
        {ConstantInt::get(IntptrTy, 0), ConstantInt::get(IntptrTy, Idx)});
    auto Load = IRB.CreateLoad(Int8Ty, CounterPtr);
    auto Inc = IRB.CreateAdd(Load, ConstantInt::get(Int8Ty, 1));
    auto Store = IRB.CreateStore(Inc, CounterPtr);
    SetNoSanitizeMetadata(Load);
    SetNoSanitizeMetadata(Store);

  }

  if (Options.InlineBoolFlag) {

    auto FlagPtr = IRB.CreateGEP(
        FunctionBoolArray->getValueType(), FunctionBoolArray,
        {ConstantInt::get(IntptrTy, 0), ConstantInt::get(IntptrTy, Idx)});
    auto Load = IRB.CreateLoad(Int1Ty, FlagPtr);
    auto ThenTerm =
        SplitBlockAndInsertIfThen(IRB.CreateIsNull(Load), &*IP, false);
    IRBuilder<> ThenIRB(ThenTerm);
    auto Store = ThenIRB.CreateStore(ConstantInt::getTrue(Int1Ty), FlagPtr);
    SetNoSanitizeMetadata(Load);
    SetNoSanitizeMetadata(Store);

  }

}

std::string ModuleSanitizerCoverage::getSectionName(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatCOFF()) {

    if (Section == SanCovCountersSectionName) return ".SCOV$CM";
    if (Section == SanCovBoolFlagSectionName) return ".SCOV$BM";
    if (Section == SanCovPCsSectionName) return ".SCOVP$M";
    return ".SCOV$GM";  // For SanCovGuardsSectionName.

  }

  if (TargetTriple.isOSBinFormatMachO()) return "__DATA,__" + Section;
  return "__" + Section;

}

/*
std::string ModuleSanitizerCoverage::getSectionStart(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatMachO())
    return "\1section$start$__DATA$__" + Section;
  return "__start___" + Section;

}

std::string ModuleSanitizerCoverage::getSectionEnd(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatMachO())
    return "\1section$end$__DATA$__" + Section;
  return "__stop___" + Section;

}

*/

char ModuleSanitizerCoverageLegacyPass::ID = 0;

INITIALIZE_PASS_BEGIN(ModuleSanitizerCoverageLegacyPass, "sancov",
                      "Pass for instrumenting coverage on functions", false,
                      false)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(PostDominatorTreeWrapperPass)
INITIALIZE_PASS_END(ModuleSanitizerCoverageLegacyPass, "sancov",
                    "Pass for instrumenting coverage on functions", false,
                    false)

ModulePass *llvm::createModuleSanitizerCoverageLegacyPassPass(
    const SanitizerCoverageOptions &Options,
    const std::vector<std::string> &AllowlistFiles,
    const std::vector<std::string> &BlocklistFiles) {

  return new ModuleSanitizerCoverageLegacyPass(Options);
  //, AllowlistFiles, BlocklistFiles);

}

static void registerLTOPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  auto p = new ModuleSanitizerCoverageLegacyPass();
  PM.add(p);

}

static RegisterStandardPasses RegisterCompTransPass(
    PassManagerBuilder::EP_OptimizerLast, registerLTOPass);

static RegisterStandardPasses RegisterCompTransPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerLTOPass);

#if LLVM_VERSION_MAJOR >= 11
static RegisterStandardPasses RegisterCompTransPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast, registerLTOPass);
#endif
