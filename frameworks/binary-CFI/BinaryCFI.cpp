// Copyright (c) University of Kansas and affiliates.

//=============================================================================
// FILE:
//    BinaryCFI.cpp
//
// DESCRIPTION:
//    Visits all functions in a module, prints their names and the number of
//    arguments via stderr. Strictly speaking, this is an analysis pass (i.e.
//    the functions are not modified). However, in order to keep things simple
//    there's no 'print' method here (every analysis pass should implement it).
//
// USAGE:
//    1. Legacy PM
//      opt -enable-new-pm=0 -load libHelloWorld.dylib -legacy-hello-world -disable-output `\`
//        <input-llvm-file>
//    2. New PM
//      opt -load-pass-plugin=libHelloWorld.dylib -passes="hello-world" `\`
//        -disable-output <input-llvm-file>
//
//
// License: MIT
//=============================================================================
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/AbstractCallSite.h"
#include "llvm/Support/CommandLine.h"

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>
#include <fstream>
#include <sstream>

using namespace llvm;
std::pair<std::string, std::string> itaniumDemanglePair(llvm::StringRef, int&);

//-----------------------------------------------------------------------------
// BinaryCFI implementation
//-----------------------------------------------------------------------------
// No need to expose the internals of the pass to the outside world - keep
// everything in an anonymous namespace.
namespace {

// Catch the output binary name.
static cl::opt<std::string>
OutputFilename("bin", cl::desc("Specify output filename"),
  cl::value_desc("filename"), cl::init(""));

// Ruturaj: Data structures to store additional function data.
// This include: calltarget and callsite return type, argument types.
std::map<std::string, std::array<uint16_t, 7>> FunParams{};
std::map<std::string, uint16_t> FunRet{};
std::map<std::string, std::array<uint16_t, 7>> CallSiteParams{};
std::map<std::string, uint16_t> CallSiteRet{};

/** Encodings contains the three relevant encodings */
static uint16_t encodeType(Type* T, bool recurse = true) {
  uint16_t TypeEncoded;
  switch (T->getTypeID()) {
      case Type::TypeID::VoidTyID:
          TypeEncoded = 1;
          break;

      case Type::TypeID::IntegerTyID: {
          auto Bits = cast<IntegerType>(T)->getBitWidth();
          if (Bits <= 1) {
              TypeEncoded = 2;
          } else if (Bits <= 8) {
              TypeEncoded = 3;
          } else if (Bits <= 16) {
              TypeEncoded = 4;
          } else if (Bits <= 32) {
              TypeEncoded = 5;
          } else {
              TypeEncoded = 6;
          }
      }
          break;

      case Type::TypeID::HalfTyID:
          TypeEncoded = 7;
          break;
      case Type::TypeID::FloatTyID:
          TypeEncoded = 8;
          break;
      case Type::TypeID::DoubleTyID:
          TypeEncoded = 9;
          break;

      case Type::TypeID::X86_FP80TyID:
      case Type::TypeID::FP128TyID:
      case Type::TypeID::PPC_FP128TyID:
          TypeEncoded = 10;
          break;

      case Type::TypeID::PointerTyID:
          if (recurse) {
              TypeEncoded = uint16_t(16) + encodeType(dyn_cast<PointerType>(T)->getElementType(), false);
          } else {
              TypeEncoded = 11;
          }
          break;
      case Type::TypeID::StructTyID:
          TypeEncoded = 12;
          break;
      case Type::TypeID::ArrayTyID:
          TypeEncoded = 13;
          break;
      default:
          TypeEncoded = 14;
          break;
  }
  assert(TypeEncoded < 32);
  return TypeEncoded;
}

// Ruturaj: collect each parameter and its encoding.
std::array<uint16_t, 7> getParameters(FunctionType *FuncTy) {
  // Create an array of 7 values and initialize it to zero.
  std::array<uint16_t, 7> parameters = {0};
  if (FuncTy->getNumParams() < 8) {
      int i{0};
      for (auto *Param : FuncTy->params()) {
          parameters[i] = encodeType(Param, true);
          ++i;
      }
  }
  else {
      for (int i{0}; i < 7; ++i) {
          parameters[i] = 32;
      }
  }
  return parameters;
}

// Ruturaj: Collect function return encoding value.
uint16_t getReturn(FunctionType *FuncTy) {
  if (FuncTy->getNumParams() < 8) {
      return encodeType(FuncTy->getReturnType(), true);
  }
  // Return 0 if functions with paramters greater than 8 is detected.
  // This is a special case.
  return 32;
}

bool isBlackListed(const Function &F) {
  return (F.getName().startswith("llvm.") || F.getName().startswith("__")  || F.getName() == "_Znwm");
}

// This function demangles if needed to be.
// This function isn't used right now.
std::string demangleFun(std::string& DemangledFunctionName) {
  int Status = 0;
  if (DemangledFunctionName.find("_", 0) == 0) {
    auto DemangledPair = itaniumDemanglePair(DemangledFunctionName, Status);
    if (Status == 0 && DemangledPair.second != "") {
        DemangledFunctionName = DemangledPair.second;
    }
  }
  return DemangledFunctionName;
}

void writeHeaderRaw(raw_ostream& Out, bool callSiteHeader = false) {
  if (callSiteHeader) {
      Out << "Dwarf";
  }
  else {
      Out << "Function";
  }

  Out << ",Arg1"
      << ",Arg2"
      << ",Arg3"
      << ",Arg4"
      << ",Arg5"
      << ",Arg6"
      << ",Arg7";
  
  Out << ",Return";

  Out << "\n";
}


void writeRawData(raw_fd_ostream& OutfileFun, raw_fd_ostream& OutfileCallsite) {
  writeHeaderRaw(OutfileFun);
  writeHeaderRaw(OutfileCallsite, true);

  for (auto it=FunParams.begin(); it!=FunParams.end(); ++it) {
      OutfileFun << it->first;
      for (auto& Param : it->second){
          OutfileFun << "," << Param;
      }
      OutfileFun  << "," << FunRet[it->first]
                  << "\n";
  }

  OutfileFun.close();

  for (auto it=CallSiteParams.begin(); it!=CallSiteParams.end(); ++it) {
      OutfileCallsite << it->first;
      for (auto& Param : it->second){
          OutfileCallsite << "," << Param;
      }
      OutfileCallsite  << "," << CallSiteRet[it->first]
                  << "\n";
  }

  OutfileCallsite.close();
}

std::string createDirectory(const std::string& currPath) {
  if (!sys::fs::is_directory(currPath + "/SDOutput") || !sys::fs::exists(currPath + "/SDOutput")) {
    auto EC = sys::fs::create_directory(currPath + "/SDOutput", true);
    if (EC) {
      errs() << "[BinaryCFI Error] (Directory Creation): " << EC.message() << '\n';
    }
  }
  return currPath+"/SDOutput/";
}

std::string getOutputBinName()
{
    if (OutputFilename.empty()) {
      const char *binPath = getenv("BINCFI");
      if (!binPath) {
        errs() << "[BinaryCFI Error] (env set) Environment variable is not set!\n";
        return "";
      }
      return std::string(binPath);
    }
    return OutputFilename.substr(OutputFilename.find_last_of("/") + 1);
}

/** Ruturaj: store additional metadata**/
std::pair<std::string, std::string> getOutputFileName(Module &M, const std::string key) {
  llvm::SmallString<128> currPath;
  sys::fs::current_path(currPath);

  std::string outputBinName = getOutputBinName();
  if (outputBinName.empty()) {
    outputBinName = key;
  }
  std::string OutputPath = createDirectory(std::move(std::string(currPath)));
  
  std::string FunFileName = OutputPath + outputBinName + "-Fun";
  std::string CallsiteFileName = OutputPath + outputBinName + "-Callsite";

  uint16_t count = 1;
  while (sys::fs::exists(FunFileName + Twine(count) + ".csv") ||
        sys::fs::exists(CallsiteFileName + Twine(count) + ".csv")) {
    ++count;
  }

  std::string FunFileNameExtended = (FunFileName + Twine(count)+ ".csv").str();
  std::string CallsiteFileNameExtended = (CallsiteFileName + Twine(count) + ".csv").str();

  return {FunFileNameExtended, CallsiteFileNameExtended};
}

// Ruturaj: store additional function and callsite info.
void storeAdditionalData(Module& M, const std::string key)
{
  errs() << "Store Additional Data for Module: " << M.getName() << "\n";

  auto FileNames = getOutputFileName(M, std::move(key));

  // Start writing the analysis data.
  std::error_code ECFun, ECCallsite;
  raw_fd_ostream OutfileFun(FileNames.first, ECFun, sys::fs::OpenFlags::F_None);
  raw_fd_ostream OutfileCallsite(FileNames.second, ECCallsite, sys::fs::OpenFlags::F_None);
  if (ECFun || ECCallsite) {
      errs() << "Failed to write to " << FileNames.first << ", " << FileNames.second << "!\n";
      return;
  }

  errs() << "Writing function and callsite encoding data to "
                  << FileNames.first << ", " << FileNames.second << ".\n";

  writeRawData(OutfileFun, OutfileCallsite);

}

static std::stringstream writeDebugLocToStream(const DebugLoc* Loc) {
  assert(Loc);
  auto* Scope = cast<DIScope>(Loc->getScope());
  std::stringstream Stream;
  Stream << Scope->getFilename().str() + ":" << Loc->getLine() << ":" << Loc->getCol();
  return Stream;
}

void analyseCallTarget(Function &F) {
  std::string functionName = F.getName().str();
    // errs() << "Function: "<< functionName << "\n";

  auto NumOfParams = F.getFunctionType()->getNumParams();
  if (NumOfParams > 7) {
    NumOfParams = 7;
  }

  FunParams[functionName] = getParameters(F.getFunctionType());
  FunRet[functionName] = getReturn(F.getFunctionType());

}

int64_t analyseCallSite(Function &F) {
  int64_t indirect_calls{0};
  for(auto &MBB : F) {
    for (auto &I : MBB) {
      if (auto* CB = dyn_cast<CallBase>(&I)) {
        if (CB->isIndirectCall()) {
          const DebugLoc &Loc = I.getDebugLoc();
          std::string Dwarf;
          if (Loc) {
              std::stringstream Stream = writeDebugLocToStream(&Loc);
              Dwarf = Stream.str();
          }
          // errs() << Dwarf << '\n';
          auto NumberOfParam = CB->getFunctionType()->getNumParams();
          if (NumberOfParam >= 7) {
            NumberOfParam = 7;
          }
          // Ruturaj: Store parameter and type encodings per callsite.
          CallSiteParams[Dwarf] = getParameters(CB->getFunctionType());
          CallSiteRet[Dwarf] = getReturn(CB->getFunctionType());
          ++indirect_calls;
        }
      }
    }
  }
  // errs() << indirect_calls << '\n';
  return indirect_calls;
}

// This method implements what the pass does.
// This method is being called by new pass and legacy pass.
void visitor(Module &M) {
  errs() << "[Binary-CFI] begin analysis of module: "<< M.getName() << "\n";
  
  int64_t total_callsites{0};
  int64_t total_funs{0};

  for (auto &F : M) {
    if (isBlackListed(F)) {
      continue;
    }

    // Collect function arguments counts, type and return type.
    analyseCallTarget(F);

    // Collect indirect callsite arguments counts, type and return type.
    total_callsites += analyseCallSite(F);
    ++total_funs;
  }

  errs() << total_callsites << '\n';
  errs() << total_funs << '\n';

  // Ruturaj: store input metadata in a map structure
  storeAdditionalData(M, std::to_string(total_callsites)+"_"+std::to_string(total_funs));
}

// New PM implementation
struct BinaryCFI : PassInfoMixin<BinaryCFI> {
  // Main entry point, takes IR unit to run the pass on (&F) and the
  // corresponding pass manager (to be queried if need be)
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    visitor(M);
    return PreservedAnalyses::all();
  }

  // Without isRequired returning true, this pass will be skipped for functions
  // decorated with the optnone LLVM attribute. Note that clang -O0 decorates
  // all functions with optnone.
  static bool isRequired() { return true; }
};

// Legacy PM implementation.
// This depends on llvm version, but right now legacy pass is being executed.
struct LegacyBinaryCFI : public ModulePass {
  static char ID;
  LegacyBinaryCFI() : ModulePass(ID) {}
  // Main entry point - the name conveys what unit of IR this is to be run on.
  bool runOnModule(Module &F) override {
    visitor(F);
    // Doesn't modify the input unit of IR, hence 'false'
    return false;
  }
};
} // namespace

//-----------------------------------------------------------------------------
// New PM Registration
//-----------------------------------------------------------------------------
llvm::PassPluginLibraryInfo getBinaryCFIPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "BinaryCFI", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &FPM,
                  ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "binary-cfi") {
                    FPM.addPass(BinaryCFI());
                    return true;
                  }
                  return false;
                });
          }};
}

// This is the core interface for pass plugins. It guarantees that 'opt' will
// be able to recognize BinaryCFI when added to the pass pipeline on the
// command line, i.e. via '-passes=binary-cfi'
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getBinaryCFIPluginInfo();
}

//-----------------------------------------------------------------------------
// Legacy PM Registration
//-----------------------------------------------------------------------------
// The address of this variable is used to uniquely identify the pass. The
// actual value doesn't matter.
char LegacyBinaryCFI::ID = 0;

// This is the core interface for pass plugins. It guarantees that 'opt' will
// recognize LegacyBinaryCFI when added to the pass pipeline on the command
// line, i.e.  via '--legacy-hello-world'
static RegisterPass<LegacyBinaryCFI>
    X("legacy-binary-cfi",
      "Binary CFI",
      true, // This pass doesn't modify the CFG => true
      true // This pass is not a pure analysis pass => false
    );

static void loadPass(const PassManagerBuilder &Builder, llvm::legacy::PassManagerBase &PM) {
  PM.add(new LegacyBinaryCFI());
}

static llvm::RegisterStandardPasses
    RegisterBinaryCFI(PassManagerBuilder::EP_FullLinkTimeOptimizationLast, loadPass);
