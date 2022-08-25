// Ruturaj: this file runs before SafeDispatch and implements
// the module modification pass
// modify CMakeLists.txt and added filename of this file

// all imports similar to SafeDispatchAnalysis file

#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Transforms/IPO/SafeDispatchLayoutBuilder.h"
#include "llvm/Transforms/IPO/SafeDispatchLogStream.h"
#include "llvm/Transforms/IPO/SafeDispatchTools.h"

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>
#include <fstream>
#include <sstream>
using namespace llvm;

namespace llvm {
class ModifyModule : public ModulePass {
public:
    static char ID;
    ModifyModule() : ModulePass(ID){
      std::cerr << "Initializing modification pass" << "\n";
      initializeModifyModulePass(*PassRegistry::getPassRegistry());
    }
    ~ModifyModule() override {
        sdLog::stream() << "deleting ModifyModulePass pass\n";
    }
private:
    bool runOnModule(Module &M) override {
      return false;
    }
};
}

char ModifyModule::ID = 0;

INITIALIZE_PASS(ModifyModule, "modifyModule", "Modify module", false, false)

ModulePass *llvm::createModifyModulePass() {
    return new ModifyModule();
}
