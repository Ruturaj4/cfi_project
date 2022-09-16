# Copyright (c) University of Kansas and affiliates.
# Most of the naming conventions are according to the original
# llvm-cfi project.

from ida_imports import *
import collections
import os
import csv
import sys

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# /** CallSiteInfo encapsulates all analysis data for a single CallSite.
#      *  Iff isVirtual == false:
#      *    FunctionName, ClassName, PreciseName
#      *    and SubHierarchyMatches, PreciseSubHierarchyMatches, HierarchyIslandMatches
#      *    will not contain meaningful data.
#      * */
class CallSiteInfo():
    def __init__(self, _Params, _isVirtual=False,_FunctionName="", _ClassName="", _PreciseName=""):
        self.Params = _Params
        self.isVirtual = _isVirtual
        self.FunctionName = _FunctionName
        self.ClassName = _ClassName
        self.PreciseName = _PreciseName
        self.DisplayName = ""
        self.Dwarf = ""
        # TODO: Add encodings.
        self.TargetSignatureMatches = -1;
        self.ShortTargetSignatureMatches = -1;
        self.PreciseTargetSignatureMatches= -1;
        self.NumberOfParamMatches = -1;

        self.TargetSignatureMatches_virtual = -1;
        self.ShortTargetSignatureMatches_virtual = -1;
        self.PreciseTargetSignatureMatches_virtual = -1;
        self.NumberOfParamMatches_virtual = -1;

        self.SubHierarchyMatches = -1;
        self.PreciseSubHierarchyMatches = -1;
        self.HierarchyIslandMatches = -1;

# Model data structures.

# Counts analysed CallSites.
CallSiteCount = 0
# Info for every analysed CallSite.
Data = []

# Metric results (used for sorting CallSiteInfo).
# TODO: virtual metric.
MetricIndirect = collections.defaultdict(list)

# Baseline.
AllFunctions = set()
# Baseline v funcions.
AllVFunctions = set()

# Function type matching data.
PreciseTargetSignature = collections.defaultdict(set)
TargetSignature = collections.defaultdict(set)
ShortTargetSignature = collections.defaultdict(set)
NumberOfParameters = [0]*8
NumberOfParametersList = [set() for _ in range(8)]

# Encodings contains the three relevant encodings.
class Encodings:
    def __init__(self, _Normal, _Short, _Precise):
        self.Normal = _Normal
        self.Short = _Short
        self.Precise = _Precise

    @ staticmethod
    def encodeFunction(param_list, return_t, encodePointers, encodeReturnType=True):
        # Base encoding.
        Encoding = 32
        if len(param_list) < 8:
            if encodeReturnType:
                if encodePointers and return_t[0] == 11:
                    Encoding = 16 + return_t[1]
                else:
                    Encoding = return_t[0]
            for count, name, paratype in param_list:
                if paratype[0] == 11:
                    Encoding = 16 + paratype[1] + Encoding * 32
                else:
                    Encoding = paratype[0] + Encoding * 32
        return Encoding

    @classmethod
    def encode(cls, param_list, return_t):
        Encoding = cls.encodeFunction(param_list, return_t, True)
        EncodingShort = cls.encodeFunction(param_list, return_t, False)
        EncodingPrecise = cls.encodeFunction(param_list, return_t, True, True)
        return cls(Encoding, EncodingShort, EncodingPrecise)

def demangle_func_name(mangled_name, clean=True):
    demangle_attr = idc.get_inf_attr(idc.INF_SHORT_DN if clean else idc.INF_LONG_DN)
    return idc.demangle_name(mangled_name, demangle_attr)

# Function type matching functions.
def analyseCallees(metadata: dict) -> None:
    eprint("[SD] Processing functions...")
    for function in metadata:
        # eprint(function)
        # Get number of parameters.
        NumOfParams = len(metadata[function]["parameter_list"])
        # eprint(metadata[function]["parameter_list"])
        # eprint(f"Number of par: {NumOfParams}")
        if NumOfParams > 7: NumOfParams = 7

        # Encode the function.
        Encode = Encodings.encode(metadata[function]["parameter_list"], metadata[function]["return_t"])

        # Demangle the function name.
        demangled_name = demangle_func_name(function)
        demangled_name = demangled_name if demangled_name else function

        # Fill the data structures.
        AllFunctions.add(function)
        NumberOfParameters[NumOfParams] += 1
        NumberOfParametersList[NumOfParams].add(function)
        TargetSignature[Encode.Normal].add(function)
        ShortTargetSignature[Encode.Short].add(function)
        PreciseTargetSignature[(demangled_name, Encode.Precise)].add(function)

        # Fill the data structures if the function is virtual.
        # TODO: add this to support c++

# Function type.
def analyseCall(function: str, callsite: tuple, Info: CallSiteInfo) -> None:

    global CallSiteCount
    CallSiteCount += 1

    # Instruction address and function name.
    Info.Dwarf = hex(callsite[0])

    NumberOfParam = len(callsite[2])
    if NumberOfParam >= 7: NumberOfParam = 7

    Encode = Encodings.encode(callsite[2], callsite[1])
    Info.Encoding = Encode
    Info.TargetSignatureMatches = len(TargetSignature[Encode.Normal])
    Info.ShortTargetSignatureMatches = len(ShortTargetSignature[Encode.Short])

    Info.NumberOfParamMatches = 0
    for i in range(NumberOfParam+1):
        Info.NumberOfParamMatches += NumberOfParameters[i]

    # TODO: For virtual signatures.

    # TODO: For virtual parameters.

    if Info.isVirtual:
        # TODO: Implement analysis for virtual functions.
        pass
    else:
        Info.DisplayName = function
    Data.append(Info)


def processIndirectCallSites(metadata: dict) -> None:
    countIndirect = 0
    eprint("[SD] Processing indirect CallSites...")
    for function,data in metadata.items():
        for callsite in data["indirect_calls_hx"]:
            Info = CallSiteInfo(len(callsite[2]))
            analyseCall(function, callsite, Info)
            countIndirect += 1
    eprint(f"[SD] Found indirect CallSites: {countIndirect}")

def processVirtualCallSites():
    pass

# Helper Functions.

def applyCallSiteMetric() -> None:
    for entry in Data:
        if entry.isVirtual:
            pass
        else:
            # TODO: does rounding make sense?
            # metric = round(entry.TargetSignatureMatches / len(AllFunctions), 4)
            metric = entry.TargetSignatureMatches / len(AllFunctions)
            MetricIndirect[metric].append(entry)


def writeHeader(indirectfile, writeDetails=True) -> None:
    header = ["Ins","FunctionName","ClassName","PreciseName", \
            "Params", "", "PreciseSrcType (vTrust)", "SrcType (IFCC)", \
            "SafeSrcType (IFCC-safe)", "BinType (TypeArmor)", "Baseline", \
            "", "PreciseSrcType-VFunctions", "SrcType-VFunctions", \
            "SafeSrcType-VFunctions", "BinType-VFunctions", "Baseline-VFunctions"]
    details = ["(The dwarf info of this callsite)", \
                "(The least-derived vfunction used at this vcall)", \
                "(The class defining functionname)", \
                "(The least-derived class of the object used at this vcall)", \
                "(# of params provided by this callsite (=# consumed))", \
                "", \
                "(func sig matching including C/C++ func name & ret type)", \
                "(param type matching w/ pointer types)", \
                "(param type matching wo/ pointer types)", \
                "(Callsite param >= Callee param (up to 6)", \
                "(total # of functions)", \
                "", \
                "(PreciseSrcType only virtual targets)", \
                "(SrcType only virtual targets)", \
                "(SafeSrcType only virtual targets)", \
                "(BinType only virtual targets)", \
                "(total # of virtual targets)"]

    with open(indirectfile, 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        if writeDetails: writer.writerow(details)

def writeAnalysisData(Data, indirectfile) -> None:
    writeHeader(indirectfile)
    with open(indirectfile, 'a', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        for Info in Data:
            writer.writerow([Info.Dwarf,Info.DisplayName,"","",Info.Params,"","",Info.TargetSignatureMatches, \
            Info.ShortTargetSignatureMatches, Info.NumberOfParamMatches, len(AllFunctions), "", "",\
            "","","",""])

def writeMetricIndirect(indirectfilemetric) -> None:
    if not MetricIndirect: return
    writeHeader(indirectfilemetric)
    # ExportedLines = set()
    i = 0
    with open(indirectfilemetric, 'a', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        for metric in sorted(MetricIndirect.keys(), reverse=True):
            for Info in MetricIndirect[metric]:
                # if Info.Dwarf in ExportedLines: continue
                # ExportedLines.add(Info.Dwarf)

                vTrust = set()
                IFCC = set()
                IFCCSafe = set()
                Typearmor = set()

                demangled_name = demangle_func_name(Info.FunctionName)
                demangled_name = demangled_name if demangled_name else Info.FunctionName

                vTrust = PreciseTargetSignature[(demangled_name, Info.Encoding.Precise)]
                IFCC = TargetSignature[Info.Encoding.Normal]
                IFCCSafe = ShortTargetSignature[Info.Encoding.Normal]

                # TODO: fix accordingly
                writer.writerow([Info.Dwarf,Info.DisplayName, "", "", Info.Params, "", "", \
                Info.TargetSignatureMatches, Info.ShortTargetSignatureMatches, Info.NumberOfParamMatches,\
                len(AllFunctions), "", "", "", "", "", "", \
                f"vTrust({len(vTrust)})", f"IFCC({len(IFCC)})", f"IFCCSafe({len(IFCCSafe)})", \
                f"TypeArmor({Info.NumberOfParamMatches})"])

                i += 1
            if i > 50: break

# Write the data in file (along with the metric data).
# This function can be used to co-relate and then display the data.
def storeData() -> None:
    if not Data:
        eprint("[SD] Nothing to store...")
        return
    eprint(f"[SD] Store all CallSites for Module: {ida_nalt.get_input_file_path()}")

    path, file = os.path.split(ida_nalt.get_input_file_path())
    idaoutput = os.path.join(path, "IDAoutput")
    if not os.path.exists(idaoutput):
        os.makedirs(idaoutput)
    indirectfile = os.path.join(idaoutput, file) + "-Indirect.csv"
    writeAnalysisData(Data, indirectfile)
    indirectfilemetric = os.path.join(idaoutput, file) + "-Indirect-metric.csv"
    writeMetricIndirect(indirectfilemetric)


def build_analysis(metadata: dict) -> None:
    eprint("[SD] P7a. Started running the SDAnalysis pass ...")

    # Setup CHA info.

    # Setup callee and callee signature info.
    analyseCallees(metadata)

    # Process the CallSites.
    # Process virtual CallSites.
    processVirtualCallSites()
    # Process indirect CallSites.
    processIndirectCallSites(metadata)
    eprint(f"[SD] Total number of CallSites: {CallSiteCount}")

    # Apply the metric to the CallSiteInfo's in order to sort them.
    applyCallSiteMetric()
    # Store the analysis data.
    storeData()