# Copyright (c) University of Kansas and affiliates.

from ida_imports import *
import collections
import os
import csv

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
        # todo: add encodings
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

# model data structures

#counts analysed CallSites
CallSiteCount = 0
# info for every analysed CallSite
Data = []

# metric results (used for sorting CallSiteInfo)
# todo: virtual metric
MetricIndirect = collections.defaultdict(list)

# baseline
AllFunctions = set()
# baseline v funcions
AllVFunctions = set()

# function type matching data
PreciseTargetSignature = collections.defaultdict(set)
TargetSignature = collections.defaultdict(set)
ShortTargetSignature = collections.defaultdict(set)
NumberOfParameters = [0]*8
NumberOfParametersList = [set() for _ in range(8)]

# Encodings contains the three relevant encodings
class Encodings:
    def __init__(self, _Normal, _Short, _Precise):
        self.Normal = _Normal
        self.Short = _Short
        self.Precise = _Precise

    @ staticmethod
    def encodeFunction(param_list, return_t, encodePointers, encodeReturnType=True):
        # base encoding
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

# function type matching functions
def analyseCallees(metadata: dict) -> None:
    print("Processing functions...")
    for function in metadata:
        print(function)
        # get number of parameter
        NumOfParams = len(metadata[function]["parameter_list"])
        if NumOfParams > 7: NumOfParams = 7

        # encode the function
        # print(metadata[function])
        Encode = Encodings.encode(metadata[function]["parameter_list"], metadata[function]["return_t"])

        # demangle the function name
        demangled_name = demangle_func_name(function)
        demangled_name = demangled_name if demangled_name else function

        # fill the data structures
        AllFunctions.add(function)
        NumberOfParameters[NumOfParams] += 1
        NumberOfParametersList[NumOfParams].add(function)
        TargetSignature[Encode.Normal].add(function)
        ShortTargetSignature[Encode.Short].add(function)
        PreciseTargetSignature[(demangled_name, Encode.Precise)].add(function)

        # fill the data structures if the function is virtual
        # todo: add this to support c++

# function type
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
    for i in range(NumberOfParam):
        Info.NumberOfParamMatches += NumberOfParameters[i]

    # todo: for virtual signatures

    # todo: for virtual parameters

    if Info.isVirtual:
        # todo: implement this
        pass
    else:
        Info.DisplayName = function
    Data.append(Info)


def processIndirectCallSites(metadata: dict) -> None:
    countIndirect = 0
    print("Processing indirect CallSites...")
    for function,data in metadata.items():
        for callsite in data["indirect_calls_hx"]:
            Info = CallSiteInfo(len(callsite[2]))
            analyseCall(function, callsite, Info)
            countIndirect += 1
    print(f"Found indirect CallSites: {countIndirect}")

def processVirtualCallSites():
    pass

# Helper Functions

def applyCallSiteMetric() -> None:
    for entry in Data:
        if entry.isVirtual:
            pass
        else:
            # todo: does rounding make sense?
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

                # todo: fix accordingly
                writer.writerow([Info.Dwarf,Info.DisplayName, "", "", Info.Params, "", "", \
                Info.TargetSignatureMatches, Info.ShortTargetSignatureMatches, Info.NumberOfParamMatches,\
                len(AllFunctions), "", "", "", "", "", "", \
                f"vTrust({len(vTrust)})", f"IFCC({len(IFCC)})", f"IFCCSafe({len(IFCCSafe)})", \
                f"TypeArmor({Info.NumberOfParamMatches})"])

                i += 1
            if i > 50: break

# write the data in file (along with the metric data)
# this function can be used to co-relate and then display the data
def storeData() -> None:
    if not Data:
        print("Nothing to store...")
        return
    print(f"Store all CallSites for Module: {ida_nalt.get_input_file_path()}")

    path, file = os.path.split(ida_nalt.get_input_file_path())
    idaoutput = os.path.join(path, "IDAoutput")
    if not os.path.exists(idaoutput):
        os.makedirs(idaoutput)
    indirectfile = os.path.join(idaoutput, os.path.splitext(file)[0]) + "-Indirect.csv"
    writeAnalysisData(Data, indirectfile)
    indirectfilemetric = os.path.join(idaoutput, os.path.splitext(file)[0]) + "-Indirect-metric.csv"
    writeMetricIndirect(indirectfilemetric)


def build_analysis(metadata):
    print("P7a. Started running the SDAnalysis pass ...")

    # setup CHA info

    # setup callee and callee signature info
    analyseCallees(metadata)

    # process the CallSites
    # process virtual callsites
    processVirtualCallSites()
    # process indirect callsites
    processIndirectCallSites(metadata)
    print(f"Total number of CallSites: {CallSiteCount}")

    # apply the metric to the CallSiteInfo's in order to sort them
    applyCallSiteMetric()
    # store the analysis data
    storeData()