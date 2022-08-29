# Copyright (c) University of Kansas and affiliates.

from ida_imports import *
import type_encodings
import sys
import os
import re

# Store all metadata.
# function: metadata
metadata = {}

# Use typearmor to get argument counts at callsites.
callsites = {}
def get_argument_count_typearmor() -> None:
    # type: () -> None
    path, file = os.path.split(ida_nalt.get_input_file_path())
    with open(os.path.join(os.path.join(path, "out"), "binfo."+file), "r") as f:
        Flag = False
        for line in f:
            if line == "[icall-args]\n":
                Flag = True
            elif Flag:
                if line == "\n": break
                callsite = line.split()
                callsites[callsite[0]] = [int(callsite[2]), False]

def resolve_type(tif) -> tuple:
    ## type: (idaapi.tinfo) -> int,int (type, basetype)

    # Get pointer base type.
    ptif= tif.get_pointed_object()

    # Retrieve base and pointer types.
    realtype = type_encodings.encode(tif)
    basetype = realtype
    if realtype == 11:
        basetype = type_encodings.encode(ptif)
    return realtype, basetype

def get_function_parameters(funcdata, decomp=False) -> list:
    # type: (list, bool) -> list

    parameter_list = []
    for i,v in enumerate(funcdata):
        # itype = ida_typeinf.print_tinfo('', 0, 0, idc.PRTYPE_1LINE, v.type, '', '')
        paramter_type = resolve_type(v.tif) if decomp else resolve_type(v.type)
        if not v.name: vname = "noname"
        parameter_list.append(tuple([i, v.name, paramter_type]))
        # print(f"Para {i}: {v.name} (of type {itype} and of location: {v.argloc.atype()})")
    return parameter_list

def get_function_info_decompiler(ea, function) -> None:
    # type: (int, str) ->  None

    try:
        decompiled = ida_hexrays.decompile(ea)
    except ida_hexrays.DecompilationFailure:
        return

    func_tinfo = idaapi.tinfo_t()
    decompiled.get_func_type(func_tinfo)

    # Resolve function return type.
    # This returns a tuple -> (type, basetype).
    # For. e.g. for char * -> (pointer, char).
    # The types are returned in encoded format.
    function_type = resolve_type(func_tinfo.get_rettype())
    metadata[function]["return_t"] = function_type
    # Resolve function parameters' type.
    # max_size = sys.maxsize*2+1
    metadata[function]["parameter_list"] = get_function_parameters(decompiled.arguments, True)

def retrieve_function_data(ea) -> tuple:
    ## type: (int) -> idaapi.tinfo, ida_typeinf.func_type_data_t

    # Get function type info.
    func_tinfo = idaapi.tinfo_t()
    ida_nalt.get_tinfo(func_tinfo, ea)

    # Return None if tinfo output is false.
    if not func_tinfo: return None, None
    funcdata = ida_typeinf.func_type_data_t()
    func_tinfo.get_func_details(funcdata)
    return func_tinfo, funcdata

    ######### Retrieve return data using func_type_data_t.
    # function_details = idaapi.func_type_data_t()
    # func_tinfo.get_func_details(function_details)
    # return if fuction data is not available
    # if not func_tinfo.get_func_details(funcdata):
    #     return None
    # resolve_type(function_details.rettype)

def get_function_info(function, func_tinfo, funcdata) -> None:
    # type: (str, tinfo, func_type_data_t) -> None
    # Resolve function return type.
    # This returns a tuple -> (type, basetype).
    # For. e.g. for char * -> (pointer, char).
    # The types are returned in encoded format.
    function_type = resolve_type(func_tinfo.get_rettype())
    metadata[function]["return_t"] = function_type

    # Resolve function parameters' type.
    # max_size = sys.maxsize*2+1
    metadata[function]["parameter_list"] = get_function_parameters(funcdata)

# Callsite extractor.
# Extract argument type, return type.
def callsite_extractor(ea, function) -> None:
    # type: (str, int) -> None

    metadata[function]["indirect_calls"] = []
    metadata[function]["indirect_calls_hx"] = []
    try:
        cfunc = ida_hexrays.decompile(ea)
    except ida_hexrays.DecompilationFailure:
        return
    class cblock_visitor_t(ida_hexrays.ctree_visitor_t):

        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)

        def visit_expr(self, expr):
            if expr.op == ida_hexrays.cot_call:
                if idc.get_operand_type(expr.ea, 0) not in {idc.o_imm, idc.o_far, idc.o_near}:
                    decode = idautils.DecodeInstruction(expr.ea)
                    # Only check for call instructions.
                    # if any(x in disasm for x in {"jmp", "call"}):
                    if decode and decode.get_canon_mnem() in ["call", "jmp"]:
                        # Return if the address targets to the code section.
                        # This removes instructions which use rip addressing.
                        if "cs:" in (idc.print_operand(expr.ea,0)): return 0
                        print(hex(expr.ea))
                        print(idc.GetDisasm(expr.ea))
                        print(function)
                        # print(ida_lines.tag_remove(ida_ua.print_operand(expr.ea, 0)))
                        callsite_arguments = []
                        # Get callsite arguments and their types.
                        for index, arg in enumerate(expr.a):
                            # Get argument count from hex-rays callsites.
                            callsite_arguments.append(tuple([index, "default", resolve_type(arg.type)]))
                        callsite_return_type = resolve_type(expr.type)
                        metadata[function]["indirect_calls_hx"].append((expr.ea,callsite_return_type, callsite_arguments))
                        # print(expr.x.string)
                        # Get argument count from typearmor callsites.
                        if hex(expr.ea) in callsites:
                            callsites[hex(expr.ea)][1] = True
                            metadata[function]["indirect_calls"].append((expr.ea, callsites[hex(expr.ea)][0]))
                        else:
                            # Assign 0 call arguments if not detected by typearmor.
                            print(f"Instruction {hex(expr.ea)} Not Found in TypeArmor!")
                            metadata[function]["indirect_calls"].append((expr.ea, 0))
            return 0
    cbv = cblock_visitor_t()
    cbv.apply_to(cfunc.body, None)

# TODO: unused.
def bb_interator(ea, function) -> None:
    # type: (int, str) -> None
    flowchart = idaapi.FlowChart(idaapi.get_func(ea))
    for bb in flowchart:
        ins = bb.start_ea
        while ins < bb.end_ea:
            cmd = idc.GetDisasm(ins)
            ins = idc.next_head(ins)


def function_iterator() -> dict:
    # type: () -> dict

    # First recover callsite info from typearmor.
    print("recovering argument count from typearmor....")
    # get_argument_count_typearmor()
    ignore_funs = {"_start", "frame_dummy", "deregister_tm_clones", "fini"}
    ida_hexrays.init_hexrays_plugin()
    for ea in idautils.Functions():
        # Ignore function if not in text section.
        # if not idc.get_segm_name(ea) == ".text":
        #     continue
        function = idc.get_func_name(ea)
        # Ingore unnecessary funs.
        if function.startswith("."): continue
        if function.startswith("__"): continue
        if function in ignore_funs: continue

        # Retrieve function data.
        func_tinfo, funcdata = retrieve_function_data(ea)
        # if not funcdata: continue
        # Store function.
        metadata[function] = {}

        # Get function parameters and return type.
        get_function_info(function, func_tinfo, funcdata)
        # This improves the function information we
        # get when the decompiler is active.
        get_function_info_decompiler(ea, function)

        # Get indirect call instructions.
        # First run typearmor and then map those to ida output.
        # get_indirect_callsites(ea, function, callsites)
        callsite_extractor(ea, function)
    # typearmour false negatives.
    # for key, val in callsites.items():
    #     if val[1] == False: print(f"key: {key}")
    # print(metadata)
    return metadata
