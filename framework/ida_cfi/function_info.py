# Copyright (c) University of Kansas and affiliates.

from ida_imports import *
import type_encodings
import sys
import os

# Store all metadata.
# function: {metadata}
metadata = {}

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def decompile_function(ea) -> ida_hexrays.cfuncptr_t:
    # Instead of throwing an exception on `DecompilationFailure` it just returns `None`.
    try:
        return ida_hexrays.decompile(ea)
    except ida_hexrays.DecompilationFailure:
        return None


# Use typearmor to get argument counts at callsites.
callsites = {}
def get_argument_count_typearmor() -> None:
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


def resolve_type(tif: idaapi.tinfo_t) -> tuple:
    # tuple -> int,int (type, basetype)

    # Get pointer base type.
    ptif= tif.get_pointed_object()

    # Retrieve base and pointer types.
    realtype = type_encodings.encode(tif)
    basetype = realtype
    if realtype == 11:
        basetype = type_encodings.encode(ptif)

    return realtype, basetype


def get_function_parameters(funcdata: list, decomp=False) -> list:
    # list -> List of tuples of parameter type information.
    parameter_list = []
    for i,v in enumerate(funcdata):
        # itype = ida_typeinf.print_tinfo('', 0, 0, idc.PRTYPE_1LINE, v.type, '', '')
        paramter_type = resolve_type(v.tif) if decomp else resolve_type(v.type)
        parameter_list.append(tuple([i, v.name, paramter_type]))
        # print(f"Para {i}: {v.name} (of type {itype} and of location: {v.argloc.atype()})")
    # eprint(parameter_list)
    return parameter_list


def get_function_info_decompiler(ea: int, function: str, decompiled: ida_hexrays.cfuncptr_t) -> None:
    func_tinfo = idaapi.tinfo_t()
    decompiled.get_func_type(func_tinfo)

    # Resolve function return type.
    # This returns a tuple -> (type, basetype).
    # For. e.g. for char * -> (pointer, char).
    # The types are returned in encoded format.
    function_type = resolve_type(func_tinfo.get_rettype())
    
    metadata[function]["return_t"] = function_type
    # Resolve function parameters' type.
    metadata[function]["parameter_list"] = get_function_parameters(decompiled.arguments, True)


def retrieve_function_data(ea: int) -> tuple:
    ## tuple -> idaapi.tinfo, ida_typeinf.func_type_data_t

    # Get function type info.
    func_tinfo = idaapi.tinfo_t()
    ida_nalt.get_tinfo(func_tinfo, ea)

    # Return None if tinfo output is false.
    if not func_tinfo: return None, None

    # Get function details gathered by IDA.
    funcdata = ida_typeinf.func_type_data_t()
    func_tinfo.get_func_details(funcdata)

    return func_tinfo, funcdata


def get_function_info(function: str, func_tinfo: idaapi.tinfo_t, \
    funcdata: ida_typeinf.func_type_data_t) -> None:
    # Resolve function return type.
    # This returns a tuple -> (type, basetype).
    # For. e.g. for char * -> (pointer, char).
    # The types are returned in encoded format.
    function_type = resolve_type(func_tinfo.get_rettype())
    metadata[function]["return_t"] = function_type

    # Resolve function parameters' type.
    # max_size = sys.maxsize*2+1
    metadata[function]["parameter_list"] = get_function_parameters(funcdata)



# TODO: Implement this for functions which give decompiler error.
def bb_interator(ea: int) -> None:
    flowchart = idaapi.FlowChart(idaapi.get_func(ea))
    for bb in flowchart:
        ins = bb.start_ea
        while ins < bb.end_ea:
            if idc.get_operand_type(ins, 0) not in {idc.o_imm, idc.o_far, idc.o_near}:
                    decode = idautils.DecodeInstruction(ins)
                    # Only check for call instructions.
                    if decode and decode.get_canon_mnem() in ["call"]:
                        pass
            ins = idc.next_head(ins)
            

# Callsite extractor.
# Extract argument type, return type.
def callsite_extractor(ea: int, function: str, decompiled: ida_hexrays.cfuncptr_t) -> None:
    metadata[function]["indirect_calls"] = []
    metadata[function]["indirect_calls_hx"] = []
    
    # In case of decompilation failure, fall back to disassembly parsing.
    if decompiled is None:
        # bb_interator(ea)
        return
    
    class CblockVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)

        def visit_expr(self, expr):
            if expr.op == ida_hexrays.cot_call:
                # o_imm      = ida_ua.o_imm       # Immediate Value                      value
                # o_far      = ida_ua.o_far       # Immediate Far Address  (CODE)        addr
                # o_near     = ida_ua.o_near      # Immediate Near Address (CODE)        addr
                if idc.get_operand_type(expr.ea, 0) not in {idc.o_imm, idc.o_far, idc.o_near}:
                    decode = idautils.DecodeInstruction(expr.ea)
                    # Only check for call instructions.
                    if decode and decode.get_canon_mnem() in ["call"]:
                        callsite_arguments = []
                        # Get callsite arguments and their types.
                        for index, arg in enumerate(expr.a):
                            # Get argument count from hex-rays callsites.
                            callsite_arguments.append(tuple([index, "default", resolve_type(arg.type)]))
                        callsite_return_type = resolve_type(expr.type)
                        metadata[function]["indirect_calls_hx"].append((expr.ea,callsite_return_type, callsite_arguments))
                        # Get argument count from typearmor callsites.
                        if hex(expr.ea) in callsites:
                            callsites[hex(expr.ea)][1] = True
                            metadata[function]["indirect_calls"].append((expr.ea, callsites[hex(expr.ea)][0]))
                        else:
                            # Assign 0 call arguments if not detected by typearmor.
                            # eprint(f"Instruction {hex(expr.ea)} Not Found in TypeArmor!")
                            metadata[function]["indirect_calls"].append((expr.ea, 0))
            return 0
    cbv = CblockVisitor()
    cbv.apply_to(decompiled.body, None)


def function_iterator() -> dict:
    # First recover callsite info from typearmor.
    eprint("Recovering argument count from typearmor....")
    # get_argument_count_typearmor()

    ignore_funs = {"_start", "start", "frame_dummy", "deregister_tm_clones", "fini"}
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
        if not func_tinfo: continue
        
        # Store function.
        metadata[function] = {}

        # Get function parameters and return type.
        get_function_info(function, func_tinfo, funcdata)
        
        # Try to decompile the function
        decompiled = decompile_function(ea)

        # This improves the function information we
        # get when the decompiler is active.
        if decompiled is not None:
            get_function_info_decompiler(ea, function, decompiled)
        
        # Get indirect call instructions.
        # First run typearmor and then map those to ida output.
        # get_indirect_callsites(ea, function, callsites)
        callsite_extractor(ea, function, decompiled)
    # typearmour false negatives.
    # for key, val in callsites.items():
    #     if val[1] == False: print(f"key: {key}")
    return metadata
