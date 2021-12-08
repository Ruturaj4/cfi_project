from ida_imports import *
import type_encodings
import sys

# store all metadata
# function: metadata
metadata = {}

def resolve_type(tif):
    # type: (idaapi.tinfo) -> int,int (type, basetype)

    # get pointer base type
    ptif= tif.get_pointed_object()

    # retrieve base and pointer types
    realtype = type_encodings.encode(tif)
    basetype = realtype
    if realtype == 11:
        basetype = type_encodings.encode(ptif)
    return realtype, basetype

def get_function_parameters(funcdata, decomp=False):
    # type: (list, bool) -> list

    parameter_list = []
    for i,v in enumerate(funcdata):
        # itype = ida_typeinf.print_tinfo('', 0, 0, idc.PRTYPE_1LINE, v.type, '', '')
        paramter_type = resolve_type(v.tif) if decomp else resolve_type(v.type)
        if not v.name: vname = "noname"
        parameter_list.append(tuple([i, v.name, paramter_type]))
        # print(f"Para {i}: {v.name} (of type {itype} and of location: {v.argloc.atype()})")
    return parameter_list

def get_function_info_decompiler(ea, function):
    # type: (int, str) -> None

    try:
        decompiled = ida_hexrays.decompile(ea)
    except ida_hexrays.DecompilationFailure:
        return
    func_tinfo = idaapi.tinfo_t()
    decompiled.get_func_type(func_tinfo)

    # resolve function return type
    # this returns a tuple -> (type, basetype)
    # for. e.g. for char * -> (pointer, char)
    # the types are returned in encoded format
    function_type = resolve_type(func_tinfo.get_rettype())
    metadata[function]["return_t"] = function_type
    # resolve function parameters' type
    # max_size = sys.maxsize*2+1
    metadata[function]["parameter_list"] = get_function_parameters(decompiled.arguments, True)

def retrieve_function_data(ea):
    # type: (int) -> idaapi.tinfo, ida_typeinf.func_type_data_t

    # get function type info
    func_tinfo = idaapi.tinfo_t()
    ida_nalt.get_tinfo(func_tinfo, ea)

    # return None if tinfo output is false
    if not func_tinfo: return None, None
    funcdata = ida_typeinf.func_type_data_t()
    func_tinfo.get_func_details(funcdata)
    return func_tinfo, funcdata

    ######### retrieve return data using func_type_data_t
    # function_details = idaapi.func_type_data_t()
    # func_tinfo.get_func_details(function_details)
    # return if fuction data is not available
    # if not func_tinfo.get_func_details(funcdata):
    #     return None
    # resolve_type(function_details.rettype)

def get_function_info(ea, function):
    # type: (int, str) -> None

    # retrieve function data
    func_tinfo, funcdata = retrieve_function_data(ea)
    if not funcdata: return
    # resolve function return type
    # this returns a tuple -> (type, basetype)
    # for. e.g. for char * -> (pointer, char)
    # the types are returned in encoded format
    function_type = resolve_type(func_tinfo.get_rettype())
    metadata[function]["return_t"] = function_type

    # resolve function parameters' type
    # max_size = sys.maxsize*2+1
    metadata[function]["parameter_list"] = get_function_parameters(funcdata)

def get_indirect_callsites(ea, function):
    # type: (int, str) -> None

    for ins in idautils.FuncItems(ea):
        cmd = idc.GetDisasm(ins)
        if "call" == idc.print_insn_mnem(ins):
            # avoid near call
            if idc.get_operand_type(ins, 0) != idc.o_near:
                print(cmd)
                print(idc.get_operand_type(ins, 0))

def function_iterator():
    # type: (None) -> dict

    ignore_funs = {"_start", "frame_dummy"}
    ida_hexrays.init_hexrays_plugin()
    for ea in idautils.Functions():
        # ignore function if not in text section
        # if not idc.get_segm_name(ea) == ".text":
        #     continue
        function = idc.get_func_name(ea)

        # ingore unnecessary funs
        if function.startswith("."): continue
        if function.startswith("__"): continue
        if function in ignore_funs: continue

        print(function)
        # store function
        metadata[function] = {}

        # get function parameters and return type
        get_function_info(ea, function)
        # this improves the function information we
        # get when the decompiler is inactive
        get_function_info_decompiler(ea, function)
        # get indirect call instructions
        # get_indirect_callsites(ea, function)

        if idc.get_frame_id(ea) == None:
            continue
    # print(metadata)
    return metadata
