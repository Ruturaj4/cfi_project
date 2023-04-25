# Copyright (c) University of Kansas and affiliates.

import subprocess
import argparse
import pandas as pd
import numpy as np
import os
# from thefuzz import process


def addr2line(bin, path, ida_anal, col, llvm_callsite=None) -> list:
    dwarf = []
    # The set of callisites in llvm to match.
    # match_set = set()
    # index_list = llvm_callsite.index.values.tolist()
    for _,row in ida_anal.iterrows():
        cmd = ["llvm-symbolizer", "--obj=" + bin, "-f", row[col], "--basenames"]
        dwarflines = subprocess.check_output(cmd)
        try:
            dwarfline = dwarflines.splitlines()[1]
        except:
            dwarf.append(np.nan)
            continue
        if "?" in dwarfline.decode():
            dwarf.append(np.nan)
            continue
        # Remove **(discriminator 7)** which appears in addr2line output.
        # For e.g. perlio.c:1375 (discriminator 7).
        dwarfline = dwarfline.split()[0]
        dwarf.append(dwarfline.decode())
    return dwarf


def convert_ida_anal(bin, path, ida_anal) -> pd.core.frame.DataFrame:
    dwarf = addr2line(bin, path, ida_anal, ("Ins_ida", "(The dwarf info of this callsite)_ida"))
    ida_anal.insert(loc=0, column=("Dwarf","(The dwarf info of this callsite)"), value=dwarf)
    return ida_anal


def convert_ida_callsite(bin, path, ida_callsite, llvm_callsite) -> pd.core.frame.DataFrame:
    dwarf = addr2line(bin, path, ida_callsite, ("Ins_ida"), llvm_callsite)
    ida_callsite.insert(loc=0, column=("Dwarf"), value=dwarf)
    return ida_callsite


def clean_df(df) -> pd.core.frame.DataFrame:
    # Remove second header.
    df.columns = df.columns.droplevel(-1)
    # Drop nan columns.
    df.dropna(how='all', axis=1, inplace=True)
    # Drop columns with 0 values.
    df = df.loc[:, (df != 0).any(axis=0)]
    return df


def convert_dwarf(dwarf):
    return dwarf.split("/")[-1]
    #return ":".join(dwarf.split(":", 2)[:2])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--bin', dest='bin', help='Input Binary.', type=str, required=True)
    parser.add_argument('-p', '--path', dest='idapath', help='Ida output path.', type=str, required=True)
    
    bin = parser.parse_args().bin
    idapath = parser.parse_args().idapath
    
    path, exe = os.path.split(bin)
    
    # ida_anal = pd.read_csv(os.path.join(idapath, "IDAoutput/") + exe + "-Indirect.csv", header=[0,1])
    # llvm_anal = pd.read_csv(os.path.join(idapath, "SDOutput/") + exe + "-Indirect.csv", header=[0,1])
    
    ida_fun = pd.read_csv(os.path.join(idapath, "IDAoutput/") + exe + "-Fun.csv", header=[0])
    llvm_fun = pd.read_csv(os.path.join(idapath, "SDOutput/") + exe + "-Fun.csv", header=[0])
    
    ida_callsite = pd.read_csv(os.path.join(idapath, "IDAoutput/") + exe + "-Callsite.csv", header=[0])
    llvm_callsite = pd.read_csv(os.path.join(idapath, "SDOutput/") + exe + "-Callsite.csv", header=[0])
    
    # Add _ida suffix for ida generated columns.
    # ida_anal = ida_anal.add_suffix('_ida')
    ida_fun.columns = ["{}{}".format(c, "" if c == "Function" else "_ida") for c in ida_fun.columns]
    ida_callsite = ida_callsite.add_suffix('_ida')
    
    # Use addr2line to get dwarf information.
    # ida_anal = convert_ida_anal(bin, path, ida_anal)
    ida_callsite = convert_ida_callsite(bin, path, ida_callsite , llvm_callsite)
    
    # llvm_anal = clean_df(llvm_anal)
    # ida_anal = clean_df(ida_anal)
    
    # Combine llvm analysis dfs.
    # Remove column values from "Dwarf" in llvm df as addr2line command output doesn't include them.
    # llvm_anal["Dwarf"] = llvm_anal["Dwarf"].apply(convert_dwarf)
    # llvm_anal = llvm_anal.drop_duplicates(subset=["Dwarf"])
    # ida_anal = ida_anal.drop_duplicates(subset=["Dwarf"])
    # df = pd.concat([llvm_anal.set_index('Dwarf'),ida_anal.set_index('Dwarf')], axis=1, join='outer')
    # df.to_csv(os.path.join(idapath, exe) + "-clean.csv")
    
    # Combine llvm function dfs.
    df = pd.concat([llvm_fun.set_index('Function'),ida_fun.set_index('Function')], axis=1, join='outer')
    df.to_csv(os.path.join(idapath, exe) + "-fun-clean.csv")

    # Combine llvm callsite dfs.
    # Remove column values from "Dwarf".
    llvm_callsite["Dwarf"] = llvm_callsite["Dwarf"].apply(convert_dwarf)
    
    df = llvm_callsite.merge(ida_callsite, on="Dwarf", how="outer")
    df.to_csv(os.path.join(idapath, exe) + "-callsite-clean.csv")


if __name__ == "__main__":
    main()
