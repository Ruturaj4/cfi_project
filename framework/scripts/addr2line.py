# Copyright (c) University of Kansas and affiliates.

import subprocess
import argparse
import pandas as pd
import numpy as np
import os

def addr2line(bin, path, ida_anal) -> pd.core.frame.DataFrame:
    dwarf = []
    for _,row in ida_anal.iterrows():
        cmd = ["addr2line", "-e", bin, "-f", row[("Ins_ida", "(The dwarf info of this callsite)_ida")]]
        dwarflines = subprocess.check_output(cmd)
        function, dwarfline = dwarflines.splitlines()
        if function.decode() == "??" or dwarfline.decode() == "??:?":
            dwarf.append(np.nan)
            continue
        # remove **(discriminator 7)** which appears in addr2line output
        # for e.g. perlio.c:1375 (discriminator 7)
        dwarfline = dwarfline.split()[0]
        dwarf.append(dwarfline.decode().split(path.split("/")[-1])[-1][1:])
    ida_anal.insert(loc=0, column=("Dwarf","(The dwarf info of this callsite)"), value=dwarf)
    return ida_anal


def clean_df(df) -> pd.core.frame.DataFrame:
    # Remove second header.
    df.columns = df.columns.droplevel(-1)
    # Drop nan columns.
    df.dropna(how='all', axis=1, inplace=True)
    # Drop columns with 0 values.
    df = df.loc[:, (df != 0).any(axis=0)]
    return df


def convert_dwarf(dwarf):
    return ":".join(dwarf.split(":", 2)[:2])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--bin', dest='bin', help='Input Binary.', type=str, required=True)
    
    bin = parser.parse_args().bin
    
    path, exe = os.path.split(bin)
        
    ida_anal = pd.read_csv(os.path.join(path, "IDAoutput/") + exe + "-Indirect.csv", header=[0,1])
    llvm_anal = pd.read_csv(os.path.join(path, "SDOutput/") + exe + "-Indirect.csv", header=[0,1])
    
    # Add _ida suffix for ida generated columns.
    ida_anal = ida_anal.add_suffix('_ida')
    
    # Use addr2line to get dwarf information.
    ida_anal = addr2line(bin, path, ida_anal)
    
    llvm_anal = clean_df(llvm_anal)
    ida_anal = clean_df(ida_anal)
    # Remove column values from "Dwarf" in llvm df.
    llvm_anal["Dwarf"] = llvm_anal["Dwarf"].apply(convert_dwarf)
    llvm_anal = llvm_anal.drop_duplicates(subset=["Dwarf"])
    ida_anal = ida_anal.drop_duplicates(subset=["Dwarf"])
    df = pd.concat([llvm_anal.set_index('Dwarf'),ida_anal.set_index('Dwarf')], axis=1, join='outer')
    df.to_csv(bin + "-clean.csv")


if __name__ == "__main__":
    main()
