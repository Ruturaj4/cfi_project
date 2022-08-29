# Copyright (c) University of Kansas and affiliates.

import os
import json
import function_info
import marx_analysis
import build_models

# Wait for auto-analysis to complete.
idc.auto_wait()

def save_data_text(metadata):
    path, file = os.path.split(ida_nalt.get_input_file_path())
    with open(os.path.join(path, os.path.splitext(file)[0]) + ".idatext", "w") as f:
        count = len(metadata) - 1
        f.write("{}\n".format(count))
        for k,v in metadata.items():
            f.write(f"{k}\n")
            f.write(".return\n")
            t,b = v["return_t"]
            f.write(f"{t} {b}\n")
            f.write(".parameters\n")
            for par in v["parameter_list"]:
                n, name, types = par
                t,b = types
                f.write(f"{t} {b}\n")
            f.write("\n")
        f.write("\n")

def save_data_json(metadata):
    path, file = os.path.split(ida_nalt.get_input_file_path())
    with open(os.path.join(path, os.path.splitext(file)[0]) + ".idajson", "w") as f:
        json.dump(metadata, f)

def main():
    # Collect functions.
    metadata = function_info.function_iterator()
    # print("#### marx analysis ####")
    # Marx analysis.
    marx_analysis.marx(ida_nalt.get_input_file_path())
    # Bulid class hierarchy.
    # ida_cfi.CHA()
    # Build models.
    build_models.build_analysis(metadata)
    # print(metadata)
    # Save files.
    # save_data_json(metadata)
    # save_data_text(metadata)

if  __name__ == '__main__':
    main()

idc.qexit(0)
