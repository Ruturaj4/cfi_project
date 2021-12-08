import os
import json
import function_info
import marx_analysis

# wait for auto-analysis to complete
idc.auto_wait()

def save_data_text(metadata):
    path, file = os.path.split(ida_nalt.get_input_file_path())
    with open(os.path.join(path, os.path.splitext(file)[0]) + ".idatext", "w") as f:
        json.dump(metadata, f)

def save_data_json(metadata):
    path, file = os.path.split(ida_nalt.get_input_file_path())
    with open(os.path.join(path, os.path.splitext(file)[0]) + ".idajson", "w") as f:
        json.dump(metadata, f)

def main():
    # collect functions
    metadata = function_info.function_iterator()
    print("#### marx analysis ####")
    # marx analysis
    marx_analysis.marx(ida_nalt.get_input_file_path())
    # bulid class hierarchy
    # ida_cfi.CHA()
    # save files
    save_data_json(metadata)

if  __name__ == '__main__':
  main()

idc.qexit(0)
