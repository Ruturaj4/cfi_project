# Copyright (c) University of Kansas and affiliates.

import os

def marx(binary):
    path, file = os.path.split(binary)
    print(path)
