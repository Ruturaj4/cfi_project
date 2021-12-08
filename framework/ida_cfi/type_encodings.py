def encode(tif):
    # type: (idaapi.tinfo) -> int (encoded type)

    # may use realtype to decide the correct type
    #typeid = tif.get_realtype()

    # decide type
    itype = None
    # void type
    if tif.is_void():
        itype = 1
    # integral type
    elif tif.is_integral():
        # bit type, i am unsure if this exists
        if tif.get_size() < 1:
            itype = 2
        # int8, char, bool
        if tif.is_char() or tif.is_bool() or tif.get_size() == 1:
            itype = 3
        # int16
        elif tif.is_int16() or tif.get_size() == 2:
            itype = 4
        # int32
        elif tif.is_int32() or tif.get_size() == 3:
            itype = 5
        # int64, int128
        elif tif.is_int64() or tif.get_size() >= 4:
            itype = 6
    # floating type
    elif tif.is_floating():
        # half type
        if tif.get_size() < 4:
            itype = 7
        # float type
        elif tif.is_float() and tif.get_size() == 4:
            itype = 8
        # double type
        elif tif.is_double():
            itype = 9
        # FP80, FP128, PPC_FP128
        else:
            itype = 10
    elif tif.is_ptr():
        itype = 11
    elif tif.is_struct():
        itype = 12
    elif tif.is_array():
        itype = 13
    else:
        itype = 14
    return itype
