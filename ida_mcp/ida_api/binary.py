"""IDA 原子操作（binary 域）。

拆分自单文件 ida_api.py。共享基础设施（IDA 模块导入、IDAError、run_in_main、
SEARCH_HARD_LIMIT）在 core.py，此处 `from .core import *` 引入。函数体与拆分前
逐字节一致。
"""

from .core import *  # noqa: F401,F403


def get_segments():
    def do():
        result = []
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue
            perm = seg.perm
            perm_str = "{}{}{}".format(
                "r" if perm & ida_segment.SEGPERM_READ else "-",
                "w" if perm & ida_segment.SEGPERM_WRITE else "-",
                "x" if perm & ida_segment.SEGPERM_EXEC else "-",
            )
            result.append({
                "name": ida_segment.get_segm_name(seg),
                "start": seg.start_ea,
                "end": seg.end_ea,
                "size": seg.end_ea - seg.start_ea,
                "perm": perm_str,
            })
        return result

    return run_in_main(do)


def get_imports():
    def do():
        result = []
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module = ida_nalt.get_import_module_name(i) or ""

            def cb(ea, name, ordinal, _module=module):
                import_name = str(name) if name else f"ordinal_{ordinal}"
                result.append({"name": import_name, "ea": ea,
                               "module": _module, "ordinal": ordinal})
                return True

            ida_nalt.enum_import_names(i, cb)
        return result

    return run_in_main(do)


def get_exports():
    def do():
        result = []
        for index, ordinal, ea, name in idautils.Entries():
            result.append({"name": name, "ea": ea, "ordinal": ordinal})
        return result

    return run_in_main(do)


def get_strings():
    def do():
        result = []
        for s in idautils.Strings():
            try:
                value = str(s)
            except Exception:  # noqa: BLE001
                continue
            result.append({"value": value, "ea": s.ea,
                           "length": s.length, "type": s.strtype})
        return result

    return run_in_main(do)


def get_globals():
    """Return named data objects that are not contained in a function."""
    def do():
        result = []
        for ea, name in idautils.Names():
            if not name or ida_funcs.get_func(ea) is not None:
                continue
            flags = ida_bytes.get_full_flags(ea)
            if not ida_bytes.is_data(flags):
                continue
            result.append({"name": str(name), "ea": ea})
        result.sort(key=lambda item: (item["ea"], item["name"]))
        return result

    return run_in_main(do)


def get_data_profile(ea, read_offset=0, read_size=16,
                     dereference_depth=0):
    """Read one consistent bounded data and typed-pointer snapshot."""
    def do():
        def require_int(value, name, minimum, maximum):
            if (isinstance(value, bool) or not isinstance(value, int)
                    or value < minimum or value > maximum):
                raise IDAError(
                    "INVALID_PARAM",
                    f"{name} must be between {minimum} and {maximum}")

        require_int(read_offset, "read_offset", 0, 1048576)
        require_int(read_size, "read_size", 1, 4096)
        require_int(dereference_depth, "dereference_depth", 0, 4)

        def type_size(tif):
            try:
                size = tif.get_size()
            except Exception:  # noqa: BLE001
                return None
            badsize = getattr(idaapi, "BADSIZE", None)
            if (isinstance(size, bool) or not isinstance(size, int)
                    or size < 0 or size == badsize):
                return None
            return size

        def exact_tinfo(address):
            tif = ida_typeinf.tinfo_t()
            try:
                if ida_nalt.get_tinfo(tif, address):
                    return tif
            except Exception:  # noqa: BLE001
                return None
            return None

        def pointed_object(tif):
            try:
                pointed = tif.get_pointed_object()
            except TypeError:
                pointed = ida_typeinf.tinfo_t()
                try:
                    if not tif.get_pointed_object(pointed):
                        return None
                except Exception:  # noqa: BLE001
                    return None
            except Exception:  # noqa: BLE001
                return None
            if pointed is None or isinstance(pointed, bool):
                pointed = ida_typeinf.tinfo_t()
                try:
                    if not tif.get_pointed_object(pointed):
                        return None
                except Exception:  # noqa: BLE001
                    return None
            return pointed

        def read_prefix(address, size):
            loaded = 0
            for index in range(size):
                try:
                    if not ida_bytes.is_loaded(address + index):
                        break
                except Exception:  # noqa: BLE001
                    break
                loaded += 1
            if loaded == 0:
                raise IDAError(
                    "READ_FAILED",
                    f"cannot read {size} bytes at {hex(address)}")
            try:
                raw = ida_bytes.get_bytes(address, loaded)
            except Exception as e:  # noqa: BLE001
                raise IDAError(
                    "READ_FAILED",
                    f"cannot read loaded bytes at {hex(address)}: {e}") from e
            if raw is None or len(raw) == 0:
                raise IDAError(
                    "READ_FAILED",
                    f"cannot read loaded bytes at {hex(address)}")
            return bytes(raw[:loaded])

        def range_loaded(address, size):
            if size < 1:
                size = 1
            try:
                return all(ida_bytes.is_loaded(address + index)
                           for index in range(size))
            except Exception:  # noqa: BLE001
                return False

        tif = exact_tinfo(ea)
        dtype = str(tif) if tif is not None else ""
        object_size = type_size(tif) if tif is not None else None

        segment = None
        seg = ida_segment.getseg(ea)
        if seg is not None:
            perm = seg.perm
            segment = {
                "name": ida_segment.get_segm_name(seg),
                "permissions": "{}{}{}".format(
                    "r" if perm & ida_segment.SEGPERM_READ else "-",
                    "w" if perm & ida_segment.SEGPERM_WRITE else "-",
                    "x" if perm & ida_segment.SEGPERM_EXEC else "-",
                ),
            }

        string_value = None
        try:
            flags = ida_bytes.get_full_flags(ea)
            if ida_bytes.is_strlit(flags):
                strtype = ida_nalt.get_str_type(ea)
                raw_string = ida_bytes.get_strlit_contents(
                    ea, -1, strtype)
                if raw_string is not None:
                    if isinstance(raw_string, bytes):
                        string_value = raw_string.decode(
                            "utf-8", errors="replace")
                    else:
                        string_value = str(raw_string)
        except Exception:  # noqa: BLE001
            string_value = None

        badaddr = idaapi.BADADDR
        if (isinstance(ea, bool) or not isinstance(ea, int) or ea < 0
                or ea == badaddr or ea > badaddr - read_offset):
            raise IDAError(
                "READ_FAILED",
                f"read address is outside the database: {hex(ea)} + "
                f"{read_offset}")
        read_ea = ea + read_offset
        raw = read_prefix(read_ea, read_size)
        returned_size = len(raw)
        complete = returned_size == read_size
        read = {
            "offset": read_offset,
            "read_ea": read_ea,
            "requested_size": read_size,
            "returned_size": returned_size,
            "hex_bytes": raw.hex(),
            "complete": complete,
            "next_offset": None if complete else read_offset + returned_size,
            "object_size": object_size,
        }

        hops = []
        stop_reason = "depth_limit"
        current_ea = ea
        current_tif = tif
        visited = {ea}
        byteorder = "big" if ida_ida.inf_is_be() else "little"
        for depth in range(1, dereference_depth + 1):
            if current_tif is None:
                stop_reason = "no_type"
                break
            try:
                is_pointer = bool(current_tif.is_ptr())
            except Exception:  # noqa: BLE001
                is_pointer = False
            if not is_pointer:
                stop_reason = "not_pointer"
                break

            pointer_size = type_size(current_tif)
            hop = {
                "depth": depth,
                "from_ea": current_ea,
                "pointer_type": str(current_tif),
                "pointer_size": pointer_size,
                "raw_value": None,
                "target_ea": None,
                "target_name": None,
                "target_type": None,
                "loaded": None,
            }
            if pointer_size is None or pointer_size < 1:
                hops.append(hop)
                stop_reason = "unreadable_pointer"
                break
            try:
                pointer_raw = read_prefix(current_ea, pointer_size)
            except IDAError:
                hops.append(hop)
                stop_reason = "unreadable_pointer"
                break
            if len(pointer_raw) != pointer_size:
                hops.append(hop)
                stop_reason = "unreadable_pointer"
                break

            raw_value = int.from_bytes(pointer_raw, byteorder=byteorder)
            pointed_tif = pointed_object(current_tif)
            target_type = (str(pointed_tif)
                           if pointed_tif is not None else None)
            required_target_size = 1
            if pointed_tif is not None:
                try:
                    if pointed_tif.is_ptr():
                        required_target_size = type_size(pointed_tif) or 1
                except Exception:  # noqa: BLE001
                    pass
            loaded = range_loaded(raw_value, required_target_size)
            hop.update({
                "raw_value": raw_value,
                "target_ea": raw_value,
                "target_name": ida_name.get_name(raw_value) or "",
                "target_type": target_type,
                "loaded": loaded,
            })
            hops.append(hop)

            if pointed_tif is None:
                stop_reason = "no_type"
                break
            if raw_value in visited:
                stop_reason = "cycle"
                break
            if not loaded:
                stop_reason = "target_not_loaded"
                break
            visited.add(raw_value)
            current_ea = raw_value
            current_tif = pointed_tif

        return {
            "ea": ea,
            "name": ida_name.get_name(ea) or "",
            "type": dtype,
            "type_size": object_size,
            "string_value": string_value,
            "segment": segment,
            "read": read,
            "dereference": {
                "requested_depth": dereference_depth,
                "hops": hops,
                "stop_reason": stop_reason,
            },
        }

    return run_in_main(do)


# ---------------------------------------------------------------------------
# 交叉引用 / 调用关系
# ---------------------------------------------------------------------------
