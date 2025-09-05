import ida_segment
import ida_bytes
import ida_name
import ida_funcs
import ida_idaapi

def is_function_ptr(ea):
    """Check if EA is a pointer to a function inside .text."""
    ptr = ida_bytes.get_qword(ea)  # 64-bit binary
    if not ida_bytes.is_loaded(ptr):
        return False
    seg = ida_segment.getseg(ptr)
    if not seg:
        return False
    # Check if it's inside .text
    return seg.perm & ida_segment.SEGPERM_EXEC != 0

def dump_vtable(start_ea, max_count=64):
    """Dump a vtable starting at start_ea."""
    vtable_entries = []
    for i in range(max_count):
        ea = start_ea + i * 8  # 8 bytes per pointer (64-bit)
        if not ida_bytes.is_loaded(ea):
            break
        if not is_function_ptr(ea):
            break
        func_ptr = ida_bytes.get_qword(ea)
        func_name = ida_name.get_name(func_ptr)
        if not func_name:
            func_name = f"sub_{func_ptr:X}"
        vtable_entries.append((ea, func_ptr, func_name))
    return vtable_entries

def find_vtables():
    """Find and dump all vtables in .rdata or all segments."""
    vtables = []
    for seg_ea in ida_segment.get_segm_qty() * [0]:
        seg = ida_segment.getnseg(seg_ea)
        if not seg:
            continue
        segname = ida_segment.get_segm_name(seg)
        if segname in (".rdata", ".data"):
            ea = seg.start_ea
            while ea < seg.end_ea:
                if is_function_ptr(ea):
                    entries = dump_vtable(ea)
                    if len(entries) > 2:  # vtable should have at least 3 methods
                        vtables.append((ea, entries))
                        ea += len(entries) * 8
                    else:
                        ea += 8
                else:
                    ea += 8
    return vtables

def main():
    vtables = find_vtables()
    output_file = ida_idaapi.get_input_file_path() + "_vtables.txt"
    with open(output_file, "w") as f:
        for vt_ea, entries in vtables:
            f.write(f"VTable at {vt_ea:08X}:\n")
            for ea, func_ptr, name in entries:
                f.write(f"  {ea:08X} -> {func_ptr:08X} ({name})\n")
            f.write("\n")
    print(f"[+] Dumped {len(vtables)} vtables to {output_file}")

main()
