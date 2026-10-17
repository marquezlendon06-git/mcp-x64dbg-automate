from fastmcp import FastMCP
from x64dbg_automate import X64DbgClient
from x64dbg_automate.models import Symbol
from x64dbg_automate.models import Instruction, DisasmArgType, DisasmInstrType, InstructionArg, SegmentReg

mcp = FastMCP("MCP_Automate_Server")

x32client = X64DbgClient(r"C:\Program Files\x64dbg\release\x32\x32dbg.exe")
x64client = X64DbgClient(r"C:\Program Files\x64dbg\release\x64\x64dbg.exe")

# CHANGE THIS TO THE CLIENT YOU WANT, either x32client, or, x64client:
debugger = x32client

# --------------------------------------------------------------------
# SESSION CONTROL
# --------------------------------------------------------------------
@mcp.tool()
def attach_session(session_pid: int) -> str:
    """
    Attach to an existing debugger session. Call exactly once per debugging run.
    If already attached, reuse the existing session.
    Args: session_pid - Process IT to attach to
    Returns: str - success
    """
    debugger.attach_session(session_pid)
    return "Debugger attached"
    

# --------------------------------------------------------------------
# REGISTERS AND EXPRESSIONS
# --------------------------------------------------------------------
@mcp.tool()
def get_reg(reg: str) -> str:
    """
    Get a single register or subregister. 
    Args: reg - Register to get
    Returns: str - the hex value stored in the register (e.g., '0x64ff84')
    """
    value = debugger.get_reg(reg)
    return hex(value)


@mcp.tool()
def get_symbol_at(addr) -> dict:
    """
    Retrieves the symbol at the specified address
    Args: integer or string (e.g., 0x12345678 or "0x12345678")
    Returns: dict - with symbol details.
    """
    # Normalize address
    try:
        a = int(addr, 0) if isinstance(addr, str) else int(addr)
    except (TypeError, ValueError):
        return {"error": f"Invalid address: {addr!r}"}

    s: Symbol = debugger.get_symbol_at(a)
    if not s:
        return {"error": f"No symbol found at {hex(a)}"}

    return {
        "addr": s.addr,
        "decoratedSymbol": s.decoratedSymbol,
        "undecoratedSymbol": s.undecoratedSymbol,
        "type": s.type,
        "ordinal": s.ordinal
    }

@mcp.tool()
def eval_sync(eval_str: str) -> dict:
    """
    Evaluates expressions to get memory addresses (e.g., rsp + 0x20, esp + 0x4)
    Returns addresses, not values. Use read_memory() to get data at the address
    Args: eval_str - Expression to evaluate
    Returns: dict with "dec", "hex", "success" fields
    """
    result, success = debugger.eval_sync(eval_str)
    return {
        "dec": result,
        "hex": hex(result) if success else None,
        "success": success
    }

# --------------------------------------------------------------------
# MEMORY CONTROL
# --------------------------------------------------------------------
@mcp.tool()
def read_memory(addr, size) -> dict:
    """
    Reads data from debuggee memory. Use eval_sync() first for address calculations.
    Args:
        addr: Address to read from (int or str)
        size: Number of bytes to read (int or str)
    Returns: dict with "addr", "size", "data_hex" fields or {"error": "..."}
    """
    # If AI agent provides values with "0x" prefix
    # int(addr, 0) will auto-detect base from prefix (e.g. "0x" for hex)
    a = int(addr, 0) if isinstance(addr, str) else addr
    n = int(size, 0) if isinstance(size, str) else size

    data = debugger.read_memory(a, n)

    # Flip endianness so hex string matches the integer value in memory
    flipped = bytes(data[::-1]).hex()

    return {"addr": hex(a), "size": n, "data_hex": "0x"+flipped}

@mcp.tool()
def read_aob(addr, size) -> dict:
    """
    Read memory bytes as AoB signature without endianness flipping
    Args: addr - Address to read (int or str), size - Number of bytes (int or str)
    Returns: dict with "addr", "size", "aob", "hex_bytes" fields
    """
    # Normalize inputs (mirror read_memory style)
    a = int(addr, 0) if isinstance(addr, str) else addr
    n = int(size, 0) if isinstance(size, str) else size

    data = debugger.read_memory(a, n)  # returns bytes

    # Preserve order exactly as read from memory
    hex_no_prefix = data.hex().upper()
    # Insert spaces every 2 hex chars to build AoB string
    aob = " ".join(hex_no_prefix[i:i+2] for i in range(0, len(hex_no_prefix), 2))

    return {
        "addr": hex(a),
        "size": n,
        "aob": aob,
        "hex_bytes": "0x" + hex_no_prefix
    }


@mcp.tool()
def read_str_from_memory(addr, size, encoding: str = "ascii") -> dict:
    """
    Reads memory bytes and decodes them as text
    Args:
        addr: Address to read from (int or str)
        size: Number of bytes to read (int or str)  
        encoding: Text encoding (default: "ascii")
    Returns: dict with "addr", "hex_bytes", "string" fields or {"error": "..."}
    """
    # --- Normalize the memory address ---
    # If addr is a string like "0x64FF7C", convert to int using base auto-detection.
    # If addr is already an int, leave it as-is.
    a = int(addr, 0) if isinstance(addr, str) else addr

    # --- Normalize the size to read ---
    # Same logic: convert string values ("4", "0x4") into int.
    n = int(size, 0) if isinstance(size, str) else size

    try:
        # --- Attempt to read raw bytes from the debuggee's memory ---
        # This calls the debugger backend to extract 'n' bytes starting at address 'a'.
        hex_bytes = debugger.read_memory(a, n)
    except Exception as e:
        # If memory access fails (invalid address, access violation, etc.),
        # return a dictionary with the error message.
        return {"error": str(e)}

    try:
        # --- Try decoding the raw bytes into a human-readable string ---
        # Use the provided encoding (default: ASCII), could be unicode (utf-16) etc...
        # errors="replace" means undecodable bytes will be replaced with � instead of raising an exception.
        text = hex_bytes.decode(encoding, errors="replace")
    except Exception:
        # If decoding fails entirely (e.g., invalid encoding), just set text to None.
        text = None

    # --- Return results as a dictionary ---
    return {
        "addr": hex(a),                       # Address formatted as hex string
        "hex_bytes": "0x" + hex_bytes.hex(),  # Raw bytes in hex (big-endian string format, ie. bytes as they appear in memory L to R)
        "string": text,                       # Decoded text (if possible), otherwise None
    }

@mcp.tool()
def virt_query(addr) -> dict:
    """
    Query virtual memory information for a page containing the given address.
    Args: addr - Address to query (int or str)
    Returns: dict with memory page info fields or {"error": "..."}
    """
    # --- Normalize the memory address, mirroring read_str_from_memory ---
    try:
        a = int(addr, 0) if isinstance(addr, str) else int(addr)
    except (TypeError, ValueError):
        return {"error": f"Invalid address: {addr!r}"}

    # --- Perform the query and convert the MemPage model into a dict ---
    try:
        mp = debugger.virt_query(a)
    except Exception as e:
        return {"error": str(e)}

    if not mp:
        return {"error": f"No memory information for {hex(a)}"}

    return {
        "base_address":       hex(mp.base_address),
        "allocation_base":    hex(mp.allocation_base),
        "allocation_protect": mp.allocation_protect,
        "partition_id":       mp.partition_id,
        "region_size":        mp.region_size,
        "state":              mp.state,
        "protect":            mp.protect,
        "type":               mp.type,
        "info":               mp.info,
    }

@mcp.tool()
def memmap() -> dict:
    """
    Retrieves complete memory map of the debugged process
    Args: None
    Returns: dict with "memory_pages" array and "total_pages" count or {"error": "..."}
    """
    try:
        # Call the debugger's memmap function to get list of MemPage objects
        pages = debugger.memmap()
    except Exception as e:
        return {"error": str(e)}

    if not pages:
        return {"error": "No memory pages found or memmap failed"}

    # Convert list of MemPage objects to list of dictionaries
    memory_pages = []
    for page in pages:
        memory_pages.append({
            "base_address":       hex(page.base_address),
            "allocation_base":    hex(page.allocation_base),
            "allocation_protect": page.allocation_protect,
            "partition_id":       page.partition_id,
            "region_size":        page.region_size,
            "state":              page.state,
            "protect":            page.protect,
            "type":               page.type,
            "info":               page.info,
        })

    return {
        "memory_pages": memory_pages,
        "total_pages": len(memory_pages)
    }

# --------------------------------------------------------------------
# ASSEMBLING and DISASSEMBLING
# --------------------------------------------------------------------
@mcp.tool()
def disassemble_at(addr) -> dict:
    """
    Disassemble single instruction at address
    Args: addr - Address to disassemble (int or str)
    Returns: dict with instruction details or {"error": "..."}
    """
    # --- Normalize address, following pattern from other memory functions ---
    try:
        a = int(addr, 0) if isinstance(addr, str) else int(addr)
    except (TypeError, ValueError):
        return {"error": f"Invalid address: {addr!r}"}

    # --- Perform the disassembly ---
    try:
        instruction = debugger.disassemble_at(a)
    except Exception as e:
        return {"error": str(e)}

    if not instruction:
        return {"error": f"Failed to disassemble instruction at {hex(a)}"}

    # --- Convert InstructionArg objects to dictionaries ---
    args = []
    for arg in instruction.arg:
        args.append({
            "mnemonic": arg.mnemonic,
            "type": int(arg.type),
            "segment": int(arg.segment),
            "constant": arg.constant,
            "value": arg.value,
            "memvalue": arg.memvalue
        })

    # --- Return the instruction details as a dictionary ---
    return {
        "addr": hex(a),
        "instruction": instruction.instruction,
        "argcount": instruction.argcount,
        "instr_size": instruction.instr_size,
        "type": int(instruction.type),
        "args": args
    }

@mcp.tool()
def disassemble_multi_line(start_addr, num_lines) -> dict:
    """
    Disassemble multiple consecutive instructions
    Args:
        start_addr: Address to begin (int or str)
        num_lines: Number of instructions to decode (int or str)
    Returns: dict mapping "addr" -> "instruction"
    """
    # Normalize inputs (mirror style used in disassemble_at)
    try:
        a = int(start_addr, 0) if isinstance(start_addr, str) else int(start_addr)
    except (TypeError, ValueError):
        return {"error": f"Invalid start address: {start_addr!r}"}

    try:
        n = int(num_lines, 0) if isinstance(num_lines, str) else int(num_lines)
    except (TypeError, ValueError):
        return {"error": f"Invalid num_lines: {num_lines!r}"}

    if n <= 0:
        return {"error": "num_lines must be > 0"}

    result = {}
    cur = a

    for _ in range(n):
        try:
            ins = debugger.disassemble_at(cur)
        except Exception as e:
            # If we already have some lines decoded, return partial; else report error
            return result if result else {"error": str(e)}

        if not ins:
            # Same: return partial if we decoded anything, else error
            return result if result else {"error": f"Failed to disassemble at {hex(cur)}"}

        result[hex(cur)] = ins.instruction

        # Predict next address using instr_size; guard against invalid/zero sizes
        step = ins.instr_size if isinstance(ins.instr_size, int) else 0
        if step <= 0:
            # Avoid stalling; advance minimally
            step = 1
        cur += step

    return result



# --------------------------------------------------------------------
# ANNOTATIONS (COMMENTS and LABELS)
# --------------------------------------------------------------------
@mcp.tool()
def set_comment_at(address, text) -> bool:
    """
    Set a comment at a specific address in the current x64dbg session
    Args:
    address: Absolute address (int or str)
    text: Comment text (no double quotes allowed)
    Returns: bool - True on success
    """
    # --- Normalize/validate inputs ---
    try:
        a = int(address, 0) if isinstance(address, str) else int(address)
    except (TypeError, ValueError):
        return False

    if not isinstance(text, str):
        try:
            text = str(text)
        except Exception:
            return False

    # x64dbg automate (annotations API) forbids double quotes in the comment text
    if '"' in text:
        return False

    try:
        return bool(debugger.set_comment_at(a, text))
    except Exception:
        return False


@mcp.tool()
def set_label_at(address, text) -> bool:
    """
    Set a label at a specific address
    Args: address - Absolute address (int or str)
    text: Label text (no double quotes allowed)
    Returns: bool - True on success
    """
    # --- Normalize/validate inputs (match style of set_comment_at) ---
    try:
        a = int(address, 0) if isinstance(address, str) else int(address)
    except (TypeError, ValueError):
        return False

    if not isinstance(text, str):
        try:
            text = str(text)
        except Exception:
            return False

    # The upstream API forbids double quotes in the label text
    if '"' in text:
        return False

    try:
        return bool(debugger.set_label_at(a, text))
    except Exception:
        return False

# --------------------------------------------------------------------
# COMMANDS AND EXTENSIBILITY
# --------------------------------------------------------------------

@mcp.tool()
def cmd_sync(cmd_str) -> bool:
    """
    Execute an x64dbg command synchronously
    Args: cmd_str - x64dbg command string
    Returns: bool - True on success, False on failure
    """
    # Normalize/validate input similar to other tools
    try:
        if not isinstance(cmd_str, str):
            cmd_str = str(cmd_str)
    except Exception:
        return False

    try:
        # Delegates directly to the underlying client; works for both x32/x64
        return bool(debugger.cmd_sync(cmd_str))
    except Exception:
        return False


if __name__ == "__main__":
    # run locally
    # mcp.run()
    # listen on all interfaces (LAN) on port 9628
    mcp.run(transport="sse", host="0.0.0.0", port=9628)