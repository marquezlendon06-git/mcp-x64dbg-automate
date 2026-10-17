```
 __  __  ____ ____         __   _  _  _  _     _  _  _               
|  \/  |/ ___|  _ \       / /_ | || || || |   | \| |/ |              
| |\/| | |   | |_) |_____| '_ \| || || || |_  | .` |/ _ \            
| |  | | |___|  __/_____|| (_) |__  _|__  _|  |_|\_/_/ \_\           
|_|  |_|\____|_|          \___/   |_|   |_|                           
    _         _                        _                               
   /_\ _  _| |_ ___  _ __  __ _ | |_ ___                              
  / _ \ || |  _/ _ \| '  \/ _` |  _/ -_)                             
 /_/ \_\_,_|\__\___/|_|_|_\__,_|\__\___|                              
```

> **AI-Powered Malware Analysis** — Claude controls x64dbg over MCP from an isolated sandbox

---

## What Is This?

`mcp-x64dbg-automate` is an MCP (Model Context Protocol) server that exposes x64dbg debugger capabilities as tools Claude can call. It runs inside an isolated malware analysis VM, allowing Claude on a separate AI workstation to drive the debugger — reading registers, disassembling code, inspecting memory, setting labels and comments — without the malware ever having a path to escape to the internet or the host.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│  VM1 — Windows11x64_AIDevMac (10.10.10.1)               │
│                                                          │
│   ┌─────────────────────────────────────────────────┐   │
│   │  Claude Desktop  ──►  MCP Client (mcp-remote)   │   │
│   └──────────────────────────┬──────────────────────┘   │
│                               │  TCP 9628 (SSE)          │
│   Internet (NAT adapter)      │                          │
└───────────────────────────────┼─────────────────────────┘
                                │
          ╔═══════════════════╗ │  Internal VMnet only
          ║  FIREWALL RULES   ║ │  (no internet on VM2)
          ║  TCP 9628 only ↕  ║ │
          ╚═══════════════════╝ │
                                │
┌───────────────────────────────┼─────────────────────────┐
│  VM2 — Windows11x64_Reverse-Eng (10.10.10.2)            │
│                               │                          │
│   ┌─────────────────────────────────────────────────┐   │
│   │  mcp_x64dbg_automate_server.py  (port 9628)     │   │
│   │              ▼                                   │   │
│   │         x64dbg / x32dbg                         │   │
│   │              ▼                                   │   │
│   │       [ Malware Sample ]                         │   │
│   └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## Low-Level Architecture

```
Claude Desktop (VM1)
       │
       │  JSON-RPC over SSE (mcp-remote transport)
       │  http://10.10.10.2:9628/sse
       ▼
FastMCP Server — mcp_x64dbg_automate_server.py (VM2)
       │
       │  x64dbg_automate Python client
       │  (connects to x64dbg named pipe / COM interface)
       ▼
x64dbg / x32dbg (VM2)
       │
       │  Windows Debug API (CreateProcess / Attach)
       ▼
Malware process under analysis
```

### MCP Tools Exposed

| Tool | Category | Description |
|---|---|---|
| `attach_session(pid)` | Session | Attach to a running debugger session by PID |
| `get_reg(reg)` | Registers | Read a register or subregister value |
| `eval_sync(expr)` | Registers | Evaluate an expression (e.g. `rsp+0x20`) |
| `get_symbol_at(addr)` | Symbols | Resolve symbol name at an address |
| `read_memory(addr, size)` | Memory | Read bytes from debuggee memory (endian-flipped) |
| `read_aob(addr, size)` | Memory | Read memory as Array-of-Bytes signature |
| `read_str_from_memory(addr, size, enc)` | Memory | Read and decode memory as text |
| `virt_query(addr)` | Memory | Query virtual memory page info |
| `memmap()` | Memory | Get full memory map of the debugged process |
| `disassemble_at(addr)` | Disasm | Disassemble single instruction |
| `disassemble_multi_line(addr, n)` | Disasm | Disassemble N consecutive instructions |
| `set_comment_at(addr, text)` | Annotations | Set a comment at an address |
| `set_label_at(addr, text)` | Annotations | Set a label at an address |
| `cmd_sync(cmd)` | Commands | Execute any x64dbg command synchronously |

---

## Installation

### Prerequisites

- Python 3.10+ installed on **VM2** (the malware analysis sandbox)
- x64dbg installed on VM2 at `C:\Program Files\x64dbg\`
- Node.js installed on **VM1** (for `mcp-remote` MCP client transport)

### VM2 — Install Python dependencies

```bash
pip install fastmcp x64dbg-automate
```

### VM1 — Configure Claude Desktop

Add the following to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "mcp_automate": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://10.10.10.2:9628/sse"
      ]
    }
  }
}
```

---

## Configuration

Open `mcp_x64dbg_automate_server.py` and set the debugger client to match the target architecture:

```python
# For 32-bit targets
debugger = x32client

# For 64-bit targets
debugger = x64client
```

Update the x64dbg paths if installed in a non-default location:

```python
x32client = X64DbgClient(r"C:\Program Files\x64dbg\release\x32\x32dbg.exe")
x64client = X64DbgClient(r"C:\Program Files\x64dbg\release\x64\x64dbg.exe")
```

---

## Running the Server

On **VM2**, run as Administrator:

```bash
python mcp_x64dbg_automate_server.py
```

The server listens on `0.0.0.0:9628` (all interfaces) via SSE transport. Restart it after any Windows Firewall policy changes.

---

## Network & Security Setup

See [`malware-lab-network-setup.md`](malware-lab-network-setup.md) for the full:
- VMware network isolation configuration
- Windows Firewall rules for both VMs
- Troubleshooting guide (including the WFP GUID diagnostic technique)
- Snapshot workflow for safe malware analysis

**Security model summary:**
- VM2 has **no internet adapter** — malware cannot call home
- Windows Firewall on VM2: `BlockInbound, BlockOutbound` with only TCP 9628 to VM1 allowed
- VM1 default `BlockInbound` policy prevents VM2 from initiating any connection back
- VMware Guest Isolation: clipboard and drag-drop disabled on VM2

---

## License

For educational and authorized security research use only.
