# Pwner

A blazing-fast C++ CTF pwn challenge automation tool. Sets up your entire exploit workspace in seconds — checksec, pwntools script, libc patching, and decompiler launch in one command.

```
    ____
   / __ \__      ______  ___  _____
  / /_/ / | /| / / __ \/ _ \/ ___/
 / ____/| |/ |/ / / / /  __/ /
/_/     |__/|__/_/ /_/\___/_/      v1.0.0
```

## Features

- **One-command setup**: Create challenge workspace, checksec, generate pwntools script, patch libc, launch decompiler — all at once
- **Native ELF parsing**: Built-in checksec with zero external dependencies — reads ELF headers directly via mmap
- **Smart libc patching**: Renames libc to `libc.so.6`, finds/downloads matching `ld-linux`, runs patchelf with `--set-rpath` and `--set-interpreter`
- **Auto libc download**: Parses Dockerfiles to detect distro version, queries [libc.rip](https://libc.rip) to download matching libc + loader
- **Template library**: Specialized exploit templates for heap, format string, ROP, V8/browser, kernel, and GPU challenges
- **Terminal detection**: Auto-detects tmux/kitty/alacritty/wezterm and configures `context.terminal` correctly
- **Decompiler integration**: Launches IDA Pro, Ghidra, or Binary Ninja in the background with the correct binary

## Quick Start

### 1. Install Dependencies

```bash
# Required
sudo apt install build-essential cmake patchelf python3 curl

# pwntools
pip3 install pwntools

# Optional
sudo apt install binutils file
```

### 2. Build & Install

```bash
git clone <repo> && cd Pwner
chmod +x setup.sh install.sh

# Interactive configuration (decompiler path, challenge directory, terminal, etc.)
./setup.sh

# Build and install to /usr/local/bin
./install.sh

# Or install to a custom prefix
./install.sh ~/.local
```

### 3. Configure

Run `./setup.sh` to create the configuration file at `~/.config/pwner/pwner.conf`. It will ask you for:

| Setting | Description | Example |
|---|---|---|
| `challenges_dir` | Base directory where challenge folders are created | `~/ctf` |
| `decompiler` | Which decompiler to use | `ida`, `ghidra`, `binja` |
| `decompiler_path` | Full path to the decompiler binary | `/opt/ida/ida64` |
| `terminal` | Terminal multiplexer for GDB | `tmux`, `kitty`, `alacritty` |
| `gdb_plugin` | GDB enhancement plugin | `pwndbg`, `gef`, `vanilla` |
| `editor` | Preferred text editor | `nvim`, `vim`, `code` |

You can also edit the config file directly:

```ini
# ~/.config/pwner/pwner.conf
challenges_dir=/home/user/ctf
decompiler=ida
decompiler_path=/opt/ida/ida64
terminal=tmux
gdb_plugin=pwndbg
editor=nvim
```

## Usage

```
Pwner [options] <binary> [libc] [loader]
```

### Full Setup (Default)

```bash
# Basic setup: checksec + script + decompiler
Pwner ./challenge

# With provided libc (patches binary automatically)
Pwner ./challenge ./libc-2.35.so

# With libc AND loader
Pwner ./challenge ./libc-2.35.so ./ld-linux-x86-64.so.2

# Set remote in generated script
Pwner -r 'pwn.example.com:1337' ./challenge ./libc.so
```

**What happens:**
1. Creates `~/ctf/Challenge/` directory (first letter capitalized)
2. Copies binary, runs `chmod +x`
3. Runs built-in checksec (arch, RELRO, canary, NX, PIE, FORTIFY)
4. If libc provided: renames to `libc.so.6`, finds/downloads loader, runs `patchelf --set-rpath . --set-interpreter ./ld-linux-x86-64.so.2`
5. If no libc: attempts auto-download from Dockerfile detection + libc.rip API
6. Generates `solve.py` with full pwntools boilerplate (ELF, context, conn(), GDB, remote)
7. Launches decompiler in background

### Mode Flags

| Flag | Short | Description |
|---|---|---|
| `--decomp` | `-d` | Open decompiler only |
| `--script` | `-s` | Generate pwntools script only |
| `--checksec` | `-c` | Run checksec only |
| `--patch` | `-p` | Patch binary with libc only |
| `--deps` | | Check all dependencies |

```bash
Pwner -d ./challenge            # Just open IDA/Ghidra
Pwner -s ./challenge            # Just generate solve.py
Pwner -c ./challenge            # Just checksec
Pwner -p ./challenge ./libc.so  # Just patch, don't setup workspace
Pwner --deps                    # Check patchelf, pwntools, etc.
```

### Challenge Templates

| Flag | Type | What it adds |
|---|---|---|
| `--heap` | Heap | `alloc()`, `free()`, `show()`, `edit()` helpers, libc offset notes |
| `--fmt` | Format String | `exec_fmt()`, `FmtStr()` auto-offset, GOT overwrite patterns |
| `--rop` | ROP | `ROP(elf)`, gadget search patterns, ret2libc, SROP frame |
| `--v8` | V8/Browser | d8 setup, `exploit.js` with addrof/fakeobj/arb-rw primitives, WASM RWX |
| `--kernel` | Kernel | `solve.py` with QEMU automation, `exploit.c`, Makefile (musl-gcc), initramfs helpers |
| `--gpu` | GPU | CUDA/OpenCL exploitation notes, DMA attack patterns |

```bash
Pwner --heap ./challenge ./libc.so     # Full heap challenge setup
Pwner -s --rop ./challenge             # Generate ROP script only
Pwner --kernel ./bzImage               # Full kernel challenge setup
Pwner --v8 ./d8                        # V8 challenge setup with exploit.js
Pwner -s --fmt ./challenge             # Format string script only
```

### Modifier Flags

| Flag | Description |
|---|---|
| `--no-decomp` | Skip opening decompiler in full setup |
| `--no-script` | Skip script generation in full setup |
| `--no-patch` | Skip libc patching/download |
| `--download-libc` | Force attempt to download libc from internet |
| `-n, --name NAME` | Override challenge directory name |
| `-o, --output DIR` | Override output directory |
| `-r, --remote H:P` | Set remote host:port in generated script |
| `-t, --terminal T` | Override terminal for GDB |
| `-v, --verbose` | Verbose output |

```bash
Pwner --no-decomp ./challenge                # Setup without opening IDA
Pwner -n MyChall -o /tmp ./challenge         # Custom name and output dir
Pwner -r 'host.io:31337' --heap ./chal libc  # Heap setup with remote preset
Pwner -t kitty ./challenge                   # Use kitty for GDB terminal
```

## Generated Script

The default `solve.py` looks like:

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF('./challenge')
libc = ELF('./libc.so.6')

context.binary = elf
context.terminal = ['tmux', 'splitw', '-h']

gs = '''
b main
c
'''

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('', 0)
    else:
        return process(elf.path)

io = conn()

# ===========================
#        EXPLOIT HERE
# ===========================

io.interactive()
```

Run with:
```bash
python3 solve.py          # Local process
python3 solve.py GDB      # Attach GDB
python3 solve.py REMOTE   # Connect to remote
```

## Libc Patching Details

When you provide a libc, Pwner:

1. **Renames** the libc to `libc.so.6` (required for patchelf `--set-rpath` to work)
2. **Finds the loader** (`ld-linux-x86-64.so.2` etc.):
   - Checks same directory as libc for `ld-linux*` files
   - Extracts libc build-id and queries libc.rip for matching loader
   - Falls back to system loader with a warning
3. **Patches** the binary:
   ```
   patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . ./challenge
   ```
4. Makes all files executable

When no libc is provided, Pwner attempts auto-download:
1. Looks for `Dockerfile` near the binary
2. Parses `FROM ubuntu:XX.XX` to identify distro version
3. Queries libc.rip API for matching libc
4. Downloads and patches automatically

## Kernel Challenge Setup

`Pwner --kernel ./bzImage` generates:

| File | Purpose |
|---|---|
| `solve.py` | QEMU automation (extract/build/pack/run commands) |
| `exploit.c` | C exploit template with device interaction, privilege escalation |
| `Makefile` | Static compilation with `musl-gcc` (falls back to `gcc -static`) |
| `run.sh` | QEMU launch script with SMEP/SMAP/KASLR flags |
| `helpers.sh` | Initramfs extract/rebuild helpers |

Workflow:
```bash
python3 solve.py extract   # Extract initramfs to fs/
# Edit exploit.c
python3 solve.py build     # Compile with musl-gcc
python3 solve.py pack      # Pack exploit into initramfs
python3 solve.py run       # Launch QEMU
python3 solve.py all       # All of the above
```

## V8 Challenge Setup

`Pwner --v8 ./d8` generates:

| File | Purpose |
|---|---|
| `solve.py` | pwntools automation for d8 with `--allow-natives-syntax` |
| `exploit.js` | JavaScript exploit template with addrof/fakeobj/arb-rw primitives and WASM shellcode setup |

## Architecture Support

Pwner's ELF parser handles:
- **x86_64** (amd64)
- **i386** (x86)
- **ARM** (arm)
- **AArch64** (aarch64)
- **MIPS** (mips)
- **PowerPC** (powerpc/powerpc64)
- **RISC-V** (riscv)

Both 32-bit and 64-bit, little and big endian.

## Directory Layout

```
~/ctf/Challenge/
├── challenge          # Binary (chmod +x, optionally patched)
├── libc.so.6          # Renamed libc (if provided/downloaded)
├── ld-linux-x86-64.so.2  # Loader (if found/downloaded)
└── solve.py           # Pwntools exploit script
```

For kernel challenges:
```
~/ctf/Challenge/
├── bzImage
├── initramfs.cpio.gz
├── solve.py
├── exploit.c
├── Makefile
├── run.sh
└── helpers.sh
```

## Configuration File

Location: `~/.config/pwner/pwner.conf`

```ini
challenges_dir=/home/user/ctf
decompiler=ida
decompiler_path=/opt/ida/ida64
terminal=tmux
gdb_plugin=pwndbg
editor=nvim
```

Regenerate with: `./setup.sh`

## Building from Source

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j$(nproc)
sudo cmake --install .
```

Requirements: CMake 3.14+, C++17 compiler (GCC 8+ or Clang 7+).

## License

MIT
