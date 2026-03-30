#include "scripts.hpp"
#include "utils.hpp"

namespace pwner {

// ═══════════════════════════════════════════════════════════════
//  DEFAULT TEMPLATE
// ═══════════════════════════════════════════════════════════════
static std::string tmpl_default(const ScriptParams& p) {
    std::string s = R"(#!/usr/bin/env python3
from pwn import *

elf = ELF('./%BINARY%')
)";
    if (p.has_libc)
        s += "libc = ELF('./" + p.libc_name + "')\n";

    s += R"(
context.binary = elf
context.terminal = %TERMINAL%

gs = '''
b main
c
'''

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('%RHOST%', %RPORT%)
    else:
        return process(elf.path)

p = conn()

# ===========================
#        EXPLOIT HERE
# ===========================


p.interactive()
)";
    return s;
}

// ═══════════════════════════════════════════════════════════════
//  HEAP TEMPLATE
// ═══════════════════════════════════════════════════════════════
static std::string tmpl_heap(const ScriptParams& p) {
    std::string s = R"(#!/usr/bin/env python3
from pwn import *

elf = ELF('./%BINARY%')
)";
    if (p.has_libc)
        s += "libc = ELF('./" + p.libc_name + "')\n";
    else
        s += "libc = elf.libc\n";

    s += R"(
context.binary = elf
context.terminal = %TERMINAL%

gs = '''
b main
c
'''

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('%RHOST%', %RPORT%)
    else:
        return process(elf.path)

# ── Heap interaction helpers ──────────────────────────────────
# Adjust menu indices & prompts for your challenge

def alloc(idx, size, data=b''):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(size).encode())
    if data:
        p.sendafter(b': ', data)

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())

def show(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())
    return p.recvline()

def edit(idx, data):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendafter(b': ', data)

p = conn()

# ===========================
#        EXPLOIT HERE
# ===========================
#
# Useful addresses (adjust for your libc version):
#   libc.sym['__free_hook']
#   libc.sym['__malloc_hook']
#   libc.sym['system']
#   libc.sym['__libc_start_main']
#   next(libc.search(b'/bin/sh'))
#
# Leak example:
#   libc.address = leak - libc.sym['<func>']
#
# Tcache (glibc >= 2.26):
#   Tcache poison: overwrite fd of freed chunk
#   Tcache count: max 7 per bin
#
# Fastbin (glibc < 2.26 or size < 0x80):
#   Double free -> fastbin dup
#   Forge fake chunk with correct size field


p.interactive()
)";
    return s;
}

// ═══════════════════════════════════════════════════════════════
//  FORMAT STRING TEMPLATE
// ═══════════════════════════════════════════════════════════════
static std::string tmpl_fmt(const ScriptParams& p) {
    std::string s = R"(#!/usr/bin/env python3
from pwn import *

elf = ELF('./%BINARY%')
)";
    if (p.has_libc)
        s += "libc = ELF('./" + p.libc_name + "')\n";

    s += R"(
context.binary = elf
context.terminal = %TERMINAL%

gs = '''
b main
c
'''

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('%RHOST%', %RPORT%)
    else:
        return process(elf.path)

# ── Format string helpers ─────────────────────────────────────

def exec_fmt(payload):
    """Send a format string payload and return the output.
       Used with FmtStr() for automatic offset detection."""
    p = process(elf.path)
    p.sendline(payload)
    out = p.recvall(timeout=1)
    p.close()
    return out

# Auto-detect format string offset:
# autofmt = FmtStr(exec_fmt)
# log.info(f"Format string offset: {autofmt.offset}")
# offset = autofmt.offset

p = conn()

# ===========================
#        EXPLOIT HERE
# ===========================
#
# Manual leak:
#   p.sendline(b'%p.' * 20)
#
# Arbitrary write (after finding offset):
#   payload = fmtstr_payload(offset, {target_addr: value})
#   p.sendline(payload)
#
# GOT overwrite:
#   payload = fmtstr_payload(offset, {elf.got['printf']: elf.sym['win']})


p.interactive()
)";
    return s;
}

// ═══════════════════════════════════════════════════════════════
//  ROP TEMPLATE
// ═══════════════════════════════════════════════════════════════
static std::string tmpl_rop(const ScriptParams& p) {
    std::string s = R"(#!/usr/bin/env python3
from pwn import *

elf = ELF('./%BINARY%')
)";
    if (p.has_libc)
        s += "libc = ELF('./" + p.libc_name + "')\n";

    s += R"(
context.binary = elf
context.terminal = %TERMINAL%

rop = ROP(elf)

gs = '''
b main
c
'''

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('%RHOST%', %RPORT%)
    else:
        return process(elf.path)

p = conn()

# ===========================
#        EXPLOIT HERE
# ===========================
#
# Gadget search:
#   rop.find_gadget(['pop rdi', 'ret'])
#   rop.find_gadget(['pop rsi', 'pop r15', 'ret'])
#   rop.find_gadget(['ret'])  # stack alignment
#
# ret2libc:
#   rop_libc = ROP(libc)
#   rop_libc.call('system', [next(libc.search(b'/bin/sh'))])
#   chain = rop_libc.chain()
#
# Ret2PLT:
#   rop.call(elf.plt['puts'], [elf.got['puts']])
#   rop.call(elf.sym['main'])
#
# SROP:
#   frame = SigreturnFrame()
#   frame.rax = 0x3b        # execve
#   frame.rdi = binsh_addr
#   frame.rip = syscall_ret
#
# Build payload:
#   padding = b'A' * offset
#   payload = padding + rop.chain()


p.interactive()
)";
    return s;
}

// ═══════════════════════════════════════════════════════════════
//  V8 / BROWSER TEMPLATE
// ═══════════════════════════════════════════════════════════════
static std::string tmpl_v8(const ScriptParams& p) {
    (void)p;
    std::string s = R"(#!/usr/bin/env python3
from pwn import *
import os

context.arch = 'amd64'
context.terminal = %TERMINAL%

D8 = './d8'
ARGS = ['--allow-natives-syntax', '--shell']

gs = '''
c
'''

def conn():
    if args.GDB:
        return gdb.debug([D8] + ARGS + ['./exploit.js'], gdbscript=gs)
    elif args.REMOTE:
        return remote('%RHOST%', %RPORT%)
    else:
        return process([D8] + ARGS + ['./exploit.js'])

p = conn()

# ===========================
#        EXPLOIT HERE
# ===========================
#
# V8 exploitation notes:
#   - Check patch diff for vulnerability
#   - Use %DebugPrint(obj) for object inspection
#   - Use %SystemBreak() as breakpoint
#   - Compressed pointers: heap starts at aligned base
#   - Float array for addrof/fakeobj primitives
#   - ArrayBuffer backing store for arb r/w
#   - WASM for RWX page (shellcode execution)


p.interactive()
)";
    return s;
}

// ═══════════════════════════════════════════════════════════════
//  KERNEL TEMPLATE
// ═══════════════════════════════════════════════════════════════
static std::string tmpl_kernel(const ScriptParams& p) {
    (void)p;
    std::string s = R"(#!/usr/bin/env python3
"""
Kernel exploitation automation script.
Handles initramfs extraction, exploit compilation, packing, and QEMU launch.

Usage:
    python3 solve.py extract   - Extract initramfs
    python3 solve.py build     - Compile exploit
    python3 solve.py pack      - Rebuild initramfs with exploit
    python3 solve.py run       - Launch QEMU
    python3 solve.py all       - Extract + build + pack + run
    python3 solve.py shell     - Pack + run with debug shell
"""
import os, sys, subprocess, shutil

# ── Config ────────────────────────────────────────────────────
QEMU     = 'qemu-system-x86_64'
KERNEL   = './bzImage'
INITRD   = './initramfs.cpio.gz'
FS_DIR   = './fs'
EXPLOIT  = './exploit.c'
EXPLOIT_BIN = './exploit'

QEMU_ARGS = [
    '-m', '256M',
    '-nographic',
    '-kernel', KERNEL,
    '-initrd', INITRD,
    '-append', 'console=ttyS0 loglevel=3 oops=panic panic=1 kaslr',
    '-cpu', 'kvm64,+smep,+smap',
    '-monitor', '/dev/null',
    '-no-reboot',
    # '-s',  # Uncomment for GDB server on :1234
]


def extract():
    """Extract initramfs to fs/ directory."""
    os.makedirs(FS_DIR, exist_ok=True)
    os.system(f'cd {FS_DIR} && zcat ../{INITRD} | cpio -idm 2>/dev/null')
    print('[+] Extracted initramfs to', FS_DIR)


def build():
    """Compile exploit statically with musl-gcc (or gcc -static)."""
    cc = 'musl-gcc' if shutil.which('musl-gcc') else 'gcc'
    flags = '-static -O2 -o'
    ret = os.system(f'{cc} {flags} {EXPLOIT_BIN} {EXPLOIT}')
    if ret == 0:
        print('[+] Exploit compiled:', EXPLOIT_BIN)
    else:
        print('[-] Compilation failed')
        sys.exit(1)


def pack():
    """Copy exploit into fs/ and rebuild initramfs."""
    if os.path.exists(EXPLOIT_BIN):
        shutil.copy2(EXPLOIT_BIN, os.path.join(FS_DIR, 'exploit'))
        os.chmod(os.path.join(FS_DIR, 'exploit'), 0o755)
    os.system(f'cd {FS_DIR} && find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > ../{INITRD}')
    print('[+] Rebuilt initramfs')


def run():
    """Launch QEMU."""
    cmd = [QEMU] + QEMU_ARGS
    print('[*] Launching:', ' '.join(cmd))
    os.execvp(QEMU, cmd)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    actions = {
        'extract': extract,
        'build':   build,
        'pack':    pack,
        'run':     run,
    }

    cmd = sys.argv[1]
    if cmd == 'all':
        extract(); build(); pack(); run()
    elif cmd == 'shell':
        pack(); run()
    elif cmd in actions:
        actions[cmd]()
    else:
        print(f'Unknown command: {cmd}')
        print(__doc__)
        sys.exit(1)


if __name__ == '__main__':
    main()
)";
    return s;
}

// ═══════════════════════════════════════════════════════════════
//  GPU TEMPLATE
// ═══════════════════════════════════════════════════════════════
static std::string tmpl_gpu(const ScriptParams& p) {
    std::string s = R"(#!/usr/bin/env python3
from pwn import *

elf = ELF('./%BINARY%')
)";
    if (p.has_libc)
        s += "libc = ELF('./" + p.libc_name + "')\n";

    s += R"(
context.binary = elf
context.terminal = %TERMINAL%

gs = '''
b main
c
'''

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('%RHOST%', %RPORT%)
    else:
        return process(elf.path)

p = conn()

# ===========================
#       GPU EXPLOIT HERE
# ===========================
#
# GPU pwn notes:
#   - Check CUDA version: nvcc --version
#   - Check GPU: nvidia-smi
#   - Common bugs: race conditions in kernel launch
#   - Buffer overflows in GPU memory copies
#   - cuMemAlloc / cuMemcpyHtoD / cuMemcpyDtoH
#   - UVM (Unified Virtual Memory) can bridge GPU/CPU access
#   - Check for improper bounds checking in CUDA kernels
#   - OpenCL: clCreateBuffer, clEnqueueNDRangeKernel
#
# For DMA attacks:
#   - PCIe TLP (Transaction Layer Packets)
#   - IOMMU bypass techniques


p.interactive()
)";
    return s;
}

// ═══════════════════════════════════════════════════════════════
//  TEMPLATE SUBSTITUTION AND DISPATCH
// ═══════════════════════════════════════════════════════════════
std::string generate_script(const ScriptParams& p) {
    std::string s;

    switch (p.type) {
        case ScriptType::HEAP:    s = tmpl_heap(p);    break;
        case ScriptType::FMT:     s = tmpl_fmt(p);     break;
        case ScriptType::ROP:     s = tmpl_rop(p);     break;
        case ScriptType::V8:      s = tmpl_v8(p);      break;
        case ScriptType::KERNEL:  s = tmpl_kernel(p);  break;
        case ScriptType::GPU:     s = tmpl_gpu(p);     break;
        default:                  s = tmpl_default(p);  break;
    }

    // Apply substitutions
    s = replace_all(s, "%BINARY%",   p.binary_name);
    s = replace_all(s, "%TERMINAL%", terminal_pwntools(p.terminal));
    s = replace_all(s, "%RHOST%",    p.remote_host);
    s = replace_all(s, "%RPORT%",    p.remote_port > 0 ? std::to_string(p.remote_port) : "0");

    return s;
}

// ═══════════════════════════════════════════════════════════════
//  KERNEL HELPER FILES
// ═══════════════════════════════════════════════════════════════

std::string generate_kernel_exploit_c() {
    return R"(// Kernel exploit template
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>

// ── Device interaction ───────────────────────────────────────
#define DEVICE "/dev/vuln"

int fd;

void setup() {
    fd = open(DEVICE, O_RDWR);
    if (fd < 0) {
        perror("open device");
        exit(1);
    }
    printf("[*] Device opened: fd=%d\n", fd);
}

// ── Privilege escalation ─────────────────────────────────────

typedef int (*commit_creds_t)(unsigned long cred);
typedef unsigned long (*prepare_kernel_cred_t)(unsigned long task);

commit_creds_t      commit_creds;
prepare_kernel_cred_t prepare_kernel_cred;

void get_root() {
    commit_creds(prepare_kernel_cred(0));
}

void get_shell() {
    if (getuid() == 0) {
        printf("[+] Got root!\n");
        system("/bin/sh");
    } else {
        printf("[-] Failed to get root\n");
        exit(1);
    }
}

// ── Kernel ASLR leak ────────────────────────────────────────

unsigned long leak_kaslr() {
    // Read /proc/kallsyms or use side channels
    // Placeholder: return 0 for no KASLR or implement leak
    return 0;
}

// ── Main ─────────────────────────────────────────────────────

int main() {
    printf("[*] Kernel exploit starting...\n");

    setup();

    unsigned long kaslr_base = leak_kaslr();
    printf("[*] KASLR base: 0x%lx\n", kaslr_base);

    // TODO: trigger vulnerability

    // TODO: get code execution -> call get_root()

    get_shell();

    close(fd);
    return 0;
}
)";
}

std::string generate_kernel_makefile() {
    return R"MK(CC      ?= musl-gcc
CFLAGS  = -static -O2 -Wall
TARGET  = exploit
SRC     = exploit.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[+] Built: $(TARGET)"

# Fallback if musl-gcc is not available
fallback:
	gcc -static $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)
)MK";
}

std::string generate_kernel_run_sh() {
    return R"(#!/bin/bash
# QEMU launch script for kernel exploitation
# Adjust flags as needed for the specific challenge

QEMU="qemu-system-x86_64"
KERNEL="./bzImage"
INITRD="./initramfs.cpio.gz"

$QEMU \
    -m 256M \
    -nographic \
    -kernel "$KERNEL" \
    -initrd "$INITRD" \
    -append "console=ttyS0 loglevel=3 oops=panic panic=1 kaslr" \
    -cpu kvm64,+smep,+smap \
    -monitor /dev/null \
    -no-reboot \
    "$@"
    # Add -s for GDB server on :1234
    # Add -S to pause at start (for GDB attach)
)";
}

std::string generate_kernel_helpers_sh() {
    return R"(#!/bin/bash
# Initramfs extraction and rebuild helpers

FS_DIR="./fs"
INITRD="./initramfs.cpio.gz"

extract() {
    mkdir -p "$FS_DIR"
    cd "$FS_DIR" && zcat "../$INITRD" | cpio -idm 2>/dev/null
    echo "[+] Extracted to $FS_DIR"
    cd ..
}

rebuild() {
    if [ -f ./exploit ]; then
        cp ./exploit "$FS_DIR/exploit"
        chmod +x "$FS_DIR/exploit"
    fi
    cd "$FS_DIR" && find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "../$INITRD"
    echo "[+] Rebuilt $INITRD"
    cd ..
}

case "$1" in
    extract)  extract ;;
    rebuild)  rebuild ;;
    *)        echo "Usage: $0 {extract|rebuild}" ;;
esac
)";
}

// ═══════════════════════════════════════════════════════════════
//  V8 HELPER FILES
// ═══════════════════════════════════════════════════════════════

std::string generate_v8_exploit_js() {
    return R"(// V8 exploit template
// Run with: ./d8 --allow-natives-syntax --shell exploit.js

// ── Helper functions ─────────────────────────────────────────

// Convert float to 64-bit unsigned integer representation
var buf = new ArrayBuffer(8);
var f64 = new Float64Array(buf);
var u32 = new Uint32Array(buf);
var u8  = new Uint8Array(buf);

function ftoi(val) {
    f64[0] = val;
    return BigInt(u32[0]) + (BigInt(u32[1]) << 32n);
}

function itof(val) {
    u32[0] = Number(val & 0xffffffffn);
    u32[1] = Number(val >> 32n);
    return f64[0];
}

function hex(val) {
    return '0x' + val.toString(16);
}

// ── Exploitation primitives ──────────────────────────────────

// TODO: Implement addrof primitive
function addrof(obj) {
    // Use type confusion to leak object address
    return 0n;
}

// TODO: Implement fakeobj primitive
function fakeobj(addr) {
    // Use type confusion to create fake object at address
    return {};
}

// TODO: Implement arbitrary read/write
function read64(addr) {
    // Use corrupted ArrayBuffer backing store
    return 0n;
}

function write64(addr, val) {
    // Use corrupted ArrayBuffer backing store
}

// ── Shellcode ────────────────────────────────────────────────
// Use WASM to get RWX page, overwrite with shellcode

var wasm_code = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d,  // WASM magic
    0x01, 0x00, 0x00, 0x00,  // Version 1
    0x01, 0x05, 0x01, 0x60,  // Type section
    0x00, 0x01, 0x7f,        // () -> i32
    0x03, 0x02, 0x01, 0x00,  // Function section
    0x07, 0x08, 0x01, 0x04,  // Export section
    0x6d, 0x61, 0x69, 0x6e,  // "main"
    0x00, 0x00,              // export func 0
    0x0a, 0x06, 0x01, 0x04,  // Code section
    0x00, 0x41, 0x2a, 0x0b   // i32.const 42; end
]);

var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod, {});
var wasm_func = wasm_instance.exports.main;

// ── Trigger ──────────────────────────────────────────────────

console.log("[*] V8 exploit starting...");

// TODO: Trigger vulnerability from patch diff

// %DebugPrint(obj)    // Print object internals
// %SystemBreak()       // Trigger breakpoint

console.log("[+] Done");
)";
}

} // namespace pwner
