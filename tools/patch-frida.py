#!/usr/bin/env python3
"""Apply Florida-style anti-detection patches to the bundled frida-inject.

Florida (https://github.com/Ylarod/Florida) patches frida's source before building
frida-server/frida-inject. We take the stock frida-inject 17.26.2 for android-arm64
and do the same replacements at the binary level, keeping every string the same
length so the ELF layout, dynamic tables and section headers stay intact.

Patched:
  * "frida:rpc"                       -> random 9 chars (rpc channel magic)
  * "frida-agent"                     -> "<rand>-agent" (agent template, resource
                                         names, memfd/maps name, SONAME)
  * "frida_agent_main"                -> "<rand>_agent_main" (agent entrypoint)
  * "gum-js-loop" (thread name)       -> random 11 chars
  * "gmain" / "gdbus" thread names    -> random 5 chars
  * "FridaScriptEngine", "GLib-GIO", "GDBusProxy", "GumScript" inside the embedded
    agents are reversed in place (Florida does the same with sed in its build)
  * "/data/local/tmp/frida-helper-"   -> "/data/adb/dexmcp/helper-" (root-only dir)
  * "/data/local/tmp" (temp dir used for the control pipe when running as root)
                                      -> "/data/adb"
  * "/sys/fs/selinux/load"            -> "/data/adb/dexmcp/ld" (the App points this at
                                         /dev/null and applies the rules through KernelSU,
                                         so frida-inject never reloads the SELinux policy;
                                         compat mode points it back at the real node)

Usage:
  python tools/patch-frida.py app/src/main/assets/frida/frida-inject
  python tools/patch-frida.py --out patched.so frida-inject.orig

The stock binary can be re-downloaded from
https://github.com/frida/frida/releases/download/17.26.2/frida-inject-17.26.2-android-arm64.xz
"""

import argparse
import os
import random
import struct
import sys

FD = b"frida-agent"
ENTRY = b"frida_agent_main"
RPC = b"frida:rpc"
JS_LOOP = b"gum-js-loop"
HELPER_PATH = b"/data/local/tmp/frida-helper-"
TMP_PATH = b"/data/local/tmp"
NEW_HELPER_PATH = b"/data/adb/dexmcp/helper-"
NEW_TMP_PATH = b"/data/adb"
SELINUX_LOAD = b"/sys/fs/selinux/load"
NEW_SELINUX_LOAD = b"/data/adb/dexmcp/ld"
SELINUX_POLICY = b"/sys/fs/selinux/policy"
NEW_SELINUX_POLICY = b"/data/adb/dexmcp/pol"
AGENT_ONLY = [b"FridaScriptEngine", b"GLib-GIO", b"GDBusProxy", b"GumScript"]

ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"


def rand(n):
    return "".join(random.choice(ALNUM) for _ in range(n)).encode()


def replace_equal(data, needle, replacement, label, stats):
    """Replace every occurrence, padding/truncating the replacement to the same size."""
    assert len(replacement) <= len(needle), label
    padded = replacement + b"\x00" * (len(needle) - len(replacement))
    count = data.count(needle)
    if count:
        stats[label] = count
    return data.replace(needle, padded)


def replace_nul_terminated(data, needle, replacement, label, stats):
    """Replace only standalone C strings (`needle` immediately followed by NUL)."""
    count = data.count(needle + b"\x00")
    if count:
        stats[label] = count
    padded = replacement + b"\x00" * (len(needle) - len(replacement))
    return data.replace(needle + b"\x00", padded + b"\x00")


def find_agent_regions(data):
    """Locate the embedded agent shared objects (ELF images bigger than 1 MiB)."""
    starts = []
    i = 0
    while True:
        i = data.find(b"\x7fELF", i)
        if i < 0:
            break
        try:
            cls = data[i + 4]
            if cls == 2:
                phoff = struct.unpack_from("<Q", data, i + 32)[0]
                phnum = struct.unpack_from("<H", data, i + 56)[0]
                phsz = 56
            elif cls == 1:
                phoff = struct.unpack_from("<I", data, i + 28)[0]
                phnum = struct.unpack_from("<H", data, i + 44)[0]
                phsz = 32
            else:
                i += 4
                continue
            if not (0 < phnum <= 20) or phoff * phsz > 65536:
                i += 4
                continue
            end = 0
            for k in range(phnum):
                p = i + phoff + k * phsz
                if cls == 2:
                    off = struct.unpack_from("<Q", data, p + 8)[0]
                    filesz = struct.unpack_from("<Q", data, p + 32)[0]
                else:
                    off = struct.unpack_from("<I", data, p + 4)[0]
                    filesz = struct.unpack_from("<I", data, p + 16)[0]
                end = max(end, i + off + filesz)
            if i != 0 and end - i > 1024 * 1024:
                starts.append((i, end))
            i += 4
        except Exception:
            i += 4

    regions = []
    for idx, (start, end) in enumerate(starts):
        limit = starts[idx + 1][0] if idx + 1 < len(starts) else len(data)
        regions.append((start, max(end, start + (limit - start))))
    return regions


def gnu_hash(name):
    h = 5381
    for c in name:
        h = ((h << 5) + h + c) & 0xFFFFFFFF
    return h


def elf_hash(name):
    h = 0
    for c in name:
        h = ((h << 4) + c) & 0xFFFFFFFF
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= ~g & 0xFFFFFFFF
    return h


def elf_sections(data, base):
    """Return {name: (offset, size)} for the ELF image starting at *base*."""
    cls = data[base + 4]
    if cls == 2:
        shoff = struct.unpack_from("<Q", data, base + 40)[0]
        shnum = struct.unpack_from("<H", data, base + 60)[0]
        shstrndx = struct.unpack_from("<H", data, base + 62)[0]
        entsz = 64
    else:
        shoff = struct.unpack_from("<I", data, base + 32)[0]
        shnum = struct.unpack_from("<H", data, base + 48)[0]
        shstrndx = struct.unpack_from("<H", data, base + 50)[0]
        entsz = 40
    shdrs = []
    for i in range(shnum):
        p = base + shoff + i * entsz
        if cls == 2:
            name, typ, flags, addr, off, size, link, info, align, es = struct.unpack_from("<IIQQQQIIQQ", data, p)
        else:
            name, typ, flags, addr, off, size, link, info, align, es = struct.unpack_from("<IIIIIIIIII", data, p)
        shdrs.append((name, off, size, link, es))
    strname, stroff, strsize, _, _ = shdrs[shstrndx]
    strtab = bytes(data[base + stroff:base + stroff + strsize])
    out = {}
    for name, off, size, link, es in shdrs:
        raw = strtab[name:strtab.find(b"\x00", name)]
        out[raw.decode()] = (base + off, size, link, es)
    return out


def patch_agent_hashes(data, base, entry_name, stats):
    """Keep .gnu.hash/.hash consistent after renaming the exported entrypoint.

    The agent's .gnu.hash has a single bucket, so updating the chain entry and the
    bloom filter is enough; the SysV .hash table is rebuilt from scratch.
    """
    secs = elf_sections(data, base)
    if ".dynsym" not in secs or ".dynstr" not in secs:
        return 0
    dynsym_off, dynsym_size, _, dynsym_entsz = secs[".dynsym"]
    dynstr_off, dynstr_size, _, _ = secs[".dynstr"]
    dynstr = bytes(data[dynstr_off:dynstr_off + dynstr_size])
    entsz = dynsym_entsz or 24
    count = dynsym_size // entsz

    names = []
    for i in range(count):
        st_name = struct.unpack_from("<I", data, dynsym_off + i * entsz)[0]
        if st_name and st_name < len(dynstr):
            names.append(dynstr[st_name:dynstr.find(b"\x00", st_name)])
        else:
            names.append(b"")

    target = None
    for i, name in enumerate(names):
        if name == entry_name:
            target = i
            break
    if target is None:
        return 0

    if ".gnu.hash" in secs:
        gh_off, gh_size, _, _ = secs[".gnu.hash"]
        nbuckets, symoffset, bloom_size, bloom_shift = struct.unpack_from("<IIII", data, gh_off)
        h = gnu_hash(entry_name)
        chain_off = gh_off + 16 + bloom_size * 8 + nbuckets * 4
        idx = target - symoffset
        assert idx >= 0, "entrypoint before symoffset"
        old = struct.unpack_from("<I", data, chain_off + idx * 4)[0]
        struct.pack_into("<I", data, chain_off + idx * 4, (h & ~1) | (old & 1))
        bloom_off = gh_off + 16
        word = (h // 64) % bloom_size
        bits = (1 << (h % 64)) | (1 << ((h >> bloom_shift) % 64))
        old_word = struct.unpack_from("<Q", data, bloom_off + word * 8)[0]
        struct.pack_into("<Q", data, bloom_off + word * 8, old_word | bits)
        stats["gnu.hash"] = stats.get("gnu.hash", 0) + 1

    if ".hash" in secs:
        h_off, h_size, _, _ = secs[".hash"]
        nbucket, nchain = struct.unpack_from("<II", data, h_off)
        assert h_size >= 8 + 4 * nbucket + 4 * nchain
        buckets = [0] * nbucket
        chains = [0] * nchain
        for i, name in enumerate(names):
            if not name or i >= nchain:
                continue
            b = elf_hash(name) % nbucket
            if buckets[b] == 0:
                buckets[b] = i
            else:
                j = buckets[b]
                while chains[j] != 0:
                    j = chains[j]
                chains[j] = i
        struct.pack_into("<%dI" % nbucket, data, h_off + 8, *buckets)
        struct.pack_into("<%dI" % nchain, data, h_off + 8 + 4 * nbucket, *chains)
        stats["sysv.hash"] = stats.get("sysv.hash", 0) + 1
    return 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="stock frida-inject")
    parser.add_argument("--out", help="output path (default: patch input in place)")
    parser.add_argument("--seed", type=int, default=None, help="deterministic suffix seed")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    with open(args.input, "rb") as fp:
        data = bytearray(fp.read())
    original_size = len(data)

    prefix = rand(5)
    rpc = rand(9)
    loop = rand(11)
    gmain = rand(5)
    gdbus = rand(5)
    stats = {}

    def apply(func, needle, replacement, label):
        nonlocal data
        had = data.count(needle)
        if had:
            data = func(data, needle, replacement, label, stats)

    apply(replace_equal, FD, prefix + b"-agent", "frida-agent")
    apply(replace_equal, ENTRY, prefix + b"_agent_main", "frida_agent_main")
    apply(replace_equal, RPC, rpc, "frida:rpc")
    apply(replace_equal, JS_LOOP, loop, "gum-js-loop")
    apply(replace_nul_terminated, b"gmain", gmain, "gmain")
    apply(replace_nul_terminated, b"gdbus", gdbus, "gdbus")
    apply(replace_equal, HELPER_PATH, NEW_HELPER_PATH, "helper path")
    apply(replace_nul_terminated, TMP_PATH, NEW_TMP_PATH, "temp path")
    apply(replace_nul_terminated, SELINUX_LOAD, NEW_SELINUX_LOAD, "selinux policy load")
    apply(replace_nul_terminated, SELINUX_POLICY, NEW_SELINUX_POLICY, "selinux policy read")

    regions = find_agent_regions(bytes(data))
    reversed_hits = 0
    for needle in AGENT_ONLY:
        flipped = needle[::-1]
        for start, end in regions:
            chunk = bytes(data[start:end])
            hits = chunk.count(needle)
            if hits:
                data[start:end] = chunk.replace(needle, flipped)
                reversed_hits += hits
    if reversed_hits:
        stats["agent type strings"] = reversed_hits

    # The entrypoint symbol was renamed above; the dynamic symbol hash tables must
    # follow, otherwise dlsym(handle, "<rand>_agent_main") in the target fails.
    entry_name = prefix + b"_agent_main"
    for start, end in regions:
        patch_agent_hashes(data, start, entry_name, stats)

    assert len(data) == original_size, "size changed"

    out = args.out or args.input
    with open(out, "wb") as fp:
        fp.write(data)

    print(f"patched {out}")
    print(f"  random prefix: {prefix.decode()}  rpc: {rpc.decode()}")
    print(f"  agent regions: {[(hex(s), hex(e)) for s, e in regions]}")
    for label, count in stats.items():
        print(f"  {label}: {count}")


if __name__ == "__main__":
    sys.exit(main())
