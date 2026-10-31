#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automatically locate and lift download restrictions for PCL-CE(v2.15.1+) RegionPolicy regions
"""

import argparse
import hashlib
import os
import struct
import sys
import unicodedata
import zlib

TARGET_NAMESPACE = "PCL.Core.App.Region"
TARGET_TYPE = "RegionAssessment"
TARGET_METHOD = "get_IsRestricted"


class PatchError(Exception):
    pass


def _display_width(text):
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1
               for ch in str(text))


class Log:
    def __init__(self, quiet=False, verbose=False):
        self.quiet = quiet
        self.verbose = verbose
        self.section_no = 0

    def section(self, title):
        self.section_no += 1
        if not self.quiet:
            print("\n[%d] %s" % (self.section_no, title))

    def kv(self, key, value):
        if self.quiet:
            return
        print("  %s%s %s" % (key, " " * max(1, 18 - _display_width(key)), value))

    def text(self, line=""):
        if not self.quiet:
            print(line)

    def note(self, line):
        if not self.quiet:
            print("  " + line)

    def dbg(self, line, indent=6):
        if not self.quiet and self.verbose:
            print(" " * indent + "| " + line)

    def dbg_kv(self, key, value, indent=6):
        if not self.quiet and self.verbose:
            print("%s| %s%s %s" % (" " * indent, key,
                                   " " * max(1, 18 - _display_width(key)), value))


LOG = Log(quiet=True, verbose=False)
def dbg(line, indent=6):
    LOG.dbg(line, indent)


def U16(b, o):
    return struct.unpack_from("<H", b, o)[0]
def U32(b, o):
    return struct.unpack_from("<I", b, o)[0]
def S32(b, o):
    return struct.unpack_from("<i", b, o)[0]
def S64(b, o):
    return struct.unpack_from("<q", b, o)[0]


class Reader:
    def __init__(self, buf, pos):
        self.buf = buf
        self.pos = pos

    def take(self, n):
        if self.pos + n > len(self.buf):
            raise PatchError("读取越界")
        v = self.buf[self.pos:self.pos + n]
        self.pos += n
        return v

    def u8(self):
        return self.take(1)[0]
    def u32(self):
        return struct.unpack("<I", self.take(4))[0]
    def s32(self):
        return struct.unpack("<i", self.take(4))[0]
    def i64(self):
        return struct.unpack("<q", self.take(8))[0]

    def string(self):
        n = 0
        shift = 0
        while True:
            b = self.u8()
            n |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                break
            if shift > 28:
                raise PatchError("7 位长度非法")
        raw = self.take(n)
        return raw.decode("utf-8")
class BundleEntry:
    __slots__ = ("path", "offset", "size", "comp_size", "ftype")

    def __init__(self, path, offset, size, comp_size, ftype):
        self.path = path
        self.offset = offset
        self.size = size
        self.comp_size = comp_size
        self.ftype = ftype

    @property
    def compressed(self):
        return self.comp_size not in (0, self.size)

    def type_name(self):
        return {1: "assembly", 2: "native", 3: "deps.json",
                4: "runtimeconfig"}.get(self.ftype, "type%d" % self.ftype)

    def __repr__(self):
        return "<%s @0x%X size=%d>" % (self.path, self.offset, self.size)


class Bundle:
    def __init__(self, header_offset, major, minor, bundle_id, num, entries,
                 data, layout):
        self.header_offset = header_offset
        self.major = major
        self.minor = minor
        self.bundle_id = bundle_id
        self.num = num
        self.entries = entries
        self.data = data
        self.layout = layout


def _try_bundle_header(data, o):
    n = len(data)
    for has_flags in (False, True):
        for has_comp_size in (False, True):
            tag = "flags=%s comp=%s" % (has_flags, has_comp_size)
            try:
                r = Reader(data, o)
                major = r.u32()
                minor = r.u32()
                num = r.s32()
                if not (1 <= major <= 10) or minor != 0:
                    dbg("0x%X %-22s 版本非法 (%d.%d)" % (o, tag, major, minor))
                    continue
                if not (1 <= num <= 5000):
                    dbg("0x%X %-22s 文件数非法 (%d)" % (o, tag, num))
                    continue
                bundle_id = r.string()
                deps_off = r.i64()
                deps_size = r.i64()
                rc_off = r.i64()
                rc_size = r.i64()
                if has_flags:
                    flags = r.i64()
                    dbg("0x%X %-22s flags=0x%X" % (o, tag, flags))
                entries = []
                for idx in range(num):
                    off = r.i64()
                    size = r.i64()
                    comp = r.i64() if has_comp_size else size
                    ftype = r.u8()
                    path = r.string()
                    entries.append(BundleEntry(path, off, size, comp, ftype))
                if r.pos != n:
                    dbg("0x%X %-22s 未落在 EOF (停 0x%X, 差 %d )"
                        % (o, tag, r.pos, n - r.pos))
                    continue
                offsets = [e.offset for e in entries]
                if offsets != sorted(offsets):
                    dbg("0x%X %-22s 条目偏移非递增" % (o, tag))
                    continue
                if any(e.offset < 0 or e.size < 0 or e.offset + e.size > n
                       for e in entries):
                    dbg("0x%X %-22s 条目越界" % (o, tag))
                    continue
                if not any(e.path.lower().endswith(".dll") for e in entries):
                    dbg("0x%X %-22s 没有任何 dll 条目" % (o, tag))
                    continue
                dbg("0x%X %-22s 命中: v%d.%d, %d 个文件, id=%r"
                    % (o, tag, major, minor, num, bundle_id))
                return Bundle(o, major, minor, bundle_id, num, entries, data, tag)
            except (PatchError, struct.error, UnicodeDecodeError, IndexError) as e:
                dbg("0x%X %-22s 失败: %s" % (o, tag, e))
                continue
    return None


def parse_bundle(data):
    n = len(data)
    scan_from = max(0, n - 512 * 1024)
    dbg("文件大小 %d (0x%X), 扫描区间 0x%X..0x%X"
        % (n, n, scan_from, n - 12), 2)
    hits = 0
    for o in range(scan_from, max(scan_from, n - 12)):
        if data[o] > 10 or data[o] == 0:
            continue
        if data[o + 1] or data[o + 2] or data[o + 3]:
            continue
        if U32(data, o + 4) != 0:
            continue
        num = S32(data, o + 8)
        if not (1 <= num <= 5000):
            continue
        hits += 1
        dbg("候选位置 0x%X: major=%d minor=0 numFiles=%d"
            % (o, data[o], num), 2)
        b = _try_bundle_header(data, o)
        if b is not None:
            dbg("共检查 %d 个候选, 采用 0x%X" % (hits, o), 2)
            return b
    dbg("未找到 bundle 索引 (通过初筛的候选 %d 个)" % hits, 2)
    return None

class PE:
    def __init__(self, buf):
        self.buf = buf
        dbg("DOS 头: MZ, e_lfanew = 0x%X" % U32(buf, 0x3C))
        if buf[0:2] != b"MZ":
            raise PatchError("不是 PE 文件(缺少 MZ 头)")
        pe = U32(buf, 0x3C)
        if buf[pe:pe + 4] != b"PE\0\0":
            raise PatchError("PE 签名错误")
        self.num_sections = U16(buf, pe + 6)
        self.opt_size = U16(buf, pe + 20)
        self.machine = U16(buf, pe + 4)
        dbg("COFF 头: machine=0x%04X, 节数=%d, 可选头长度=%d"
            % (self.machine, self.num_sections, self.opt_size))
        opt = pe + 24
        magic = U16(buf, opt)
        if magic == 0x20B:
            self.magic = "PE32+"
            self.data_dirs = opt + 112
        elif magic == 0x10B:
            self.magic = "PE32"
            self.data_dirs = opt + 96
        else:
            raise PatchError("未知的可选头 magic: 0x%X" % magic)
        dbg("可选头 magic=0x%X (%s), 数据目录表 0x%X"
            % (magic, self.magic, self.data_dirs))
        self.sections = []
        base = opt + self.opt_size
        for i in range(self.num_sections):
            s = base + i * 40
            name = buf[s:s + 8].rstrip(b"\0").decode("latin-1")
            vsize = U32(buf, s + 8)
            vaddr = U32(buf, s + 12)
            rsize = U32(buf, s + 16)
            rptr = U32(buf, s + 20)
            self.sections.append((name, vaddr, vsize, rptr, rsize))
            dbg("节[%d] %-8s VA=0x%08X VSize=0x%08X RawPtr=0x%08X RawSize=0x%08X"
                % (i, name, vaddr, vsize, rptr, rsize))
        self.clr_rva = U32(buf, self.data_dirs + 14 * 8)
        self.clr_size = U32(buf, self.data_dirs + 14 * 8 + 4)
        self.entry_point_rva = U32(buf, opt + 16)
        dbg("数据目录[14] CLR Runtime Header: RVA=0x%X Size=%d -> %s"
            % (self.clr_rva, self.clr_size,
               "托管程序集" if self.is_managed else "原生文件"))
        dbg("数据目录[4] 证书表: RVA=0x%X Size=%d -> %s"
            % (U32(buf, self.data_dirs + 4 * 8),
               U32(buf, self.data_dirs + 4 * 8 + 4),
               "已签名" if U32(buf, self.data_dirs + 4 * 8) else "未签名"))

    @property
    def is_managed(self):
        return self.clr_rva != 0 and self.clr_size != 0

    def rva_to_offset(self, rva, quiet=False):
        for name, vaddr, vsize, rptr, rsize in self.sections:
            span = max(vsize, rsize)
            if vaddr <= rva < vaddr + span:
                delta = rva - vaddr
                if delta >= rsize:
                    raise PatchError(
                        "RVA 0x%X 落在节 %s 的未初始化区" % (rva, name))
                if not quiet:
                    dbg("RVA 0x%X 命中节 %s: 0x%X + (0x%X - 0x%X) = 0x%X"
                        % (rva, name, rptr, rva, vaddr, rptr + delta))
                return rptr + delta
        raise PatchError("RVA 0x%X 不属于任何节" % rva)
def read_streams(buf, pe):
    cor = pe.rva_to_offset(pe.clr_rva)
    cb = U32(buf, cor)
    md_rva = U32(buf, cor + 8)
    md_size = U32(buf, cor + 12)
    dbg("COR20 头 @0x%X: cb=%d, 运行时版本 %d.%d, 元数据 RVA=0x%X Size=%d"
        % (cor, cb, U16(buf, cor + 4), U16(buf, cor + 6), md_rva, md_size))
    dbg("COR20 标志=0x%X, 强名称签名大小=%d (%s)"
        % (U32(buf, cor + 16), U32(buf, cor + 32),
           "未签名" if U32(buf, cor + 32) == 0 else "已签名"))

    md = pe.rva_to_offset(md_rva, quiet=True)
    if U32(buf, md) != 0x424A5342:
        raise PatchError("元数据签名不是 BSJB, 不是托管程序集?")
    ver_len = U32(buf, md + 12)
    version = buf[md + 16:md + 16 + ver_len].rstrip(b"\0").decode("latin-1")
    dbg("元数据根 @0x%X: 签名 BSJB, 版本串 %r" % (md, version))

    p = md + 16 + ver_len
    if p + 4 > len(buf):
        raise PatchError("元数据根越界")
    nstreams = U16(buf, p + 2)
    p += 4
    dbg("流数量 = %d" % nstreams)
    streams = {}
    for _ in range(nstreams):
        off = U32(buf, p)
        size = U32(buf, p + 4)
        p += 8
        name = bytearray()
        while buf[p] != 0:
            name.append(buf[p])
            p += 1
        p += 1
        while (p - md) % 4 != 0:
            p += 1
        key = name.decode("latin-1")
        streams[key] = (md + off, size)
        dbg("流 %-10s 偏移 0x%06X 大小 0x%06X" % (key, off, size))
        if off + size > md_size:
            raise PatchError("流 %s 越界" % key)
    return {"meta_off": md, "meta_size": md_size, "streams": streams}


# 元数据表列定义: ('u16'|'u32'|'str'|'guid'|'blob'|('idx',表号)|('coded',编码名))
CODED_INDEX = {
    "ResolutionScope": ([0x00, 0x01, 0x1A, 0x23], 2),
    "TypeDefOrRef": ([0x02, 0x01, 0x1B], 2),
}

TABLE_NAMES = {
    0x00: "Module", 0x01: "TypeRef", 0x02: "TypeDef", 0x03: "FieldPtr",
    0x04: "Field", 0x05: "MethodPtr", 0x06: "MethodDef",
}

COLUMNS = {
    0x00: [("u16",), ("str",), ("guid",), ("guid",), ("guid",)],              # Module
    0x01: [("coded", "ResolutionScope"), ("str",), ("str",)],                  # TypeRef
    0x02: [("u32",), ("str",), ("str",), ("coded", "TypeDefOrRef"),
           ("idx", 0x04), ("idx", 0x06)],                                      # TypeDef
    0x03: [("idx", 0x04)],                                                     # FieldPtr
    0x04: [("u16",), ("str",), ("blob",)],                                     # Field
    0x05: [("idx", 0x06)],                                                     # MethodPtr
    0x06: [("u32",), ("u16",), ("u16",), ("str",), ("blob",), ("idx", 0x08)],   # MethodDef
}


def _coded_size(rows, name):
    tables, bits = CODED_INDEX[name]
    mx = max(rows.get(t, 0) for t in tables)
    return 4 if mx >= (1 << (16 - bits)) else 2


def _column_size(rows, heap, col):
    kind = col[0]
    if kind == "u16":
        return 2
    if kind == "u32":
        return 4
    if kind == "str":
        return 4 if heap & 0x01 else 2
    if kind == "guid":
        return 4 if heap & 0x02 else 2
    if kind == "blob":
        return 4 if heap & 0x04 else 2
    if kind == "idx":
        return 4 if rows.get(col[1], 0) >= 0x10000 else 2
    if kind == "coded":
        return _coded_size(rows, col[1])
    raise PatchError("未知列类型 %r" % (col,))


def row_size(rows, heap, table):
    return sum(_column_size(rows, heap, c) for c in COLUMNS[table])


def read_row(buf, off, rows, heap, table):
    vals = []
    p = off
    for col in COLUMNS[table]:
        n = _column_size(rows, heap, col)
        vals.append(U16(buf, p) if n == 2 else U32(buf, p))
        p += n
    return vals


def parse_tables(buf, md):
    streams = md["streams"]
    key = None
    for cand in ("#~", "#-"):
        if cand in streams:
            key = cand
            break
    if key is None:
        raise PatchError("找不到 #~ 元数据表流")

    t, tsize = streams[key]
    heap = buf[t + 6]
    dbg("表流 %s @0x%X: 版本 %d.%d, heapSizes=0x%02X, 保留=0x%02X"
        % (key, t, buf[t + 4], buf[t + 5], heap, buf[t + 7]))
    valid = struct.unpack_from("<Q", buf, t + 8)[0]
    sorted_mask = struct.unpack_from("<Q", buf, t + 16)[0]
    dbg("valid 掩码 = 0x%016X, sorted 掩码 = 0x%016X" % (valid, sorted_mask))
    p = t + 24
    rows = {}
    for i in range(64):
        if (valid >> i) & 1:
            rows[i] = U32(buf, p)
            p += 4
    dbg("共 %d 张表, 行数数组结束于 0x%X" % (len(rows), p), 6)
    dbg("行数: " + ", ".join("%s=%d" % (TABLE_NAMES.get(i, "0x%02X" % i), n)
                             for i, n in sorted(rows.items())), 6)

    offsets = {}
    cur = p
    for i in sorted(rows):
        if i > 0x06:
            break
        if i not in COLUMNS:
            raise PatchError("表 0x%02X 未支持, 无法计算偏移" % i)
        rs = row_size(rows, heap, i)
        offsets[i] = cur
        dbg("表 %-9s 行数 %5d x 行宽 %2d = %7d 字节, 起点 0x%06X"
            % (TABLE_NAMES[i], rows[i], rs, rows[i] * rs, cur))
        cur += rows[i] * rs

    return {
        "stream": key,
        "heap": heap,
        "rows": rows,
        "row_offsets": offsets,
        "data_start": p,
    }


def get_string(buf, md, idx):
    if idx == 0:
        return ""
    base, size = md["streams"]["#Strings"]
    if idx >= size:
        raise PatchError("#Strings 索引 0x%X 越界" % idx)
    start = base + idx
    end = start
    limit = base + size
    while end < limit and buf[end] != 0:
        end += 1
    return buf[start:end].decode("utf-8", "replace")


def find_method(buf, md, tables):
    rows = tables["rows"]
    heap = tables["heap"]
    if 0x02 not in tables["row_offsets"]:
        raise PatchError("元数据里没有 TypeDef 表")
    if 0x06 not in tables["row_offsets"]:
        raise PatchError("元数据里没有 MethodDef 表")

    t2 = tables["row_offsets"][0x02]
    t6 = tables["row_offsets"][0x06]
    rs2 = row_size(rows, heap, 0x02)
    rs6 = row_size(rows, heap, 0x06)
    n2 = rows[0x02]
    n6 = rows[0x06]
    dbg("TypeDef 表 @0x%X, %d 行 x %d 字节" % (t2, n2, rs2))
    dbg("MethodDef 表 @0x%X, %d 行 x %d 字节" % (t6, n6, rs6))

    type_rows = []
    for i in range(n2):
        vals = read_row(buf, t2 + i * rs2, rows, heap, 0x02)
        namespace = get_string(buf, md, vals[2])
        name = get_string(buf, md, vals[1])
        type_rows.append((namespace, name, vals[5]))

    hit = None
    for i, (namespace, name, _) in enumerate(type_rows):
        if namespace == TARGET_NAMESPACE and name == TARGET_TYPE:
            hit = i
            break
    if hit is None:
        raise PatchError("没找到类型 %s.%s" % (TARGET_NAMESPACE, TARGET_TYPE))

    flags, name_i, ns_i, extends, field_list, method_list = read_row(
        buf, t2 + hit * rs2, rows, heap, 0x02)
    dbg("TypeDef#%d 行 @0x%X: Flags=0x%X, Extends=0x%X, FieldList=%d, MethodList=%d"
        % (hit + 1, t2 + hit * rs2, flags, extends, field_list, method_list))

    start = type_rows[hit][2]
    end = n6 + 1
    for j in range(hit + 1, n2):
        nxt = type_rows[j][2]
        if nxt:
            end = nxt
            break
    dbg("方法区间 = MethodDef 行 %d..%d (%d 个)" % (start, end - 1, end - start))
    if start < 1:
        raise PatchError("TypeDef#%d 的 MethodList 无效" % (hit + 1))

    for row in range(start, end):
        row_off = t6 + (row - 1) * rs6
        vals = read_row(buf, row_off, rows, heap, 0x06)
        rva, impl_flags, method_flags, name_idx, sig_idx, param_list = vals
        name = get_string(buf, md, name_idx)
        dbg("#%-5d @0x%06X RVA=0x%06X Impl=0x%04X Flags=0x%04X %s"
            % (row, row_off, rva, impl_flags, method_flags, name))
        if name == TARGET_METHOD:
            return {
                "typedef_index": hit + 1,
                "typedef_name": type_rows[hit][0] + "." + type_rows[hit][1],
                "methoddef_index": row,
                "token": 0x06000000 | row,
                "rva": rva,
                "impl_flags": impl_flags,
                "flags": method_flags,
                "table_offset": row_off,
                "param_list": param_list,
                "signature": sig_idx,
            }

    raise PatchError("%s 里没找到方法 %s" % (TARGET_TYPE, TARGET_METHOD))
def locate_body(buf, pe, rva):
    off = pe.rva_to_offset(rva)
    first = buf[off]
    kind = first & 0x03
    dbg("方法体首字节 0x%02X, 头类型 = %d (%s)"
        % (first, kind, {2: "tiny", 3: "fat"}.get(kind, "非法")))
    if LOG.verbose:
        LOG.text(hexdump(buf[off:off + 16], off))
    if kind == 0x02:
        return {
            "kind": "tiny",
            "header_offset": off,
            "header_size": 1,
            "max_stack": 8,
            "code_size": first >> 2,
            "code_offset": off + 1,
        }
    if kind == 0x03:
        head = U16(buf, off)
        header_size = ((head >> 12) & 0x0F) * 4
        if header_size < 12:
            raise PatchError("fat header 长度异常: %d" % header_size)
        body = {
            "kind": "fat",
            "header_offset": off,
            "header_size": header_size,
            "flags_word": head,
            "max_stack": U16(buf, off + 2),
            "code_size": U32(buf, off + 4),
            "local_sig": U32(buf, off + 8),
            "code_offset": off + header_size,
        }
        dbg("fat header: flags=0x%04X (%d 字节头, InitLocals=%d), "
            "MaxStack=%d, CodeSize=%d, LocalVarSig=0x%08X"
            % (head, header_size,
               1 if (head & 0x10) else 0,
               body["max_stack"], body["code_size"], body["local_sig"]))
        return body
    raise PatchError("未知的方法体头 (首字节 0x%02X)" % first)


def hexdump(data, base=0):
    out = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexpart = " ".join("%02X" % b for b in chunk)
        out.append("  %08X  %-47s  %s"
                   % (base + i, hexpart,
                      "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)))
    return "\n".join(out)



def analyze_executable(data, label):
    info = {"label": label, "container": None, "dll_offset": 0}

    LOG.section("容器")
    bundle = parse_bundle(data)
    if bundle is not None:
        info["container"] = "bundle"
        info["bundle"] = bundle
        LOG.kv("类型", ".NET 单文件 bundle (v%d.%d), 清单 0x%X, "
                       "共 %d 个文件" % (bundle.major, bundle.minor,
                                        bundle.header_offset, bundle.num))
        LOG.kv("布局", bundle.layout)
        if LOG.verbose:
            LOG.text("  条目清单:")
            for e in bundle.entries:
                LOG.text("    %08X  %10d  %-13s %s"
                         % (e.offset, e.size, e.type_name(), e.path))
        target = None
        for e in bundle.entries:
            if os.path.basename(e.path).lower() == "pcl.core.dll":
                target = e
                break
        if target is None:
            raise PatchError("bundle 里没有 PCL.Core.dll")
        if target.compressed:
            raise PatchError(
                "PCL.Core.dll 在 bundle 里是压缩的, 无法等长修改"
                "请在解包后用文件夹方式运行")
        info["entry"] = target
        info["dll_offset"] = target.offset
        LOG.kv("PCL.Core.dll", "偏移 0x%X, 大小 %s 字节"
               % (target.offset, format(target.size, ",")))
        dll = data[target.offset:target.offset + target.size]
    else:
        LOG.kv("类型", "裸托管程序集")
        LOG.kv("文件", label)
        dll = data

    LOG.section("PE 与节表")
    pe = PE(dll)
    if not pe.is_managed:
        raise PatchError("这个文件不是托管程序集 (CLR 目录为空)")
    info["pe"] = pe
    info["magic"] = pe.magic
    LOG.kv("架构", pe.magic)

    LOG.section("元数据")
    md = read_streams(dll, pe)
    info["md"] = md
    tables = parse_tables(dll, md)
    info["tables"] = tables
    info["heap"] = tables["heap"]
    LOG.kv("元数据流", "%s @ +0x%X"
           % (tables["stream"], md["streams"][tables["stream"]][0] - md["meta_off"]))
    LOG.kv("堆大小", "0x%02X (#Strings=%s, #GUID=%s, #Blob=%s)"
           % (tables["heap"],
              "4" if tables["heap"] & 1 else "2",
              "4" if tables["heap"] & 2 else "2",
              "4" if tables["heap"] & 4 else "2"))
    LOG.kv("行数", "TypeDef=%d  MethodDef=%d"
           % (tables["rows"].get(0x02, 0), tables["rows"].get(0x06, 0)))

    method = find_method(dll, md, tables)
    info["method"] = method
    LOG.kv("TypeDef#", "%d  %s" % (method["typedef_index"], method["typedef_name"]))
    LOG.kv("MethodDef#", "%d  %s" % (method["methoddef_index"], TARGET_METHOD))
    LOG.kv("token", "0x%08X" % method["token"])
    LOG.kv("RVA", "0x%06X" % method["rva"])

    LOG.section("RVA -> 文件偏移")
    secname = None
    for name, vaddr, vsize, rptr, rsize in pe.sections:
        if vaddr <= method["rva"] < vaddr + max(vsize, rsize):
            secname = (name, vaddr, rptr)
            LOG.kv("命中节", "%s  VirtualAddress=0x%X  PointerToRawData=0x%X"
                   % (name, vaddr, rptr))
            break
    info["_sec"] = secname
    body = locate_body(dll, pe, method["rva"])
    info["body"] = body
    dll_method_off = pe.rva_to_offset(method["rva"], quiet=True)
    info["dll_method_offset"] = dll_method_off
    info["file_method_offset"] = info["dll_offset"] + dll_method_off
    info["file_code_offset"] = info["dll_offset"] + body["code_offset"]
    if body["kind"] == "fat":
        info["file_code_size_offset"] = info["dll_offset"] + body["header_offset"] + 4
    else:
        info["file_code_size_offset"] = None

    LOG.kv("DLL 内", "0x%X + (0x%X - 0x%X) = 0x%X"
           % (secname[2], method["rva"], secname[1], dll_method_off))
    if info["dll_offset"]:
        LOG.kv("加容器偏移", "0x%X + 0x%X = 0x%X"
               % (info["dll_offset"], dll_method_off, info["file_method_offset"]))

    LOG.section("方法体")
    code = dll[body["code_offset"]:body["code_offset"] + body["code_size"]]
    info["orig_il"] = code
    LOG.kv("头部", "%s, %d 字节, MaxStack=%d, CodeSize=%d"
           % (body["kind"], body["header_size"], body["max_stack"],
              body["code_size"]))
    LOG.kv("IL 偏移", "0x%X (DLL 内 0x%X)"
           % (info["file_code_offset"], body["code_offset"]))
    LOG.text("  原始 IL (%d 字节):" % len(code))
    LOG.text(hexdump(code, info["file_code_offset"]))
    patched = bytearray(code)
    patched[0:2] = b"\x16\x2a"
    LOG.text("  补丁后 IL:")
    LOG.text(hexdump(bytes(patched), info["file_code_offset"]))
    info["dll"] = dll
    return info


def compute_patch(info):
    body = info["body"]
    code_off = info["file_code_offset"]
    if body["kind"] == "fat":
        return [
            (info["file_code_size_offset"], b"\x16\x00\x00\x00", b"\x02\x00\x00\x00"),
            (code_off, b"\x02\x28", b"\x16\x2a"),
        ]
    first = info["dll"][body["header_offset"]]
    new_first = (2 << 2) | 0x02
    return [
        (info["dll_offset"] + body["header_offset"], bytes([first]), bytes([new_first])),
        (code_off, b"\x02\x28", b"\x16\x2a"),
    ]


def already_patched(info):
    body = info["body"]
    return body["code_size"] == 2 and info["orig_il"][:2] == b"\x16\x2a"
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Automatically locate and lift download restrictions for PCL-CE(v2.15.1+) RegionPolicy regions",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="PCL2_CE.exe, PCL.Core.dll")
    ap.add_argument("-o", "--output", help="output file path")
    ap.add_argument("-i", "--in-place", action="store_true",
                    help="backup and modify")
    ap.add_argument("-c", "--check", action="store_true",
                    help="calculate offset only")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="detail mode")
    ap.add_argument("-x", "--extract", metavar="DIR",
                    help="unpacking files")
    ap.add_argument("-q", "--quiet", action="store_true", help="output modify exe without detail info")
    args = ap.parse_args(argv)

    global LOG
    LOG = Log(quiet=args.quiet, verbose=args.verbose)

    try:
        with open(args.input, "rb") as f:
            data = f.read()
    except OSError as e:
        print("错误: 无法读取 %s (%s)" % (args.input, e), file=sys.stderr)
        return 1

    if args.verbose:
        LOG.text("输入文件: %s (%s 字节)" % (os.path.abspath(args.input),
                                         format(len(data), ",")))

    if args.extract:
        return do_extract(data, args)

    try:
        info = analyze_executable(data, args.input)
    except PatchError as e:
        print("\n错误: %s" % e, file=sys.stderr)
        return 1

    if already_patched(info):
        LOG.text("")
        LOG.note("[!] 已经被改过了")
        return 0

    patches = compute_patch(info)
    LOG.section("补丁")
    for off, old, new in patches:
        LOG.kv("0x%08X" % off, "%-14s -> %s"
               % (" ".join("%02X" % b for b in old),
                  " ".join("%02X" % b for b in new)))

    if args.check:
        LOG.text("")
        return 0

    out = bytearray(data)
    LOG.section("写入")
    for off, old, new in patches:
        current = out[off:off + len(old)]
        dbg("核对 0x%08X: 文件中是 %s, 期望 %s"
            % (off, " ".join("%02X" % b for b in current),
               " ".join("%02X" % b for b in old)))
        if current != old:
            print("错误: 0x%X 处的原字节与预期不符"
                  % off, file=sys.stderr)
            return 1
        out[off:off + len(new)] = new
        dbg("已写入 0x%08X: %s" % (off, " ".join("%02X" % b for b in new)))

    if len(out) != len(data):
        print("错误: 补丁改变了文件大小", file=sys.stderr)
        return 1
    LOG.kv("大小", "%s 字节" % format(len(out), ","))

    if args.in_place:
        target = args.input
        backup = target + ".bak"
        if not os.path.exists(backup):
            with open(backup, "wb") as f:
                f.write(data)
            LOG.kv("备份", backup)
    else:
        if args.output:
            target = args.output
        else:
            root, ext = os.path.splitext(args.input)
            target = root + "_unlocked" + (ext or ".exe")

    with open(target, "wb") as f:
        f.write(out)

    LOG.kv("输出", os.path.abspath(target))
    LOG.kv("原 SHA256", hashlib.sha256(data).hexdigest())
    LOG.kv("新 SHA256", hashlib.sha256(out).hexdigest())
    LOG.text("")
    LOG.note("[OK] 完成")
    return 0


def do_extract(data, args):
    bundle = parse_bundle(data)
    if bundle is None:
        print("错误: 这个文件不是 .NET 单文件 bundle, 无法解包", file=sys.stderr)
        return 1
    outdir = args.extract
    os.makedirs(outdir, exist_ok=True)
    total = 0
    for e in bundle.entries:
        raw = data[e.offset:e.offset + (e.comp_size if e.compressed else e.size)]
        if e.compressed:
            try:
                raw = zlib.decompress(raw, -15)
            except zlib.error as err:
                print("  [跳过] %s (解压失败: %s)" % (e.path, err))
                continue
        dest = os.path.join(outdir, e.path.replace("/", os.sep))
        os.makedirs(os.path.dirname(dest) or outdir, exist_ok=True)
        with open(dest, "wb") as f:
            f.write(raw)
        dbg("解包 %-45s %9d 字节 -> %s" % (e.path, len(raw), dest), 2)
        total += 1
    print("已解包 %d/%d 个文件 -> %s" % (total, bundle.num, os.path.abspath(outdir)))
    return 0


def _setup_io():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


if __name__ == "__main__":
    _setup_io()
    sys.exit(main())
