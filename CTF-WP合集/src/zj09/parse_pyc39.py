# -*- coding: utf-8 -*-
"""
parse_pyc39.py —— 手工解析 Python 3.9 的 .pyc（marshal version 4）
本机只有 Python 3.12，marshal 格式与 3.9 不兼容，所以自己写解析器 + 3.9 opcode 表。

仅支持本题需要的类型：code object / str / bytes / int / None / tuple / 等
用法： python parse_pyc39.py <pyc路径>
"""
import sys
import struct

# ---------------- marshal 类型码（Python 3.9, marshal version 4）----------------
FLAG_REF = 0x80
TYPE_NULL = ord('0')
TYPE_NONE = ord('N')
TYPE_FALSE = ord('F')
TYPE_TRUE = ord('T')
TYPE_STOPITER = ord('S')
TYPE_ELLIPSIS = ord('.')
TYPE_INT = ord('i')
TYPE_INT64 = ord('I')
TYPE_FLOAT = ord('f')
TYPE_BINARY_FLOAT = ord('g')
TYPE_COMPLEX = ord('x')
TYPE_BINARY_COMPLEX = ord('y')
TYPE_LONG = ord('l')
TYPE_STRING = ord('s')
TYPE_INTERNED = ord('t')
TYPE_REF = ord('r')
TYPE_TUPLE = ord('(')
TYPE_SMALL_TUPLE = ord(')')   # Python 3.4+ : 1 字节长度
TYPE_LIST = ord('[')
TYPE_DICT = ord('{')
TYPE_CODE = ord('c')
TYPE_UNICODE = ord('u')
TYPE_UNKNOWN = ord('?')
TYPE_SET = ord('<')
TYPE_FROZENSET = ord('>')
TYPE_ASCII = ord('a')
TYPE_ASCII_INTERNED = ord('A')
TYPE_SHORT_ASCII = ord('z')
TYPE_SHORT_ASCII_INTERNED = ord('Z')


class Code:
    """3.9 的 code object 字段（注意 3.9 还没有 linetable，用的是 lnotab）"""

    def __init__(self):
        self.argcount = 0
        self.posonlyargcount = 0
        self.kwonlyargcount = 0
        self.nlocals = 0
        self.stacksize = 0
        self.flags = 0
        self.code = b''
        self.consts = ()
        self.names = ()
        self.varnames = ()
        self.freevars = ()
        self.cellvars = ()
        self.filename = ''
        self.name = ''
        self.firstlineno = 0
        self.lnotab = b''

    def __repr__(self):
        return '<Code %s>' % self.name


class Reader:
    def __init__(self, data):
        self.d = data
        self.p = 0
        self.refs = []          # FLAG_REF 的对象表

    def byte(self):
        b = self.d[self.p]
        self.p += 1
        return b

    def n(self, size):
        s = self.d[self.p:self.p + size]
        self.p += size
        return s

    def i32(self):
        v = struct.unpack('<i', self.n(4))[0]
        return v

    def u32(self):
        return struct.unpack('<I', self.n(4))[0]

    def i64(self):
        return struct.unpack('<q', self.n(8))[0]

    # 容器类：CPython 是"先占 ref 槽位再读子对象"，所以 ref 表顺序是前序
    _CONTAINERS = (TYPE_TUPLE, TYPE_SMALL_TUPLE, TYPE_LIST, TYPE_DICT,
                   TYPE_SET, TYPE_FROZENSET, TYPE_CODE)

    def read_object(self):
        code = self.byte()
        flag = code & FLAG_REF
        t = code & ~FLAG_REF
        if t == TYPE_REF:
            idx = self.i32()
            if idx >= len(self.refs):
                raise ValueError('bad ref #%d (have %d) at %d' % (idx, len(self.refs), self.p))
            return self.refs[idx]
        if flag and t in self._CONTAINERS:
            slot = len(self.refs)
            self.refs.append(None)      # 先占位，保证索引与 CPython 一致
            obj = self._read(t)
            self.refs[slot] = obj
            return obj
        obj = self._read(t)
        if flag:
            self.refs.append(obj)
        return obj

    def _read(self, t):
        if t == TYPE_NULL:
            return None
        if t == TYPE_NONE:
            return None
        if t == TYPE_FALSE:
            return False
        if t == TYPE_TRUE:
            return True
        if t == TYPE_STOPITER:
            return StopIteration
        if t == TYPE_ELLIPSIS:
            return Ellipsis
        if t == TYPE_INT:
            return self.i32()
        if t == TYPE_INT64:
            return self.i64()
        if t == TYPE_FLOAT:
            n = self.byte()
            return float(self.n(n).decode('ascii'))
        if t == TYPE_BINARY_FLOAT:
            return struct.unpack('<d', self.n(8))[0]
        if t == TYPE_COMPLEX:
            n = self.byte()
            s = self.n(n).decode('ascii')
            r, i = s.split('+', 1) if '+' in s else s.split('-', 1)
            return complex(float(r.rstrip('+')), float(i.replace('j', '')))
        if t == TYPE_BINARY_COMPLEX:
            return complex(struct.unpack('<d', self.n(8))[0], struct.unpack('<d', self.n(8))[0])
        if t == TYPE_LONG:
            n = self.i32()
            v = 0
            for k in range(abs(n)):
                d = struct.unpack('<H', self.n(2))[0]
                v |= d << (15 * k)
            if n < 0:
                v = -v
            return v
        if t == TYPE_STRING:
            return self.n(self.i32())
        if t == TYPE_INTERNED:
            return self.n(self.i32()).decode('utf-8', 'surrogateescape')
        if t == TYPE_ASCII:
            return self.n(self.i32()).decode('ascii')
        if t == TYPE_ASCII_INTERNED:
            return self.n(self.i32()).decode('ascii')
        if t == TYPE_SHORT_ASCII:
            return self.n(self.byte()).decode('ascii')
        if t == TYPE_SHORT_ASCII_INTERNED:
            return self.n(self.byte()).decode('ascii')
        if t == TYPE_UNICODE:
            return self.n(self.i32()).decode('utf-8', 'surrogateescape')
        if t == TYPE_REF:
            return self.refs[self.i32()]
        if t == TYPE_SMALL_TUPLE:
            n = self.byte()
            out = []
            for _ in range(n):
                out.append(self.read_object())
            return tuple(out)
        if t == TYPE_TUPLE:
            n = self.i32()
            out = []
            for _ in range(n):
                out.append(self.read_object())
            return tuple(out)
        if t == TYPE_LIST:
            n = self.i32()
            out = []
            for _ in range(n):
                out.append(self.read_object())
            return out
        if t == TYPE_DICT:
            out = {}
            while True:
                k = self.read_object()
                if k is None and self.d[self.p - 1] == TYPE_NULL:
                    break
                v = self.read_object()
                out[k] = v
            return out
        if t == TYPE_SET or t == TYPE_FROZENSET:
            n = self.i32()
            out = []
            for _ in range(n):
                out.append(self.read_object())
            return set(out) if t == TYPE_SET else frozenset(out)
        if t == TYPE_CODE:
            c = Code()
            c.argcount = self.i32()
            c.posonlyargcount = self.i32()
            c.kwonlyargcount = self.i32()
            c.nlocals = self.i32()
            c.stacksize = self.i32()
            c.flags = self.i32()
            c.code = self.read_object()
            c.consts = self.read_object()
            c.names = self.read_object()
            c.varnames = self.read_object()
            c.freevars = self.read_object()
            c.cellvars = self.read_object()
            c.filename = self.read_object()
            c.name = self.read_object()
            c.firstlineno = self.i32()
            c.lnotab = self.read_object()
            return c
        raise ValueError('unknown marshal type 0x%02x at %d' % (t, self.p - 1))


# ---------------- Python 3.9 opcode 表 ----------------
opname = ['<%d>' % i for i in range(256)]


def _d(name, op):
    opname[op] = name


for _n, _o in [
    ('POP_TOP', 1), ('ROT_TWO', 2), ('ROT_THREE', 3), ('DUP_TOP', 4), ('DUP_TOP_TWO', 5),
    ('ROT_FOUR', 6), ('NOP', 9), ('UNARY_POSITIVE', 10), ('UNARY_NEGATIVE', 11),
    ('UNARY_NOT', 12), ('UNARY_INVERT', 15), ('BINARY_MATRIX_MULTIPLY', 16),
    ('INPLACE_MATRIX_MULTIPLY', 17), ('BINARY_POWER', 19), ('BINARY_MULTIPLY', 20),
    ('BINARY_MODULO', 22), ('BINARY_ADD', 23), ('BINARY_SUBTRACT', 24), ('BINARY_SUBSCR', 25),
    ('BINARY_FLOOR_DIVIDE', 26), ('BINARY_TRUE_DIVIDE', 27), ('INPLACE_FLOOR_DIVIDE', 28),
    ('INPLACE_TRUE_DIVIDE', 29), ('RERAISE', 48), ('WITH_EXCEPT_START', 49),
    ('GET_AITER', 50), ('GET_ANEXT', 51), ('BEFORE_ASYNC_WITH', 52), ('BEGIN_FINALLY', 53),
    ('END_ASYNC_FOR', 54), ('INPLACE_ADD', 55), ('INPLACE_SUBTRACT', 56),
    ('INPLACE_MULTIPLY', 57), ('INPLACE_MODULO', 59), ('STORE_SUBSCR', 60),
    ('DELETE_SUBSCR', 61), ('BINARY_LSHIFT', 62), ('BINARY_RSHIFT', 63), ('BINARY_AND', 64),
    ('BINARY_XOR', 65), ('BINARY_OR', 66), ('INPLACE_POWER', 67), ('GET_ITER', 68),
    ('GET_YIELD_FROM_ITER', 69), ('PRINT_EXPR', 70), ('LOAD_BUILD_CLASS', 71),
    ('YIELD_FROM', 72), ('GET_AWAITABLE', 73), ('LOAD_ASSERTION_ERROR', 74),
    ('INPLACE_LSHIFT', 75), ('INPLACE_RSHIFT', 76), ('INPLACE_AND', 77), ('INPLACE_XOR', 78),
    ('INPLACE_OR', 79), ('LIST_TO_TUPLE', 82), ('RETURN_VALUE', 83), ('IMPORT_STAR', 84),
    ('SETUP_ANNOTATIONS', 85), ('YIELD_VALUE', 86), ('POP_BLOCK', 87), ('POP_EXCEPT', 89),
    ('STORE_NAME', 90), ('DELETE_NAME', 91), ('UNPACK_SEQUENCE', 92), ('FOR_ITER', 93),
    ('UNPACK_EX', 94), ('STORE_ATTR', 95), ('DELETE_ATTR', 96), ('STORE_GLOBAL', 97),
    ('DELETE_GLOBAL', 98), ('LOAD_CONST', 100), ('LOAD_NAME', 101), ('BUILD_TUPLE', 102),
    ('BUILD_LIST', 103), ('BUILD_SET', 104), ('BUILD_MAP', 105), ('LOAD_ATTR', 106),
    ('COMPARE_OP', 107), ('IMPORT_NAME', 108), ('IMPORT_FROM', 109), ('JUMP_FORWARD', 110),
    ('JUMP_IF_FALSE_OR_POP', 111), ('JUMP_IF_TRUE_OR_POP', 112), ('JUMP_ABSOLUTE', 113),
    ('POP_JUMP_IF_FALSE', 114), ('POP_JUMP_IF_TRUE', 115), ('LOAD_GLOBAL', 116),
    ('SETUP_FINALLY', 122), ('LOAD_FAST', 124), ('STORE_FAST', 125), ('DELETE_FAST', 126),
    ('RAISE_VARARGS', 130), ('CALL_FUNCTION', 131), ('MAKE_FUNCTION', 132),
    ('BUILD_SLICE', 133), ('LOAD_CLOSURE', 135), ('LOAD_DEREF', 136), ('STORE_DEREF', 137),
    ('DELETE_DEREF', 138), ('CALL_FUNCTION_KW', 141), ('CALL_FUNCTION_EX', 142),
    ('SETUP_WITH', 143), ('EXTENDED_ARG', 144), ('LIST_APPEND', 145), ('SET_ADD', 146),
    ('MAP_ADD', 147), ('LOAD_CLASSDEREF', 148), ('BUILD_LIST_UNPACK', 149),
    ('BUILD_MAP_UNPACK', 150), ('BUILD_MAP_UNPACK_WITH_CALL', 151),
    ('BUILD_TUPLE_UNPACK', 152), ('BUILD_SET_UNPACK', 153), ('SETUP_ASYNC_WITH', 154),
    ('FORMAT_VALUE', 155), ('BUILD_CONST_KEY_MAP', 156), ('BUILD_STRING', 157),
    ('BUILD_TUPLE_UNPACK_WITH_CALL', 158), ('LOAD_METHOD', 160), ('CALL_METHOD', 161),
    ('CALL_FINALLY', 162), ('POP_FINALLY', 163),
]:
    _d(_n, _o)

HAVE_ARG = 90
JREL = {93, 110, 122, 143, 154}          # 相对跳转
JABS = {111, 112, 113, 114, 115, 119}    # 绝对跳转
CMP = ['<', '<=', '==', '!=', '>', '>=', 'in', 'not in', 'is', 'is not', 'EXC_MATCH', 'BAD']


def dis(code, indent=0):
    """把 code.co_code 线性反汇编成文本行"""
    pad = '    ' * indent
    lines = []
    co = code.code
    i = 0
    # 先把 EXTENDED_ARG 合进来，保证跳转目标统一按"指令起点"处理
    raw = []
    while i < len(co):
        op = co[i]
        start = i
        if op >= HAVE_ARG:
            arg = co[i + 1]
            i += 2
            # 处理 EXTENDED_ARG 链
            if op == 144:
                ext = arg
                while i < len(co) and co[i] == 144:
                    ext = (ext << 8) | co[i + 1]
                    i += 2
                op2 = co[i] if i < len(co) else 0
                arg2 = co[i + 1] if i + 1 < len(co) else 0
                i += 2
                raw.append((start, op, ext, '%s %d  (EXTENDED_ARG prefix)' % (opname[op], ext)))
                raw.append((start + 2, op2, arg2, None))
                continue
            raw.append((start, op, arg, None))
        else:
            arg = None
            i += 1
            raw.append((start, op, None, None))
    offs = [r[0] for r in raw]
    off2idx = {o: k for k, o in enumerate(offs)}

    for start, op, arg, force in raw:
        name = opname[op]
        extra = ''
        if arg is not None:
            if op in (100,):
                extra = '   ; %r' % (code.consts[arg],)
            elif op in (90, 101, 106, 108, 109, 116, 95, 96, 97, 98, 91):
                try:
                    extra = '   ; %s' % code.names[arg]
                except Exception:
                    extra = ''
            elif op in (124, 125, 126):
                try:
                    extra = '   ; %s' % code.varnames[arg]
                except Exception:
                    extra = ''
            elif op in (136, 137, 138, 135, 148):
                pool = list(code.cellvars) + list(code.freevars)
                try:
                    extra = '   ; %s' % pool[arg]
                except Exception:
                    extra = ''
            elif op == 107:
                extra = '   ; %s' % (CMP[arg] if arg < len(CMP) else arg)
            elif op in JREL:
                extra = '   ; -> %d' % (start + 2 + arg)
            elif op in JABS:
                extra = '   ; -> %d' % arg
        s = '%s%4d  %-24s %s%s' % (pad, start, name, '' if arg is None else arg, extra)
        if force:
            s = '%s%4d  %-24s %s' % (pad, start, force.split()[0], force)
        lines.append(s)
    return lines


def walk(code, indent=0):
    pad = '    ' * indent
    out = []
    out.append('%s=== code object: %s  (file=%s, firstlineno=%d) ===' %
               (pad, code.name, code.filename, code.firstlineno))
    out.append('%sargcount=%d posonly=%d kwonly=%d nlocals=%d stacksize=%d flags=0x%x' %
               (pad, code.argcount, code.posonlyargcount, code.kwonlyargcount,
                code.nlocals, code.stacksize, code.flags))
    out.append('%sconsts  = %r' % (pad, code.consts))
    out.append('%snames   = %r' % (pad, code.names))
    out.append('%svarnames= %r' % (pad, code.varnames))
    out.append('%s--- disassembly ---' % pad)
    out.extend(dis(code, indent))
    for c in code.consts:
        if isinstance(c, Code):
            out.append('')
            out.extend(walk(c, indent + 1))
    return out


def main():
    path = sys.argv[1]
    data = open(path, 'rb').read()
    magic = data[0:4]
    print('[i] file = %s  size = %d' % (path, len(data)))
    print('[i] magic = %s  (int little-endian = %d)' % (magic.hex(' '), struct.unpack('<H', magic[:2])[0]))
    print('[i] header 16 bytes: %s' % data[:16].hex(' '))
    r = Reader(data[16:])
    top = r.read_object()
    print('[OK] marshal parsed, top object = %r' % (top,))
    print()
    print('\n'.join(walk(top)))


if __name__ == '__main__':
    main()
