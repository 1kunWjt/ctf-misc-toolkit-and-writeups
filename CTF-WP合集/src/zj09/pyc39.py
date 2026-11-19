# -*- coding: utf-8 -*-
"""
pyc39.py —— 最小 Python 3.9 marshal 读取器 + 反汇编器（无第三方依赖）

为什么需要它：
    第 09 题 ezRe 是 Python 3.9 的 .pyc（magic 61 0d 0d 0a = 3425）。
    本机 Python 是 3.12，`marshal.loads` 读不了 3.9 的 code object（字节码/结构都变了），
    所以只能按 CPython 3.9 的 marshal.c 自己解析。

关键坑（上一个版本的 bug）：
    marshal 里带 FLAG_REF(0x80) 的对象会登记到"引用表"，之后用 TYPE_REF('r') 回指。
    登记必须发生在**读内容之前**（pre-order 预留槽位），因为容器内部可能引用自己。
    顺序错了 → 索引整体偏移 → IndexError。
"""
import struct
import sys

# ---------------------------------------------------------------- 基础类型
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
TYPE_LIST = ord('[')
TYPE_DICT = ord('{')
TYPE_CODE = ord('c')
TYPE_UNICODE = ord('u')
TYPE_UNKNOWN = ord('?')
TYPE_SET = ord('<')
TYPE_FROZENSET = ord('>')
TYPE_ASCII = ord('a')
TYPE_ASCII_INTERNED = ord('A')
TYPE_SMALL_TUPLE = ord(')')
TYPE_SHORT_ASCII = ord('z')
TYPE_SHORT_ASCII_INTERNED = ord('Z')
TYPE_STRINGREF = ord('R')
FLAG_REF = 0x80


class Code:
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
        return '<code %s args=%d>' % (self.name, self.argcount)


class Reader:
    def __init__(self, data):
        self.d = data
        self.i = 0
        self.refs = []
        self._strings = []

    def byte(self):
        b = self.d[self.i]
        self.i += 1
        return b

    def read(self, n):
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def i32(self):
        v = struct.unpack('<i', self.read(4))[0]
        return v

    def i64(self):
        v = struct.unpack('<q', self.read(8))[0]
        return v

    def object(self):
        b = self.byte()
        flag = b & FLAG_REF
        t = b & 0x7F
        slot = None
        if flag:
            slot = len(self.refs)
            self.refs.append(None)          # ★ pre-order 预留
        obj = self._read(t)
        if flag:
            self.refs[slot] = obj
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
        if t == TYPE_LONG:
            n = self.i32()
            sign = -1 if n < 0 else 1
            n = abs(n)
            val = 0
            for k in range(n):
                val |= struct.unpack('<H', self.read(2))[0] << (15 * k)
            return sign * val
        if t in (TYPE_FLOAT, TYPE_BINARY_FLOAT):
            if t == TYPE_BINARY_FLOAT:
                return struct.unpack('<d', self.read(8))[0]
            return float(self.read(self.byte()).decode())
        if t == TYPE_COMPLEX or t == TYPE_BINARY_COMPLEX:
            if t == TYPE_BINARY_COMPLEX:
                return complex(struct.unpack('<d', self.read(8))[0], struct.unpack('<d', self.read(8))[0])
            return complex(self.read(self.byte()).decode())
        if t in (TYPE_STRING, TYPE_INTERNED):
            n = self.i32()
            return self.read(n)
        if t == TYPE_STRINGREF:
            return self._strings[self.i32()]
        if t == TYPE_UNICODE:
            n = self.i32()
            return self.read(n).decode('utf-8', 'replace')
        if t in (TYPE_ASCII, TYPE_ASCII_INTERNED):
            n = self.i32()
            s = self.read(n).decode('latin-1')
            if t == TYPE_ASCII_INTERNED and not any(x is s for x in self._strings):
                self._strings.append(s)
            return s
        if t in (TYPE_SHORT_ASCII, TYPE_SHORT_ASCII_INTERNED):
            n = self.byte()
            s = self.read(n).decode('latin-1')
            if t == TYPE_SHORT_ASCII_INTERNED and not any(x is s for x in self._strings):
                self._strings.append(s)
            return s
        if t == TYPE_REF:
            return self.refs[self.i32()]
        if t == TYPE_TUPLE or t == TYPE_SMALL_TUPLE:
            n = self.i32() if t == TYPE_TUPLE else self.byte()
            return tuple(self.object() for _ in range(n))
        if t == TYPE_LIST:
            n = self.i32()
            return [self.object() for _ in range(n)]
        if t == TYPE_DICT:
            out = {}
            while True:
                k = self.object()
                if k is None and self.d[self.i - 1] == TYPE_NULL:
                    break
                out[k] = self.object()
            return out
        if t == TYPE_SET or t == TYPE_FROZENSET:
            n = self.i32()
            s = {self.object() for _ in range(n)}
            return s if t == TYPE_SET else frozenset(s)
        if t == TYPE_CODE:
            c = Code()
            c.argcount = self.i32()
            c.posonlyargcount = self.i32()
            c.kwonlyargcount = self.i32()
            c.nlocals = self.i32()
            c.stacksize = self.i32()
            c.flags = self.i32()
            c.code = self.object()
            c.consts = self.object()
            c.names = self.object()
            c.varnames = self.object()
            c.freevars = self.object()
            c.cellvars = self.object()
            c.filename = self.object()
            c.name = self.object()
            c.firstlineno = self.i32()
            c.lnotab = self.object()
            return c
        raise ValueError('unknown marshal type 0x%02x at %d' % (t, self.i - 1))


# ---------------------------------------------------------------- 3.9 反汇编
OP = {
    1: 'POP_TOP', 2: 'ROT_TWO', 3: 'ROT_THREE', 4: 'DUP_TOP', 5: 'DUP_TOP_TWO',
    6: 'ROT_FOUR', 9: 'NOP', 10: 'UNARY_POSITIVE', 11: 'UNARY_NEGATIVE',
    12: 'UNARY_NOT', 15: 'UNARY_INVERT', 16: 'BINARY_MATRIX_MULTIPLY',
    17: 'INPLACE_MATRIX_MULTIPLY', 19: 'BINARY_POWER', 20: 'BINARY_MULTIPLY',
    22: 'BINARY_MODULO', 23: 'BINARY_ADD', 24: 'BINARY_SUBTRACT',
    25: 'BINARY_SUBSCR', 26: 'BINARY_FLOOR_DIVIDE', 27: 'BINARY_TRUE_DIVIDE',
    28: 'INPLACE_FLOOR_DIVIDE', 29: 'INPLACE_TRUE_DIVIDE', 50: 'GET_AITER',
    51: 'GET_ANEXT', 52: 'BEFORE_ASYNC_WITH', 53: 'BEGIN_FINALLY',
    54: 'END_ASYNC_FOR', 55: 'INPLACE_ADD', 56: 'INPLACE_SUBTRACT',
    57: 'INPLACE_MULTIPLY', 59: 'INPLACE_MODULO', 60: 'STORE_SUBSCR',
    61: 'DELETE_SUBSCR', 62: 'BINARY_LSHIFT', 63: 'BINARY_RSHIFT',
    64: 'BINARY_AND', 65: 'BINARY_XOR', 66: 'BINARY_OR', 67: 'INPLACE_POWER',
    68: 'GET_ITER', 69: 'GET_YIELD_FROM_ITER', 70: 'PRINT_EXPR',
    71: 'LOAD_BUILD_CLASS', 72: 'YIELD_FROM', 73: 'GET_AWAITABLE',
    75: 'INPLACE_LSHIFT', 76: 'INPLACE_RSHIFT', 77: 'INPLACE_AND',
    78: 'INPLACE_XOR', 79: 'INPLACE_OR', 81: 'WITH_CLEANUP_START',
    82: 'WITH_CLEANUP_FINISH', 83: 'RETURN_VALUE', 84: 'IMPORT_STAR',
    85: 'SETUP_ANNOTATIONS', 86: 'YIELD_VALUE', 87: 'POP_BLOCK',
    88: 'END_FINALLY', 89: 'POP_EXCEPT', 90: 'STORE_NAME', 91: 'DELETE_NAME',
    92: 'UNPACK_SEQUENCE', 93: 'FOR_ITER', 94: 'UNPACK_EX', 95: 'STORE_ATTR',
    96: 'DELETE_ATTR', 97: 'STORE_GLOBAL', 98: 'DELETE_GLOBAL',
    100: 'LOAD_CONST', 101: 'LOAD_NAME', 102: 'BUILD_TUPLE', 103: 'BUILD_LIST',
    104: 'BUILD_SET', 105: 'BUILD_MAP', 106: 'LOAD_ATTR', 107: 'COMPARE_OP',
    108: 'IMPORT_NAME', 109: 'IMPORT_FROM', 110: 'JUMP_FORWARD',
    111: 'JUMP_IF_FALSE_OR_POP', 112: 'JUMP_IF_TRUE_OR_POP', 113: 'JUMP_ABSOLUTE',
    114: 'POP_JUMP_IF_FALSE', 115: 'POP_JUMP_IF_TRUE', 116: 'LOAD_GLOBAL',
    120: 'SETUP_FINALLY', 124: 'LOAD_FAST', 125: 'STORE_FAST', 126: 'DELETE_FAST',
    130: 'RAISE_VARARGS', 131: 'CALL_FUNCTION', 132: 'MAKE_FUNCTION',
    133: 'BUILD_SLICE', 135: 'LOAD_CLOSURE', 136: 'LOAD_DEREF',
    137: 'STORE_DEREF', 138: 'DELETE_DEREF', 141: 'CALL_FUNCTION_KW',
    142: 'CALL_FUNCTION_EX', 143: 'SETUP_WITH', 144: 'EXTENDED_ARG',
    145: 'LIST_APPEND', 146: 'SET_ADD', 147: 'MAP_ADD', 148: 'LOAD_CLASSDEREF',
    154: 'SETUP_ASYNC_WITH', 155: 'FORMAT_VALUE', 156: 'BUILD_CONST_KEY_MAP',
    157: 'BUILD_STRING', 160: 'LOAD_METHOD', 161: 'CALL_METHOD',
    162: 'LIST_EXTEND', 163: 'SET_UPDATE', 164: 'DICT_MERGE', 165: 'DICT_UPDATE',
}
NOARG = {1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 15, 16, 17, 19, 20, 22, 23, 24, 25, 26,
         27, 28, 29, 50, 51, 52, 54, 55, 56, 57, 59, 60, 61, 62, 63, 64, 65, 66,
         67, 68, 69, 70, 71, 72, 73, 75, 76, 77, 78, 79, 81, 82, 83, 84, 85, 86,
         87, 88, 89}
# 注意：130 RAISE_VARARGS / 133 BUILD_SLICE / 162-165 是**带参数**的，别放进来
NAMES = {90: 'names', 91: 'names', 95: 'names', 96: 'names', 97: 'names',
         98: 'names', 101: 'names', 106: 'names', 108: 'names', 109: 'names',
         116: 'names', 160: 'names', 125: 'varnames', 124: 'varnames',
         126: 'varnames', 136: 'cellvars', 137: 'cellvars', 135: 'cellvars'}
JUMPS = {110, 111, 112, 113, 114, 115, 93}


def dis(code, out=None, header=True):
    lines = []
    if header:
        lines.append('== code %r  file=%r  firstlineno=%d  locals=%r'
                     % (code.name, code.filename, code.firstlineno, code.varnames))
    b = code.code
    i = 0
    ext = 0
    while i < len(b):
        off = i
        op = b[i]
        i += 1
        if op == 144:  # EXTENDED_ARG
            ext = (ext | b[i]) << 8
            i += 1
            continue
        name = OP.get(op, 'OP_%d' % op)
        arg = None
        if op not in NOARG:
            arg = ext | b[i]
            i += 1
        ext = 0
        extra = ''
        if op in NAMES and arg is not None:
            seq = getattr(code, NAMES[op])
            if arg < len(seq):
                extra = '  (%s)' % seq[arg]
            else:
                extra = '  (<%s[%d] 越界>)' % (NAMES[op], arg)
        elif op == 100 and arg is not None:
            extra = '  (%r)' % (code.consts[arg],)
        elif op == 107 and arg is not None:
            extra = '  (%s)' % COMPARE.get(arg, arg)
        elif op in (131,) and arg is not None:
            extra = '  (npos=%d, nkw=%d)' % (arg & 0xFF, arg >> 8)
        lines.append('%5d  %-24s %5s%s' % (off, name, '' if arg is None else arg, extra))
    if out is not None:
        out.extend(lines)
    return '\n'.join(lines)


COMPARE = {0: '<', 1: '<=', 2: '==', 3: '!=', 4: '>', 5: '>=', 6: 'in',
           7: 'not in', 8: 'is', 9: 'is not', 10: 'exception match', 11: 'BAD'}


def parse_file(path):
    data = open(path, 'rb').read()
    magic = struct.unpack('<H', data[:2])[0]
    r = Reader(data)
    r.i = 16  # 跳过 4 字节 magic + 4 字节 flags + 4 字节 mtime + 4 字节 size
    return magic, r.object()


def dump(code, ind=0, out=None):
    buf = []
    dis(code, buf)
    print('\n'.join(buf))
    for c in code.consts:
        if isinstance(c, Code):
            print('%s  --- 内层 code ---' % ' ' * ind)
            dump(c, ind + 2)


if __name__ == '__main__':
    magic, top = parse_file(sys.argv[1])
    print('magic =', hex(magic), '(3425 = Python 3.9)')
    dump(top)
