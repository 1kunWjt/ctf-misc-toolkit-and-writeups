# -*- coding: utf-8 -*-
"""14-ds-encode 数据恢复（v2）
用「trailer 签名 80|uid(3B)|00 00 00 00」定位每条记录的尾锚点，
再按 cryptoType 逐个字段解码，最后按 PDF 规范脱落敏输出 CSV。
"""
import struct, base64, re, hashlib, csv, os, collections

ROOT = r"C:\Users\XiaoMibook\Documents\deepseek-harness\default-workspace\CTF-WP\14-ds-encode\files\tempdir\DS附件\ds-encode附件_unzip\ds-data_unzip\ds-data\person"
IBD = os.path.join(ROOT, "data.ibd")
OUT = r"D:\XiaoMibook\CTF学习\.wp_scratch\14\out"
PS = 16384
CT = ('Base85', 'Base32', 'Base64')
CJK = re.compile(r'^[\u4e00-\u9fa5]{2,5}$')

b = open(IBD, 'rb').read()

def leaves():
    for i in range(len(b) // PS):
        o = i * PS
        if struct.unpack('>H', b[o + 24:o + 26])[0] == 17855 and struct.unpack('>H', b[o + 64:o + 66])[0] == 0:
            yield i

def enc_len(kind, n):
    if kind == 'Base32':
        return 8 * ((n + 4) // 5)
    if kind == 'Base64':
        return 4 * ((n + 2) // 3)
    full, rem = divmod(n, 4)          # Base85
    return full * 5 + (0 if rem == 0 else rem + 1)

def dec(kind, s):
    if kind == 'Base32':
        return base64.b32decode(s + b'=' * (-len(s) % 8))
    if kind == 'Base64':
        return base64.b64decode(s + b'=' * (-len(s) % 4))
    return base64.b85decode(s)

def try_split(kind, blob):
    """枚举 username/password/name 的字节长度，用结构约束定界"""
    L = len(blob)
    out = []
    for nl in range(4, 33):
        for pl in range(0, 33):
            if enc_len(kind, nl) + enc_len(kind, pl) + enc_len(kind, 18) + enc_len(kind, 11) > L:
                continue
            for ml in range(6, 19):
                if (enc_len(kind, nl) + enc_len(kind, pl) + enc_len(kind, ml)
                        + enc_len(kind, 18) + enc_len(kind, 11)) != L:
                    continue
                try:
                    lens = (nl, pl, ml, 18, 11)
                    o, parts = 0, []
                    for n in lens:
                        k = enc_len(kind, n)
                        parts.append(dec(kind, blob[o:o + k])); o += k
                except Exception:
                    continue
                if [len(p) for p in parts] != list(lens):
                    continue
                if not re.fullmatch(rb'[0-9]{18}', parts[3]) or not re.fullmatch(rb'[0-9]{11}', parts[4]):
                    continue
                try:
                    nm = parts[2].decode('utf-8')
                except Exception:
                    continue
                if not CJK.match(nm):
                    continue
                if not re.fullmatch(rb'[\x21-\x7e]+', parts[0]) or not re.fullmatch(rb'[\x21-\x7e]*', parts[1]):
                    continue
                out.append(parts)
    out.sort(key=lambda p: (0 if len(p[1]) > 0 else 1, 0 if len(p[0]) >= len(p[1]) else 1, -len(p[0])))
    return out

rows, fail, stat = [], [], collections.Counter()
for pno in leaves():
    pg = b[pno * PS:(pno + 1) * PS]
    ht = struct.unpack('>H', pg[40:42])[0]
    anchors = []
    for m in re.finditer(rb'\x80[\x00-\xff]{3}\x00\x00\x00\x00', pg):
        uid = (struct.unpack('>I', m.group()[:4])[0] & 0x7FFFFFFF) - 1
        if 1 <= uid <= 6000:
            anchors.append((m.start(), m.end(), uid))
    for k, (a0, a1, uid) in enumerate(anchors):
        lo = anchors[k - 1][1] if k else 0x79
        if a0 <= lo:
            continue
        seg = pg[lo:a0]
        # 记录体以 7 字节 trx 标记 + 2 字节前缀开头
        pos_ct, ct = -1, None
        for t in CT:
            p = seg.rfind(t.encode())
            if p > pos_ct:
                pos_ct, ct = p, t
        mk = seg.rfind(b'\x07\x1a\xb3\x00\x00\x01\x27')
        body0 = mk + 9 if mk >= 0 else 9
        if ct:
            blob = seg[body0:pos_ct]
        else:
            m2 = None
            for m2 in re.finditer(rb'(?=(\d{29}))', seg):
                pass
            if not m2:
                fail.append((pno, uid, 'no-anchor', seg)); stat['失败'] += 1; continue
            blob = seg[body0:m2.start() + 29]
            ct = 'Plain'
        stat[ct] += 1
        if ct == 'Plain':
            m3 = re.fullmatch(rb'(.*?)((?:[\xe4-\xe9][\x80-\xbf]{2}){2,5})(\d{18})(\d{11})', blob, re.S)
            if not m3:
                fail.append((pno, uid, 'plain-shape', blob)); stat['失败'] += 1; continue
            fields, multi = [m3.group(1), b'', m3.group(2), m3.group(3), m3.group(4)], 1
        else:
            c = try_split(ct, blob)
            if not c:
                fail.append((pno, uid, 'split', blob)); stat['失败'] += 1; continue
            fields, multi = c[0], len(c)
        rows.append(dict(uid=uid, ct=ct, f=fields, multi=multi, pno=pno))

print("[leaf pages] %d" % len(list(leaves())))
print("[定位到记录] %d，解析成功 %d，失败 %d" % (sum(stat.values()), len(rows), len(fail)))
print("[cryptoType] %s" % dict(stat))

uniq = {}
for r in rows:
    old = uniq.get(r['uid'])
    if old is None or r['multi'] < old['multi']:
        uniq[r['uid']] = r
rows = sorted(uniq.values(), key=lambda x: x['uid'])
uids = [r['uid'] for r in rows]
print("[去重后] %d 行，uid %d..%d" % (len(rows), uids[0], uids[-1]))
print("[多解未定的行] %d" % sum(1 for r in rows if r['multi'] > 1))
print("[失败样例]", [(p, u, why, bytes(x)[:40]) for p, u, why, x in fail[:3]])

EXP = {1: ('l*******1', '113db74aa2c3e35237504cba47cfe456', '795814cfe5ea891f8f88e5985e10c49d418571b3', '******1988********', '731****7567'),
       2: ('L*********************3', '48263511e31e0ed52038355d8076bd34', '4ce1fdf190c184d11dfd0f1310550aef0790a1e7', '******1999********', '740****0653'),
       3: ('w****y', '8f526c76fab044a623c332222b4b8465', '2531f13ceee0f2814fbee7f3d2bfafa21bc71b99', '******1995********', '786****4222')}

def m_user(u):
    s = u.decode('utf-8', 'replace')
    if len(s) <= 1: return s
    if len(s) == 2: return s[0] + '*'
    return s[0] + '*' * (len(s) - 2) + s[-1]
m_id = lambda i: '******' + i.decode()[6:10] + '********'
m_ph = lambda p: p.decode()[:3] + '****' + p.decode()[7:]

byuid = {r['uid']: r for r in rows}
print("\n==== 用 PDF 的 userid 1/2/3 期望值验收 ====")
allok = True
for uid in (1, 2, 3):
    r = byuid.get(uid)
    if not r:
        print("  uid=%d 未取到" % uid); allok = False; continue
    u, pw, nm, idc, ph = r['f']
    got = (m_user(u), hashlib.md5(pw).hexdigest(), hashlib.sha1(nm).hexdigest(), m_id(idc), m_ph(ph))
    okv = [g == e for g, e in zip(got, EXP[uid])]
    allok &= all(okv)
    print("  uid=%d ct=%-7s 5 项比对 %s" % (uid, r['ct'], ''.join('✓' if x else '✗' for x in okv)))
    if not all(okv):
        for g, e, n in zip(got, EXP[uid], ('username', 'password', 'name', 'idcard', 'phone')):
            if g != e:
                print("     %-8s got=%s exp=%s" % (n, g, e))
print("[总体]", "PDF 三行全部复现" if allok else "仍有不一致")

os.makedirs(OUT, exist_ok=True)
csv_path = os.path.join(OUT, 'result.csv')
with open(csv_path, 'w', encoding='utf-8', newline='') as fh:
    w = csv.writer(fh)
    w.writerow(['userid', 'username', 'password', 'name', 'idcard', 'phone'])
    for r in rows:
        u, pw, nm, idc, ph = r['f']
        w.writerow([r['uid'], m_user(u), hashlib.md5(pw).hexdigest(),
                    hashlib.sha1(nm).hexdigest(), m_id(idc), m_ph(ph)])
print("\n[out] %s rows=%d" % (csv_path, len(rows)))


