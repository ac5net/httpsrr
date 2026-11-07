#!/usr/bin/env python3
"""
httpsrr.py - HTTPS レコード（RFC 9460）を読み、ech（RFC 9848）の中身を RFC 9849 の構造で解く

使い方:
    ./httpsrr.py <ホスト名> [--fixtures <txt>] [--json]
    例: ./httpsrr.py ac-5.net
        ./httpsrr.py www.cybozu.com

やること:
  1. HTTPS（type 65）を DoH（dns.google）で引く。応答の CNAME を辿って最終名の HTTPS RRset を取る
  2. 各 RR の提示形式「SvcPriority TargetName SvcParams」を RFC 9460 2.1 / Appendix A の規則で解析し、
     2.2 のワイヤ形式に組み立て直す（キーの重複・mandatory の整合・値の形式は、このとき検査する）
  3. SvcPriority 0（AliasMode）なら TargetName を辿る（3 節。回数上限あり）
  4. ech があれば Base64 を外し、RFC 9849 4 節の ECHConfigList として解く
     （version / config_id / KEM / 公開鍵 / 暗号スイート / maximum_name_length / public_name / extensions）
     public_name は 6.1.7 の規則で検査する

Python 標準ライブラリだけで動きます。--fixtures を渡すとネットワークに出ません。
"""
import argparse
import base64
import ipaddress
import json
import re
import sys
import urllib.parse
import urllib.request

DOH = "https://dns.google/resolve"
TYPE_CNAME = 5
TYPE_HTTPS = 65
ALIAS_LIMIT = 4                  # RFC 9460 2.4.2: 上限は実装任せ。0 は禁止

# RFC 9460 14.3.2 ＋ RFC 9848 9（ech は 9460 では「予約」、9848 で定義）
KEYS = {"mandatory": 0, "alpn": 1, "no-default-alpn": 2, "port": 3, "ipv4hint": 4, "ech": 5, "ipv6hint": 6}
KEY_NAMES = {v: k for k, v in KEYS.items()}
AUTO_MANDATORY_HTTPS = {"port", "no-default-alpn"}   # RFC 9460 9
DEFAULT_ALPN_HTTPS = ["http/1.1"]                    # RFC 9460 9

# IANA HPKE レジストリ（2026-11-07 閲覧）から、ECH で見かける範囲
KEM = {0x0010: "DHKEM(P-256, HKDF-SHA256)", 0x0011: "DHKEM(P-384, HKDF-SHA384)", 0x0012: "DHKEM(P-521, HKDF-SHA512)",
       0x0020: "DHKEM(X25519, HKDF-SHA256)", 0x0021: "DHKEM(X448, HKDF-SHA512)",
       0x0041: "ML-KEM-768", 0x0050: "MLKEM768-P256", 0x647A: "X-Wing"}
KDF = {0x0001: "HKDF-SHA256", 0x0002: "HKDF-SHA384", 0x0003: "HKDF-SHA512"}
AEAD = {0x0001: "AES-128-GCM", 0x0002: "AES-256-GCM", 0x0003: "ChaCha20Poly1305"}
ECH_VERSION = 0xFE0D


class Malformed(ValueError):
    """RFC 9460 2.2 の意味で不正（クライアントは RRset 全体を捨てて非 SVCB 接続に戻る）"""


# ---------------------------------------------------------------- DNS 取得
def doh_https(name):
    """dns.google に HTTPS を問い合わせ、(status, ad, [(type, owner, rdata)]) を返す（CNAME も含む）"""
    url = DOH + "?" + urllib.parse.urlencode({"name": name, "type": TYPE_HTTPS})
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        j = json.load(r)
    ans = [(a["type"], a["name"].rstrip(".").lower(), a["data"]) for a in j.get("Answer", [])]
    return j.get("Status", -1), bool(j.get("AD")), ans


class FixtureLookup:
    """'名前 | Status | AD | type owner rdata || ...' 形式のテキストで応答を再生する"""

    def __init__(self, path):
        self.data, self.missing = {}, []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                name, st, ad, rest = [x.strip() for x in line.split("|", 3)]
                ans = []
                for rec in [x.strip() for x in rest.split("||") if x.strip()]:
                    t, owner, rdata = rec.split(" ", 2)
                    ans.append((int(t), owner.rstrip(".").lower(), rdata))
                self.data[name.lower()] = (int(st), ad == "1", ans)

    def __call__(self, name):
        key = name.lower().rstrip(".")
        if key not in self.data:
            self.missing.append(key)
            return 3, False, []
        return self.data[key]


# ---------------------------------------------------------------- 提示形式の解読（RFC 9460 2.1、Appendix A）
def _tokenize(rdata):
    """空白区切り。ただし二重引用符の中の空白は区切らない（Appendix A の quoted）"""
    toks, cur, inq, i = [], [], False, 0
    while i < len(rdata):
        c = rdata[i]
        if c == '"':
            inq = not inq
            cur.append(c)
        elif c == "\\" and i + 1 < len(rdata):
            cur.append(c + rdata[i + 1])
            i += 1
        elif c in " \t" and not inq:
            if cur:
                toks.append("".join(cur))
                cur = []
        else:
            cur.append(c)
        i += 1
    if inq:
        raise Malformed("二重引用符が閉じていない")
    if cur:
        toks.append("".join(cur))
    return toks


def charstring_decode(s):
    """Appendix A: 引用符を外し、\\X と \\DDD（10進3桁）を1オクテットに戻す。戻り値は bytes"""
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    out, i = bytearray(), 0
    while i < len(s):
        c = s[i]
        if c == "\\":
            if i + 1 >= len(s):
                raise Malformed("末尾に単独の \\")
            if s[i + 1].isdigit():                 # \DDD は 10 進 3 桁（Appendix A: dec-octet）
                if not (i + 3 < len(s) and s[i + 1:i + 4].isdigit()):
                    raise Malformed("10進エスケープは 3 桁必要: %r" % s[i:i + 4])
                n = int(s[i + 1:i + 4])
                if n > 255:
                    raise Malformed("10進エスケープが 255 を超える: \\%03d" % n)
                out.append(n)
                i += 4
                continue
            out.append(ord(s[i + 1]))
            i += 2
            continue
        out.append(ord(c))
        i += 1
    return bytes(out)


def comma_list_decode(value):
    """Appendix A.1: 文字列デコード後の値を "," で分割。"\\," と "\\\\" はエスケープ。空の項目は不可"""
    items, cur, i = [], bytearray(), 0
    while i < len(value):
        b = value[i]
        if b == 0x5C and i + 1 < len(value) and value[i + 1] in (0x2C, 0x5C):   # "\," or "\\"
            cur.append(value[i + 1])
            i += 2
            continue
        if b == 0x2C:                                                            # ","
            items.append(bytes(cur))
            cur = bytearray()
            i += 1
            continue
        cur.append(b)
        i += 1
    items.append(bytes(cur))
    if any(len(x) == 0 for x in items):
        raise Malformed("カンマ区切りリストに空の項目がある（A.1）")
    return items


def parse_rdata(rdata):
    """'SvcPriority TargetName SvcParams' → (priority, target, [(key, value_bytes or None), ...])"""
    toks = _tokenize(rdata.strip())
    if len(toks) < 2:
        raise Malformed("SvcPriority と TargetName が必要")
    try:
        prio = int(toks[0])
    except ValueError:
        raise Malformed("SvcPriority が整数でない: %r" % toks[0])
    if not 0 <= prio <= 65535:
        raise Malformed("SvcPriority の範囲外")
    target = toks[1]
    params = []
    for tok in toks[2:]:
        if "=" in tok:
            k, v = tok.split("=", 1)
            params.append((k, charstring_decode(v)))
        else:
            params.append((tok, None))          # 値なし（no-default-alpn など）
    return prio, target, params


# ---------------------------------------------------------------- ワイヤ形式（RFC 9460 2.2）
def name_to_wire(name):
    if name == ".":
        return b"\x00"
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("ascii")
        if not 0 < len(b) < 64:
            raise Malformed("不正なラベル: %r" % label)
        out += bytes([len(b)]) + b
    return out + b"\x00"


def key_number(name):
    if name in KEYS:
        return KEYS[name]
    m = re.fullmatch(r"key(\d+)", name)
    if m and (m.group(1) == "0" or not m.group(1).startswith("0")):
        n = int(m.group(1))
        if n <= 65535:
            return n
    raise Malformed("未知の SvcParamKey 名: %r（keyNNNNN 形式でなければワイヤ形式に変換できない）" % name)


def encode_param(key, value):
    """提示形式の値（bytes or None）→ ワイヤ形式の SvcParamValue。キーごとの検査もここで行う"""
    if key == "mandatory":
        if not value:
            raise Malformed("mandatory の値が空")
        names = [x.decode("ascii") for x in comma_list_decode(value)]
        nums = [key_number(n) for n in names]
        if 0 in nums:
            raise Malformed("mandatory 自身を mandatory に含めてはならない（8 節）")
        if len(set(nums)) != len(nums):
            raise Malformed("mandatory のリストにキーが重複")
        return b"".join(n.to_bytes(2, "big") for n in sorted(nums))
    if key == "alpn":
        if not value:
            raise Malformed("alpn の値が空")
        out = b""
        for item in comma_list_decode(value):
            if len(item) > 255:
                raise Malformed("alpn-id が 255 オクテットを超える")
            out += bytes([len(item)]) + item
        return out
    if key == "no-default-alpn":
        if value:
            raise Malformed("no-default-alpn の値は空でなければならない（7.1.1）")
        return b""
    if key == "port":
        if not value:
            raise Malformed("port の値が空")
        s = value.decode("ascii", "replace")
        if not s.isdigit() or not 0 <= int(s) <= 65535:
            raise Malformed("port は 0〜65535 の10進整数: %r" % s)
        return int(s).to_bytes(2, "big")
    if key in ("ipv4hint", "ipv6hint"):
        if not value:
            raise Malformed("%s の値が空" % key)
        out = b""
        for item in comma_list_decode(value):
            try:
                addr = ipaddress.ip_address(item.decode("ascii"))
            except ValueError:
                raise Malformed("%s に不正なアドレス: %r" % (key, item))
            if (key == "ipv4hint") != (addr.version == 4):
                raise Malformed("%s にアドレス族の違うアドレス: %s" % (key, addr))
            out += addr.packed
        return out
    if key == "ech":
        if not value:
            raise Malformed("ech の値が空")
        if b"\\" in value:
            raise Malformed("ech にエスケープは使えない（RFC 9848 3）")
        try:
            raw = base64.b64decode(value, validate=True)
        except Exception:
            raise Malformed("ech が Base64 として読めない")
        parse_echconfiglist(raw)             # 形式検査（例外はそのまま上げる）
        return raw
    # keyNNNNN: デコード済みの値をそのままワイヤ形式に（2.1）
    return value if value is not None else b""


def to_wire(prio, target, params):
    """RFC 9460 2.2。戻り値 (wire_bytes, findings)。findings は警告の列"""
    findings = []
    seen = set()
    encoded = []
    for k, v in params:
        n = key_number(k)
        if n in seen:
            raise Malformed("SvcParamKey %s が重複（2.1 / 2.2）" % k)
        seen.add(n)
        encoded.append((n, k, encode_param(KEY_NAMES.get(n, k), v)))
    names = {KEY_NAMES.get(n, k) for n, k, _ in encoded}
    if "no-default-alpn" in names and "alpn" not in names:
        raise Malformed("no-default-alpn には alpn が必要（self-consistent でない。7.1.1）")
    for n, k, w in encoded:
        if n == 0:
            for i in range(0, len(w), 2):
                m = int.from_bytes(w[i:i + 2], "big")
                if m not in seen:
                    raise Malformed("mandatory に挙げたキー %s がレコードに無い（8 節）" % KEY_NAMES.get(m, "key%d" % m))
                if KEY_NAMES.get(m) in AUTO_MANDATORY_HTTPS:
                    findings.append(("INFO", "%s は HTTPS では自動的に mandatory。列挙は無駄（8 節）" % KEY_NAMES[m]))
    if prio == 0 and params:
        findings.append(("WARN", "AliasMode なのに SvcParams がある。受信側は無視する（2.4.2）"))
    wire = prio.to_bytes(2, "big") + name_to_wire(target)
    if prio != 0:
        for n, k, w in sorted(encoded):          # ワイヤ形式はキー番号の昇順（2.2）
            wire += n.to_bytes(2, "big") + len(w).to_bytes(2, "big") + w
    return wire, findings


# ---------------------------------------------------------------- ECHConfigList（RFC 9849 4 節）
def _u8(b, i):
    if i + 1 > len(b):
        raise Malformed("ECHConfig が途中で切れている")
    return b[i], i + 1


def _u16(b, i):
    if i + 2 > len(b):
        raise Malformed("ECHConfig が途中で切れている")
    return int.from_bytes(b[i:i + 2], "big"), i + 2


def _vec(b, i, lenbytes):
    n, i = (_u8 if lenbytes == 1 else _u16)(b, i)
    if i + n > len(b):
        raise Malformed("ECHConfig の可変長フィールドが本体より長い")
    return b[i:i + n], i + n


def check_public_name(name):
    """RFC 9849 6.1.7: LDH ラベルのドット区切り。先頭末尾のドット不可、各ラベル 63 以下、
    最終ラベルが全部数字 or 0x+16進 なら無視（IPv4 と誤解されるため）。戻り値は None（OK）か理由"""
    if not name or name.startswith(".") or name.endswith("."):
        return "先頭または末尾がドット"
    labels = name.split(".")
    for lb in labels:
        if not lb or len(lb) > 63:
            return "ラベル長が不正"
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", lb):
            return "LDH ラベルでない: %r" % lb
    last = labels[-1]
    if last.isdigit() or re.fullmatch(r"0[xX][0-9A-Fa-f]*", last):
        return "最終ラベルが IPv4 リテラルと解釈され得る"
    return None


def parse_echconfiglist(raw):
    """ECHConfigList（長さプレフィックス付き）→ [config dict]。未知 version は skipped に入れる"""
    total, i = _u16(raw, 0)
    if total != len(raw) - 2:
        raise Malformed("ECHConfigList の長さプレフィックス（%d）と実体（%d）が合わない" % (total, len(raw) - 2))
    if total < 4:
        raise Malformed("ECHConfigList が短すぎる（<4..2^16-1>）")
    configs = []
    while i < len(raw):
        version, i = _u16(raw, i)
        body, i = _vec(raw, i, 2)
        if version != ECH_VERSION:
            configs.append({"version": version, "supported": False, "length": len(body)})
            continue
        j = 0
        config_id, j = _u8(body, j)
        kem_id, j = _u16(body, j)
        public_key, j = _vec(body, j, 2)
        suites_raw, j = _vec(body, j, 2)
        if len(suites_raw) < 4 or len(suites_raw) % 4:
            raise Malformed("cipher_suites の長さが 4 の倍数でない（<4..2^16-4>）")
        suites = [(int.from_bytes(suites_raw[k:k + 2], "big"), int.from_bytes(suites_raw[k + 2:k + 4], "big"))
                  for k in range(0, len(suites_raw), 4)]
        max_name_len, j = _u8(body, j)
        pn_raw, j = _vec(body, j, 1)
        if not pn_raw:
            raise Malformed("public_name が空（<1..255>）")
        ext_raw, j = _vec(body, j, 2)
        if j != len(body):
            raise Malformed("ECHConfigContents の後に余分なバイト")
        exts, k, seen_types = [], 0, set()
        while k < len(ext_raw):
            et, k = _u16(ext_raw, k)
            ed, k = _vec(ext_raw, k, 2)
            if et in seen_types:
                raise Malformed("同じ型の ECHConfig 拡張が 2 つある（4.2）")
            seen_types.add(et)
            exts.append({"type": et, "mandatory": bool(et & 0x8000), "len": len(ed)})
        public_name = pn_raw.decode("ascii", "replace")
        cfg = {"version": version, "supported": True, "config_id": config_id,
               "kem_id": kem_id, "kem": KEM.get(kem_id, "未知（クライアントは無視する）"),
               "public_key_len": len(public_key),
               "cipher_suites": [{"kdf": KDF.get(a, "0x%04x" % a), "aead": AEAD.get(b, "0x%04x" % b)} for a, b in suites],
               "maximum_name_length": max_name_len, "public_name": public_name,
               "extensions": exts, "ignore_reason": None}
        bad = check_public_name(public_name)
        if bad:
            cfg["ignore_reason"] = "public_name が不正（6.1.7）: " + bad
        elif kem_id not in KEM:
            cfg["ignore_reason"] = "未知の KEM（4 節: MUST ignore）"
        elif any(e["mandatory"] for e in exts):
            cfg["ignore_reason"] = "未対応の mandatory 拡張（4.2: MUST ignore）"
        configs.append(cfg)
    return configs


# ---------------------------------------------------------------- 解決（RFC 9460 3 節）
def resolve(name, lookup=doh_https):
    """name の HTTPS RRset を CNAME と AliasMode を辿って求める。
    戻り値: {'name', 'chain':[...], 'final', 'ad', 'records':[{...}], 'findings':[...], 'state'}"""
    out = {"name": name, "chain": [], "final": None, "ad": False, "records": [], "findings": [], "state": None}
    qname = name.lower().rstrip(".")
    for hop in range(ALIAS_LIMIT + 1):
        st, ad, ans = lookup(qname)
        out["ad"] = out["ad"] or ad
        if st not in (0, 3):
            raise RuntimeError("DNS 応答が異常: status=%d" % st)
        # CNAME を辿る（2.3: 各 RR は自分の所有者名で返る）
        cur = qname
        cnames = {o: d.rstrip(".").lower() for t, o, d in ans if t == TYPE_CNAME}
        seen = set()
        while cur in cnames and cur not in seen:
            seen.add(cur)
            out["chain"].append(("CNAME", cur, cnames[cur]))
            cur = cnames[cur]
        rrs = [d for t, o, d in ans if t == TYPE_HTTPS and o == cur]
        out["final"] = cur
        if not rrs:
            out["state"] = "none" if st == 0 else "nxdomain"
            out["findings"].append(("INFO", "%s に HTTPS レコード無し（status=%d）。通常の A/AAAA 接続" % (cur, st)))
            return out
        parsed = []
        try:
            for rd in rrs:
                prio, target, params = parse_rdata(rd)
                wire, fnd = to_wire(prio, target, params)
                out["findings"] += fnd
                parsed.append({"owner": cur, "rdata": rd, "priority": prio, "target": target,
                               "params": params, "wire_hex": wire.hex()})
        except Malformed as e:
            out["state"] = "malformed"
            out["findings"].append(("ERROR", "RRset が不正: %s。RRset 全体を捨てて非 SVCB 接続に戻る（2.2）" % e))
            return out
        aliases = [p for p in parsed if p["priority"] == 0]
        if aliases:
            if len(aliases) > 1:
                out["findings"].append(("WARN", "AliasMode が複数ある。1 つを無作為に選ぶ（2.4.2）"))
            if len(parsed) > len(aliases):
                out["findings"].append(("WARN", "AliasMode と ServiceMode が混在。ServiceMode は無視（2.4.1）"))
            if aliases[0]["target"] == ".":          # rstrip(".") の前に見る。"." は rstrip で空になる
                tgt = "."
            else:
                tgt = aliases[0]["target"].rstrip(".").lower()
            if tgt == ".":
                out["state"] = "alias-dot"
                out["findings"].append(("INFO", "AliasMode の TargetName が「.」= サービス無しの表明（2.5.1）"))
                return out
            out["chain"].append(("HTTPS 0", cur, tgt))
            qname = tgt
            continue
        # ServiceMode
        for p in parsed:
            p["effective_target"] = cur if p["target"] == "." else p["target"].rstrip(".").lower()
            d = {k: v for k, v in p["params"]}
            names = [k for k, _ in p["params"]]
            alpn = [x.decode("ascii", "replace") for x in comma_list_decode(d["alpn"])] if "alpn" in d else []
            p["alpn_set"] = alpn + ([] if "no-default-alpn" in names else DEFAULT_ALPN_HTTPS)
            p["ech"] = None
            if "ech" in d:
                p["ech"] = parse_echconfiglist(base64.b64decode(d["ech"]))
                usable = [c for c in p["ech"] if c.get("supported") and not c.get("ignore_reason")]
                if not usable:
                    out["findings"].append(("WARN", "ech はあるが使える ECHConfig が無い"))
            if p["target"] == "." and ("ipv4hint" in d or "ipv6hint" in d):
                out["findings"].append(("INFO", "TargetName が「.」なのに IP ヒントがある。性能上の利点は無く SHOULD NOT（7.3）"))
        parsed.sort(key=lambda p: p["priority"])
        out["records"] = parsed
        out["state"] = "service"
        return out
    out["state"] = "alias-limit"
    out["findings"].append(("WARN", "AliasMode の連鎖が上限 %d を超えた。元の名前で接続（3.1）" % ALIAS_LIMIT))
    return out


def fmt(r):
    L = ["対象      : %s%s" % (r["name"], "（DNSSEC AD）" if r["ad"] else "")]
    for kind, a, b in r["chain"]:
        L.append("  %-7s %s → %s" % (kind, a, b))
    if r["state"] in ("none", "nxdomain"):
        L.append("HTTPS     : なし（%s）" % r["final"])
    elif r["state"] == "service":
        for p in r["records"]:
            L.append("HTTPS     : %s" % p["rdata"])
            L.append("  優先度 %d / 接続先 %s / ALPN %s" % (p["priority"], p["effective_target"], ",".join(p["alpn_set"])))
            if p["ech"]:
                for c in p["ech"]:
                    if not c["supported"]:
                        L.append("  ech: version 0x%04x は未対応。読み飛ばす" % c["version"])
                        continue
                    L.append("  ech: config_id=%d KEM=%s 公開鍵 %dB スイート %s max_name_len=%d public_name=%s%s" % (
                        c["config_id"], c["kem"], c["public_key_len"],
                        "/".join("%s+%s" % (s["kdf"], s["aead"]) for s in c["cipher_suites"]),
                        c["maximum_name_length"], c["public_name"],
                        ("  [無視: %s]" % c["ignore_reason"]) if c["ignore_reason"] else ""))
    else:
        L.append("状態      : %s" % r["state"])
    for lv, m in r["findings"]:
        L.append("  [%s] %s" % (lv, m))
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name")
    ap.add_argument("--fixtures", help="テキスト形式の DNS 応答で動く（ネットワークに出ない）")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    lookup = FixtureLookup(a.fixtures) if a.fixtures else doh_https
    r = resolve(a.name, lookup)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2, default=lambda o: o.hex() if isinstance(o, bytes) else str(o)))
    else:
        print(fmt(r))
    return 1 if any(lv == "ERROR" for lv, _ in r["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
