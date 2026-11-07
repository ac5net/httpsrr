#!/usr/bin/env python3
"""httpsrr.py のオフラインテスト。RFC 9460 Appendix D のテストベクタ、RFC 9848 Figure 1、
RFC 9849 の規則、実データ 36 ドメインを固定する。"""
import base64
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import httpsrr as h  # noqa: E402

N = 0


def ok(cond, msg):
    global N
    N += 1
    if not cond:
        raise AssertionError("#%d %s" % (N, msg))


def wire(rdata):
    prio, target, params = h.parse_rdata(rdata)
    return h.to_wire(prio, target, params)[0]


def malformed(rdata):
    try:
        wire(rdata)
    except h.Malformed:
        return True
    return False


# ---- RFC 9460 Appendix D.1 / D.2: 提示形式 → ワイヤ形式 ----------------------
ok(wire("0 foo.example.com.").hex() == "0000" "03666f6f076578616d706c6503636f6d00", "Fig.2 AliasMode")
ok(wire("1 .").hex() == "000100", "Fig.3 TargetName が「.」はルートラベル 1 オクテット")
ok(wire("16 foo.example.com. port=53").hex() == "0010" "03666f6f076578616d706c6503636f6d00" "0003" "0002" "0035", "Fig.4 port")
ok(wire("1 foo.example.com. key667=hello").hex() == "0001" "03666f6f076578616d706c6503636f6d00" "029b" "0005" "68656c6c6f", "Fig.5 keyNNNNN と引用符なしの値")
ok(wire('1 foo.example.com. key667="hello\\210qoo"').hex() == "0001" "03666f6f076578616d706c6503636f6d00" "029b" "0009" "68656c6c6fd2716f6f",
   "Fig.6 引用符付きの値と 10 進エスケープ（\\210 → 0xd2）")
ok(wire('1 foo.example.com. ipv6hint="2001:db8::1,2001:db8::53:1"').hex() ==
   "0001" "03666f6f076578616d706c6503636f6d00" "0006" "0020" "20010db8000000000000000000000001" "20010db8000000000000000000530001",
   "Fig.7 引用符付きの IPv6 ヒント 2 つ")
ok(wire('1 example.com. ipv6hint="2001:db8:122:344::192.0.2.33"').hex() ==
   "0001" "076578616d706c6503636f6d00" "0006" "0010" "20010db801220344 00000000c0000221".replace(" ", ""),
   "Fig.8 IPv4 埋め込み表記の IPv6 ヒント")
ok(wire("16 foo.example.org. alpn=h2,h3-19 mandatory=ipv4hint,alpn ipv4hint=192.0.2.1").hex() ==
   "0010" "03666f6f076578616d706c65036f726700" "0000" "0004" "0001" "0004" "0001" "0009" "02" "6832" "05" "68332d3139" "0004" "0004" "c0000201",
   "Fig.9 提示形式の順序は任意、ワイヤ形式はキー番号の昇順（mandatory の値も昇順）")
fig10 = "0010" "03666f6f076578616d706c65036f726700" "0001" "000c" "08" "665c6f6f2c626172" "02" "6832"
ok(wire('16 foo.example.org. alpn="f\\\\\\\\oo\\\\,bar,h2"').hex() == fig10, "Fig.10 引用符版：alpn-id に \\ と , を含む")
ok(wire('16 foo.example.org. alpn=f\\\\\\092oo\\092,bar,h2').hex() == fig10, "Fig.10 エスケープ版：同じワイヤ形式になる")

# ---- RFC 9460 Appendix D.3: 不正なレコード ------------------------------------
ok(malformed("1 foo.example.com. key123=abc key123=def"), "Fig.11 同じキーが 2 回")
for k in ("mandatory", "alpn", "port", "ipv4hint", "ipv6hint"):
    ok(malformed("1 foo.example.com. %s" % k), "Fig.12 %s の値は空であってはならない" % k)
ok(malformed("1 foo.example.com. no-default-alpn=abc"), "Fig.13 no-default-alpn の値は空でなければならない")
ok(malformed("1 foo.example.com. mandatory=key123"), "Fig.14 mandatory に挙げたキーが無い")
ok(malformed("1 foo.example.com. mandatory=mandatory"), "Fig.15 mandatory 自身を列挙してはならない")
ok(malformed("1 foo.example.com. mandatory=key123,key123 key123=abc"), "Fig.16 mandatory のリストに重複")
ok(malformed("1 foo.example.com. no-default-alpn"), "7.1.1 no-default-alpn には alpn が要る（self-consistent）")
ok(malformed("1 foo.example.com. port=65536"), "7.2 port の範囲外")
ok(malformed("1 foo.example.com. ipv4hint=2001:db8::1"), "7.3 ipv4hint に IPv6 アドレス")
ok(malformed("1 foo.example.com. ipv4hint=192.0.2.1,,192.0.2.2"), "A.1 空の項目は不可")
ok(malformed("1 foo.example.com. foo=bar"), "未知の名前付きキーはワイヤ形式に変換できない（keyNNNNN で書く）")
ok(malformed("1 foo.example.com. key01=x"), "keyNNNNN の先頭ゼロは不可")

# ---- Appendix A: 文字列デコードとカンマ区切り ------------------------------------
ok(h.charstring_decode('"part1,part2,part3\\\\,part4\\\\\\\\"') == b"part1,part2,part3\\,part4\\\\", "A.1 の例：引用符版の文字列デコード")
ok(h.charstring_decode('part1\\,\\p\\a\\r\\t2\\044part3\\092,part4\\092\\\\') == b"part1,part2,part3\\,part4\\\\", "A.1 の例：エスケープ版も同じ値")
ok(h.comma_list_decode(b"part1,part2,part3\\,part4\\\\") == [b"part1", b"part2", b"part3,part4\\"], "A.1 の例：3 項目に分かれる")
ok(h._tokenize('1 . alpn="a b" port=1') == ["1", ".", 'alpn="a b"', "port=1"], "引用符内の空白では区切らない")
ok(malformed("1 foo.example.com. key1=a\\21x"), "落とし穴：\\ の後が数字なら 10 進 3 桁でなければならない（\\21x は不正）")
ok(h.charstring_decode("a\\046b") == b"a.b", "\\046 は '.'")

# ---- RFC 9460 の解釈（2.4 / 2.5 / 3 / 9） ------------------------------------
def static(table):
    def lookup(name):
        key = name.lower().rstrip(".")
        if key in table:
            st, ans = table[key]
            return st, False, [(t, o.lower().rstrip("."), d) for t, o, d in ans]
        return 3, False, []
    return lookup


# 2.5.2 の例：HTTPS 0 → CNAME → HTTPS 1 . port=8002。実効 TargetName は svc2.example.net
tbl = {"example.com": (0, [(65, "example.com.", "0 svc.example.net.")]),
       "svc.example.net": (0, [(5, "svc.example.net.", "svc2.example.net."), (65, "svc2.example.net.", "1 . port=8002")])}
r = h.resolve("example.com", static(tbl))
ok(r["state"] == "service" and r["records"][0]["effective_target"] == "svc2.example.net", "2.5.2 の例：AliasMode → CNAME → 「.」は最終所有者名")
ok([c[0] for c in r["chain"]] == ["HTTPS 0", "CNAME"], "連鎖の記録")
# 2.5.1: AliasMode の「.」
r = h.resolve("x.example", static({"x.example": (0, [(65, "x.example.", "0 .")])}))
ok(r["state"] == "alias-dot", "2.5.1 AliasMode の「.」はサービス無しの表明")
# 2.4.1: Alias と Service の混在は Service を無視
tbl = {"x.example": (0, [(65, "x.example.", "0 y.example."), (65, "x.example.", "1 . alpn=h2")]),
       "y.example": (0, [(65, "y.example.", "1 . alpn=h3")])}
r = h.resolve("x.example", static(tbl))
ok(r["final"] == "y.example" and any("混在" in m for _, m in r["findings"]), "2.4.1 AliasMode があれば ServiceMode は無視")
# 3.1 連鎖上限
tbl = {"a%d.example" % i: (0, [(65, "a%d.example." % i, "0 a%d.example." % (i + 1))]) for i in range(10)}
r = h.resolve("a0.example", static(tbl))
ok(r["state"] == "alias-limit", "AliasMode の連鎖は上限で打ち切る（2.4.2 / 3.1）")
# 2.2: 1 本でも不正なら RRset 全体を捨てる
tbl = {"x.example": (0, [(65, "x.example.", "1 . alpn=h2"), (65, "x.example.", "2 . port")])}
r = h.resolve("x.example", static(tbl))
ok(r["state"] == "malformed" and r["records"] == [], "2.2 不正な RR があれば RRset 全体を捨てる")
# 9: HTTPS の既定 ALPN は http/1.1。no-default-alpn で外れる
r = h.resolve("x.example", static({"x.example": (0, [(65, "x.example.", "1 . alpn=h2")])}))
ok(r["records"][0]["alpn_set"] == ["h2", "http/1.1"], "9 節：既定 ALPN http/1.1 が足される")
r = h.resolve("x.example", static({"x.example": (0, [(65, "x.example.", "1 . alpn=h2 no-default-alpn")])}))
ok(r["records"][0]["alpn_set"] == ["h2"], "no-default-alpn で既定が外れる")
# 2.4.1: 優先度順
r = h.resolve("x.example", static({"x.example": (0, [(65, "x.example.", "20 b.example."), (65, "x.example.", "10 a.example.")])}))
ok([p["priority"] for p in r["records"]] == [10, 20], "SvcPriority の昇順に並ぶ")

# ---- RFC 9848 Figure 1 の ech を RFC 9849 4 節で解く -------------------------
fig1 = ("AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAE"
        "AAWQVZWNoLXNpdGVzLmV4YW1wbGUubmV0AAA=")
cfgs = h.parse_echconfiglist(base64.b64decode(fig1))
ok(len(cfgs) == 1 and cfgs[0]["public_name"] == "ech-sites.example.net", "RFC 9848 Fig.1: public_name は ech-sites.example.net")
ok(cfgs[0]["version"] == 0xFE0D and cfgs[0]["config_id"] == 1 and cfgs[0]["kem_id"] == 0x0020, "version 0xfe0d / config_id 1 / X25519")
ok(cfgs[0]["public_key_len"] == 32 and cfgs[0]["cipher_suites"] == [{"kdf": "HKDF-SHA256", "aead": "AES-128-GCM"}], "鍵 32 バイト、スイート 1 組")
ok(cfgs[0]["maximum_name_length"] == 100 and cfgs[0]["extensions"] == [] and cfgs[0]["ignore_reason"] is None, "maximum_name_length=100、拡張なし")
ok(wire("1 . ech=" + fig1).hex().endswith("0005" + "004a" + base64.b64decode(fig1).hex()),
   "ech のワイヤ形式は ECHConfigList そのまま。SvcParam の長さ 0x4a の直後に ECHConfigList 自身の長さ 0x48 が来る（RFC 9848 3 の「redundant length prefix」）")

def raises(fn):
    try:
        fn()
    except h.Malformed:
        return True
    return False


bad = bytearray(base64.b64decode(fig1)); bad[1] -= 1
ok(raises(lambda: h.parse_echconfiglist(bytes(bad))), "ECHConfigList の長さプレフィックスが実体と合わなければ不正")
bad = bytearray(base64.b64decode(fig1)); bad[2], bad[3] = 0xFE, 0x0A
cfgs = h.parse_echconfiglist(bytes(bad))
ok(len(cfgs) == 1 and cfgs[0]["supported"] is False and cfgs[0]["length"] == 0x44, "未知の version は length で読み飛ばす（4 節：MUST ignore）")
# 構造: [0:2] リスト長 [2:4] version [4:6] length [6] config_id [7:9] kem_id [9:11] 公開鍵長 ...
bad = bytearray(base64.b64decode(fig1)); bad[7] = 0x00; bad[8] = 0x10  # KEM を P-256 に
ok(h.parse_echconfiglist(bytes(bad))[0]["kem"].startswith("DHKEM(P-256"), "KEM 0x0010 は P-256")
bad = bytearray(base64.b64decode(fig1)); bad[7] = 0x7F; bad[8] = 0xFF
ok(h.parse_echconfiglist(bytes(bad))[0]["ignore_reason"].startswith("未知の KEM"), "未知の KEM は無視理由付き")

# ---- RFC 9849 6.1.7: public_name の検査 ---------------------------------------
ok(h.check_public_name("cloudflare-ech.com") is None, "LDH ラベル")
ok(h.check_public_name("cover.defo.ie") is None, "通常の名前")
ok(h.check_public_name(".example.com") is not None and h.check_public_name("example.com.") is not None, "先頭・末尾のドット")
ok(h.check_public_name("a" * 64 + ".example") is not None, "63 を超えるラベル")
ok(h.check_public_name("under_score.example") is not None, "LDH 以外の文字")
ok(h.check_public_name("192.0.2.1") is not None, "最終ラベルが全部数字 → IPv4 と解釈され得る")
ok(h.check_public_name("example.0x7f") is not None and h.check_public_name("example.0x") is not None, "最終ラベル 0x+16進（空も含む）")
ok(h.check_public_name("example.0x7g") is None, "0x の後に 16 進でない文字があれば通常のラベル")


def with_public_name(name):
    raw = base64.b64decode(fig1)
    body = bytearray(raw[6:])                      # ECHConfigContents
    pn = name.encode()
    # config_id(1) kem(2) 公開鍵長(2) 公開鍵(32) スイート長(2) スイート(4) max_name_len(1) までを流用
    head = body[:1 + 2 + 2 + 32 + 2 + 4 + 1]
    new_body = head + bytes([len(pn)]) + pn + b"\x00\x00"
    cfg = raw[2:4] + len(new_body).to_bytes(2, "big") + bytes(new_body)
    return len(cfg).to_bytes(2, "big") + cfg


ok(h.parse_echconfiglist(with_public_name("1.2.3.4"))[0]["ignore_reason"].startswith("public_name"), "IPv4 風の public_name は無視")
ok(h.parse_echconfiglist(with_public_name("ok.example"))[0]["ignore_reason"] is None, "正常な public_name")

# ---- 実データ（2026-11-07） -----------------------------------------------------
fx = h.FixtureLookup(os.path.join(HERE, "fixtures", "live-2026-11-07.txt"))
main = ["google.com", "microsoft.com", "apple.com", "amazon.com", "cloudflare.com", "github.com", "salesforce.com", "zoom.us", "slack.com", "okta.com",
        "cybozu.com", "yahoo.co.jp", "softbank.jp", "mufg.jp", "smbc.co.jp", "ana.co.jp", "jal.co.jp", "rakuten.co.jp", "freee.co.jp", "sakura.ad.jp",
        "biglobe.ne.jp", "ocn.ne.jp", "so-net.ne.jp", "line.me", "japanpost.jp", "kddi.com", "mercari.com", "moneyforward.com", "nifty.com", "ntt.com"]
has_https, has_ech, via_cname = set(), set(), set()
for d in main:
    for n in (d, "www." + d):
        r = h.resolve(n, fx)
        ok(r["state"] != "malformed", "%s の RRset が不正扱いになっている" % n)
        if r["state"] == "service":
            has_https.add(d)
            if r["chain"]:
                via_cname.add(d)
            if any(p["ech"] for p in r["records"]):
                has_ech.add(d)
ok(has_https == {"google.com", "cloudflare.com", "cybozu.com", "so-net.ne.jp", "line.me", "mercari.com"}, "主要30で HTTPS レコードありは 6 件: %r" % sorted(has_https))
ok(via_cname == {"cybozu.com", "so-net.ne.jp", "line.me", "mercari.com"}, "うち 4 件は www の CNAME 先（CDN）に載っている")
ok(has_ech == set(), "主要30で ech を広告しているものは 0 件")
ok(fx.missing == [], "フィクスチャに無い名前を引いていない: %r" % fx.missing)

r = h.resolve("ac-5.net", fx)
c = r["records"][0]["ech"][0]
ok(c["public_name"] == "cloudflare-ech.com" and c["config_id"] == 109 and c["kem_id"] == 0x0020, "ac-5.net の ech: public_name cloudflare-ech.com, config_id 109")
r2 = h.resolve("www.ac-5.net", fx)
ok(r2["records"][0]["ech"][0]["config_id"] == 23 and r2["records"][0]["ech"][0]["public_name"] == "cloudflare-ech.com",
   "同じ日に www は config_id 23（鍵のローテーション途中の 2 世代が見えている）")
ok(r["records"][0]["alpn_set"] == ["h3", "h2", "http/1.1"], "ac-5.net の ALPN 集合")
r = h.resolve("defo.ie", fx)
ok([c["config_id"] for c in r["records"][0]["ech"]] == [177, 187, 211] and all(c["public_name"] == "cover.defo.ie" for c in r["records"][0]["ech"]),
   "defo.ie は ECHConfig 3 個、public_name は cover.defo.ie")
r = h.resolve("tls-ech.dev", fx)
c = r["records"][0]["ech"][0]
ok(len(c["cipher_suites"]) == 2 and c["cipher_suites"][1]["aead"] == "ChaCha20Poly1305" and c["maximum_name_length"] == 64 and c["public_name"] == "public.tls-ech.dev",
   "tls-ech.dev はスイート 2 組（AES-128-GCM / ChaCha20Poly1305）、maximum_name_length 64")
r = h.resolve("www.cloudflare-ech.com", fx)
ok(r["state"] == "nxdomain", "public_name の www は NXDOMAIN")
r = h.resolve("www.line.me", fx)
ok(len(r["chain"]) == 2 and r["final"] == "dj6jito9qvx8o.cloudfront.net" and r["records"][0]["alpn_set"] == ["h2", "h3", "http/1.1"], "CNAME 2 段の先の HTTPS を読む")
r = h.resolve("www.github.com", fx)
ok(r["state"] == "none" and r["final"] == "github.com", "CNAME の先に HTTPS が無ければ無し")
r = h.resolve("www.mercari.com", fx)
ok(r["records"][0]["effective_target"] == "www.mercari.com.cdn.cloudflare.net", "「.」は CNAME を辿った後の所有者名")

print("OK: %d assertions passed" % N)
