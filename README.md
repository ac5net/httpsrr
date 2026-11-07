# httpsrr

DNS の **HTTPS レコード（RFC 9460）** を読み、**ech パラメータ（RFC 9848）** の中身を **RFC 9849 の ECHConfigList** として解くスクリプトです。
Python 標準ライブラリだけで動き、外部パッケージのインストールは不要です。

## 使い方

```
git clone https://github.com/ac5net/httpsrr.git
cd httpsrr
python3 httpsrr.py <ホスト名> [--json]
```

例

```
python3 httpsrr.py ac-5.net
python3 httpsrr.py www.cybozu.com
```

DNS は DoH（dns.google）で引きます。`--fixtures <txt>` を渡すとネットワークに出ず、テキストに書いた応答で動きます（テストと再現用）。

## 何をしているか

- HTTPS（type 65）を引き、応答の CNAME を辿って最終名の HTTPS RRset を取る（RFC 9460 2.3 / 9.1）
- 提示形式「SvcPriority TargetName SvcParams」を 2.1 と Appendix A（文字列デコード、カンマ区切りのエスケープ）で解析し、2.2 のワイヤ形式に組み立て直す
  - キーの重複、`mandatory` の整合、`no-default-alpn` と `alpn` の関係、`port` / IP ヒントの形式を検査する（1 本でも不正なら RRset 全体を捨てる）
  - ワイヤ形式はキー番号の昇順。提示形式は任意の順でよい（Appendix D Figure 9）
- SvcPriority 0（AliasMode）なら TargetName を辿る。「.」は 2.5 の規則で扱う。連鎖には上限がある（3.1）
- HTTPS の既定 ALPN `http/1.1` と、自動的に mandatory な `port` / `no-default-alpn` を 9 節どおりに扱う
- `ech` は Base64 を外し、RFC 9849 4 節の構造（version / config_id / KEM / 公開鍵 / 暗号スイート / maximum_name_length / public_name / extensions）で解く
  - 未知の version は length で読み飛ばす。未知の KEM、未対応の mandatory 拡張、6.1.7 に合わない public_name は「無視」と判定する

## 主要30ドメイン＋参照6の実測（2026年11月7日）

- 主要30ドメイン（apex と www）で **HTTPS レコードがあるのは 6 件**：google.com, cloudflare.com, cybozu.com, so-net.ne.jp, line.me, mercari.com
  - うち 4 件は www の CNAME 先（CloudFront / Cloudflare CDN）に載っているもの。Akamai 配下の 12 件には無かった
- **ech を広告しているのは 30 件中 0 件**
- 参照：ac-5.net（Cloudflare プロキシ）には `ech` が付いていた（public_name は cloudflare-ech.com）。同じ日に apex と www で config_id が違う（鍵ローテーションの 2 世代）
- defo.ie は ECHConfig 3 個、tls-ech.dev は暗号スイート 2 組（AES-128-GCM / ChaCha20Poly1305）

`fixtures/live-2026-11-07.txt` はその日に dns.google から取得した 72 件の応答（CNAME 込み）です。

## テスト

```
python3 test_httpsrr.py
```

ネットワークに出ないのでオフラインで実行できます。RFC 9460 Appendix D のテストベクタ（Figure 2〜10 のワイヤ形式、Figure 11〜16 の不正例）、
Appendix A の文字列デコードの例、2.5 / 3 節の解釈、RFC 9848 Figure 1 の ech、RFC 9849 6.1.7 の public_name 規則、実データ 36 ドメインを
133 件のアサーションで確認します。

## 解説記事

RFC の要件の読み合わせ、36 ドメインの結果、落とし穴の経緯はブログに書いています。

https://ac-5.net/security/https-record-ech-rfc9460-check/

## ライセンス

MIT
