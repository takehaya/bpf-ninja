# DSL 続編バックログ

`feat/p4_based_dsl` ブランチで MVP は完了。本ドキュメントは **次に何を、どの優先度で、どう手をつけるか** を整理する作業ノート。各項目は単独 PR にできる粒度に切ってある。

優先順位は「実利用での痛さ × 工数の軽さ」で並べた個人見解。実装着手前にレビューで上下する想定。

完了済みの項目は ✅ で marking し、commit ハッシュを併記。残課題のみ展開してある。

## P0: ブロッカ級 (最優先)

### 1. CI で vimto verifier load を回す ✅ 完了

**現状**: `.github/workflows/bpf_load_test.yaml` が **vimto + 4 kernel matrix (6.1 / 6.6 / 6.12 / 6.18)** で `-run TestBpf` を回す。DSL の verifier-load テスト (`TestBpfEntryWithDSLFilter`, `TestBpfExitWithDSLFilter`, `TestBpfLoopSpikeVerifies`) は regex で自動取り込み — 新しい `TestBpf*` を足せば追加配線なしで回る。

**完了 commit**:
- `255d9dd` ci(dsl): trigger bpf-load workflow on .p4 changes too — `**.p4` の path filter を追加し vocab-only コミットも CI を triggered

**残課題 (低優先)**:
- 5.17 (bpf_loop 最小サポート kernel) を matrix に追加 — docs では 5.17+ サポート謳いなのでカバレッジ強化に意味あり
- DSL 専用の fast feedback ジョブ — 4 kernel × 全 TestBpf で 5-15 分。`TestBpfEntryWithDSLFilter` だけ単一 kernel で回す軽量ジョブを別途追加すれば PR 中の小修正で待ち時間短縮

### 2. CIDR / IP / MAC リテラル predicate ✅ 完了

**完了 commit**:
- `766e8e8` IPv4 host + IPv4 CIDR `==`/`!=`
- `369d556` IPv4 /32 short-circuit
- `02ba9c2` IPv6 host + IPv6 CIDR + MAC (`==` のみ)
- (`feat/p4_based_dsl`) IPv6 host / IPv6 CIDR / MAC で `!=` 対応 (multi-word match 用ラベル経路追加)

`eth/ipv4[src==10.0.0.1]/tcp` から `eth/ipv6[dst!=2001:db8::/32]/tcp` や `eth[dst!=de:ad:be:ef:00:01]/ipv4/tcp` まで vimto verifier 通過。lexer/parser はもともと全種を tokenize していたので、codegen が追いついた格好。

`!=` は word ごとの JNE で「不一致なら成功」のジャンプ先を per-predicate `dsl_pred_match_<n>` ラベルに振り、フォールスルー (= 全 word 一致) が `Ja dsl_reject` に落ちる形。`==` は同じ JNE で `dsl_reject` に向かい、フォールスルー (= 全 word 一致) が成功路となる。両者は `multiWordRoute` ヘルパで生成し IPv6 host / CIDR / MAC で再利用される。

### 3. `<SELF>_CHAIN_END_<FIELD>` vocab 一般化 ✅ 完了

**完了 commit**:
- `befecd2` feat(dsl): replace MPLS s-bit hardcode with vocab CHAIN_END const
- `64dff53` refactor(dsl): share field-walk, struct-return classify, doc invariants

`bpfloop.go:chainEndCheck` の `spec.Name == "mpls"` hardcode は撤去済み。`<SELF>_CHAIN_END_<FIELD> = <value>` を vocab に書けば codegen が拾う。MPLS は `MPLS_CHAIN_END_S = 1` を mpls.p4 に declarative に持つ。byte-aligned 8-bit と sub-byte 1-bit の 2 形を encode 対応。

将来 SRv6 segments_left / IPv6 ext-header 等で同型の機構を要求するときは vocab 1 行で完了する。

### 4. p4c による vocab 文法検証 (CI) ✅ 完了

**動機**: バンドル `.p4` ファイル群は p4lite が parse できる形だが、本物の P4-16 仕様に乗っているか継続検証したい。`feat/p4_based_dsl` ブランチ名のとおり、P4 互換性は design goal。

**完了内容** (`feat/p4_based_dsl`):
- `docker/p4c-check/Dockerfile` — `p4lang/p4c:1.2.5.12` をベースに multi-stage build。pin 指定で upstream の `latest` 再リファレンス drift を防ぐ
- `docker/p4c-check/check.sh` — 各 `.p4` を `p4test --parse-only --Werror` で検証。**per-file content-hash キャッシュ** (`/work/.p4c-cache/<sha256>.<ver>.ok`) 内蔵
- `scripts/p4c-check.sh` — ローカル実行用 wrapper、`docker build` + `docker run` を呼ぶだけの薄い shell
- `.github/workflows/p4c-check.yml` — buildx GHA cache + `actions/cache` で `.p4c-cache/` 持続。trigger は `.p4` / vocab loader / harness の path filter
- `Makefile` に `p4c-check` target 追加
- `.gitignore` に `/.p4c-cache/` 追加

**実機検証で判明した upstream 不具合 2 つ** (Dockerfile / check.sh で吸収):
1. `p4lang/p4c:1.2.5.12` (Ubuntu 20.04) は `libboost-iostreams1.71.0` を入れ忘れ → image build 時に `apt install` で補填
2. `--parse-only` でも `packet_in` 型解決が必要 (事前調査と異なる実機挙動) → check.sh が `#include <core.p4>` を tmp file に prepend

**ベンチ実測** (ローカル warm Docker daemon):
- cold cache: 1.8s (16 ファイル全部 parse)
- warm cache (1 ファイル変更): 変更したファイルだけ parse、他は cache hit
- 全 cache hit: 0.5s

**残課題 / 将来拡張**:
- 上流 `p4lang/p4c` に `libboost-iostreams1.71.0` 追加 PR を投げる (`apt install` workaround を撤去できる) — user 判断で skip
- `--validate` (frontend full pass) に上げる場合は `.p4` 各ファイルの先頭に `#include <core.p4>` を直接足す。今の workaround との切替判断は要望待ち

**参考**: [p4lang/p4c Docker image](https://hub.docker.com/r/p4lang/p4c), [backends/p4test](https://github.com/p4lang/p4c/blob/main/backends/p4test/p4test.cpp), [P4-16 v1.2.5 spec](https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html)

### A. 可変長 header 対応 (parser-state-machine + VAREXT/OPT) ✅ 完了

**動機**: `pkg/kunai/protocols/` 配下の `.p4` vocab は MVP 当初固定長ヘッダしか codegen に伝えておらず、GTP-U 拡張、IPv6 ext header chain、SRv6 segment list、IPv4/TCP options、GRE flags などの実フレームを silent miss していた。`feat/p4_based_dsl` ブランチ名のとおり、P4 標準への完全 alignment を目指して可変長解釈を full implementation。

**完了内容** (`feat/p4_based_dsl`):

- **PR 1**: `vocab.ParseStateMachine` IR — p4lite parser AST から正規化された state machine を構築。trivial (`extract; transition accept;`) は `nil` で legacy path に流す
- **PR 2**: `genParserMachine` codegen — state machine を walk して命令列を emit、self-loop は bpf_loop 化、select tuple match (≤3 keys) 対応。GTP-U の `gtp_h` + optional + ext chain を実装
- **PR 3**: IPv6 ext header chain — `knownVariableTails["ipv6_ext_h"]` で per-iteration variable advance、parent header `next_header` への write-back で次 layer dispatch を正しく resolve
- **PR 4**: SRv6 segment iteration — `srv6_h` の variable trail として segment list を opaque bytes 扱い、内側 dispatch (`{TCP,UDP,IPv4}_SRV6_NEXT_HEADER`) を追加
- **PR 5**: VAREXT (IPv4 IHL / TCP data_offset の primary header trailer) と OPT_TRIGGER (GRE C/K/S 各 flag-gated 4B advance) を const-based で実装。`MinimumTotal` underflow guard で IHL<5 / data_offset<5 を reject
- **PR 5 follow-up (refactor)**: `emitVariableTrailInline` / `emitVariableTrailCallback` の duplication を `trailEnv` で抽象化して 1 つに統合 — register convention だけが両者の差なので、今後 trail 系を増やすときに片方更新忘れの risk を消した
- **PR 5 follow-up (dispatch fix)**: variable advance を持つ parent (VariableSuffix / FlagTriggers) の field を子の dispatch が読むときに、`R4 - parentHS` 式が options/flag 分ずれていた問題を `parentNeedsLayerEntryAnchor` で layer-entry slot 経由に統一。dsltest を実機 root で回して初めて顕在化 — verifier load は通るが実 packet で match しない silent miss
- **PR 5 follow-up (scratch 512)**: `eth/ipv6/srv6/tcp` のような IPv6 ext + SRv6 + TCP options 累積で R4 worst-case が ~322 になり scratch 256 を超える件、scratch を 512B に拡張。per-CPU map なので memory cost は微小

**検証**:
- vimto kernel 6.1 / 6.6 / 6.12 / 6.18 で `TestBpfEntryWithDSLFilter` 全 case 緑、`eth/ipv4/udp/gtp/ipv4/tcp` と `eth/ipv4/gre/ipv4/tcp` も含む
- `make p4c-check` 緑 (新規追加した `.p4` const も p4c parse-only 通過)
- **`pkg/kunai/dsltest/`** に移動して kunai library の test helper として位置付け。gopacket 製の実フレーム against 28 E2E cases (IPv4 options / TCP options / GRE flags / IPv6 ext / SRv6 / GTP-U / VLAN / MPLS) を root で全 PASS — vimto kernel 6.18 上でも緑

**追加で対応した項目** (`feat/p4_based_dsl`):
- **kernel 6.1 BSWAP**: ✅ 解消。`asm.BSwap` (opcode `0xd7`、6.6+) を使っていた `predicate.go` / `where.go` を `asm.HostTo(asm.BE, ...)` (BPF_END family、5.x で動く) に置換。equality は constant 側を codegen 時に byte-swap して swap 命令を完全省略。**vimto kernel 6.1 で 35 chains 全 PASS** を確認
- **ESP terminal layer**: ✅ 完了。`pkg/kunai/protocols/esp.p4` 追加 — `eth/ipv4/esp` / `eth/ipv6/esp` で SPI/Sequence Number まで match できる (内側 encrypted は読めないので chain 終端)。dsltest E2E 追加 (`TestEthIPv{4,6}ESPMatch`)

**残課題 (低優先)**:
- **IPv6 ext + SRv6 Routing(43) 衝突**: 現状 scratch 512 で吸収。**fastpath JEq による verifier-narrowing を試行したが効果なし** — parser machine の done label に ext-walk path と fastpath path の両方が Ja で合流するため、verifier は両 path の R4 max を join して同じ広い bound を維持する (scratch 256 でも reject が再現)。fundamental には fastpath 専用の 別 done label + child dispatch 二重化が必要で、parser machine emit を大きく refactor する必要がある。scratch 512 (worst-case 320 B、余裕 192 B) で実用上は問題ないため defer

### B. aux header model — predicate / stack / quantifier / options ✅ 完了

**動機**: §A で可変長解釈は parser-state-machine + VAREXT として実装したが、parser block の `out` parameter で declare された **auxiliary header の field を DSL から直接 predicate / where で読む** 手段が無かった。GTP-U の opt block (`gtp.opt.next_ext`)、SRv6 segment list (`srv6.segments[N].addr`)、TCP options (`tcp.options.MSS.value`) などへのアクセスが silent gap。

**設計判断 (Y) aux header model**:
chain decomposition (= `srv6/srv6_seg+/...` のように segments を独立 chain protocol にする案) と aux header model (= `srv6.segments[N]` のように SRH wrapper の中身として表現する案) の比較で **後者を採択**。SRH segment list は SRH wrapper の中身であって外側の独立 layer ではないこと、入れ子 SRH との visual 区別が必要なこと、TCP/IPv4 options が wrapper-内ルックアップ系であることから、wrapper + aux 概念で統一。chain protocol は VLAN/MPLS/QinQ のような **真の stacked external headers** に限定。詳細な分類と実装指針は **`dsl-internals.md` §6 「可変長構造の分類と表現」**。

**実装した PR (`feat/p4_based_dsl` ブランチ)**:

| PR | scope | 例 |
|---|---|---|
| PR-A | 単発 aux predicate + bracket / where 両形 | `gtp[opt.next_ext == 0]` / `where gtp.opt.next_ext == 0` |
| PR-B + PR-B' | aux header stack の static / dynamic index access、IPv6 アドレス比較対応 | `srv6.segments[0].addr == fc00::1`、`srv6.segments[srv6.last_entry].addr == X` |
| PR-C | `any() / all()` 量化詞 (SRv6 segments を中心に、count guard 付き) | `where any(srv6.segments.addr == fc00::1)` |
| PR-D | TCP options walk codegen + parser block 経由の vocab declaration | `where tcp.options.MSS.value == 1460` |

**廃案**: 同じ問題に対し chain decomposition 方向で `srv6_seg+` / `gtpext+` を独立 chain protocol にする案を試作したが (草案 commit が一時 push、後 rollback)、wire 構造との対応が崩れること、`*` / `?` quantifier silent-miss 問題、入れ子 SRH との syntactic 区別困難、で採用見送り。aux model に切り替えたあとも、本草案で導入した parent-field-count chain end (`<SELF>_<PARENT>_COUNT_FROM_<FIELD>`) の codegen は aux header stack の count source に流用している。

**検証**:
- vimto kernel 6.1 / 6.6 / 6.12 で `TestBpfEntryWithDSLFilter` 全 case 緑
- dsltest E2E で aux predicate / static index / dynamic index / any / all / TCP option lookup を root で実フレーム match 確認
- `make p4c-check` 緑 (新規 option declaration の `header tcp_opt_*_h` も p4c parse-only 通過)

**Document**: 文法は `dsl-grammar.md §1.3 / §1.4`、user 例文は `dsl-usage.md §フィールド参照 / §Aux header / §Quantifier`、設計思想は `dsl-internals.md §6` を参照。

## P1: UX / 運用品質

### 5. エラーメッセージに source position 統一 ✅ 完了

**完了 commit**:
- `d258272` feat(dsl): prefix codegen errors with line:col when available

`PositionedError` で codegen 系エラーに `line:col:` prefix。`genLayer` / `emitPredicates` / `genCondition` / `computeCapture` / `checkUnsupported` でラップ。`errors.Is(err, ErrNotImplemented)` は維持。実例: `eth/ipv6[src==fe80::/64]/tcp` → `1:10: dsl codegen is not yet ...`

### 6. `--dsl-help` introspection ✅ 完了

**完了 commit**:
- `6ad3b97` feat(cli): add --dsl-help with grammar and bundled protocol list

`xdp-ninja --dsl-help` で文法 BNF + バンドル 16 プロトコル一覧 (header byte size + 親 dispatch list) を出力。`-i`/`-p` 不要、誰でも実行可能。次の項 (`--list-protos`) は本実装でカバー済みなので独立 PR は不要。

### 7. `--list-protos` introspection ✅ 6 で代替

`--dsl-help` の出力に既にプロトコル catalogue (header bytes + 親 dispatch) が含まれるので別フラグの追加価値は薄い。要件次第で「もっと詳細を出す `--list-protos` (フィールド一覧 + 各プロトコルの dispatch const 全件)」を後付け可能だが、現状 unmet need なし。

## P2: 機能拡張 (需要次第)

### 8. `field in [v1, v2, ...]` predicate

**動機**: `where tcp.dport == 443 or tcp.dport == 80` の構文糖。

**スコープ**:
- Parser は既に `ast.PredIn` を生成 (Unsupported フラグ立ち)
- Codegen で `PredIn` を「OR の連続」に展開 (MVP)、もしくは hash-table lookup (BPF_MAP_TYPE_HASH) — MVP は OR 展開で十分

**工数**: 0.5-1 日。

### 9. `field has FLAG` predicate

**動機**: `tcp.flags has SYN` のように bitmask 比較を書けるようにする。

**スコープ**:
- Parser は既に `ast.PredHas` を生成 (Unsupported)
- Vocab に flag bit の定数を持たせる必要あり (`const bit<9> TCP_FLAG_SYN = 0x002;`)
- Codegen で `field & mask != 0` を emit

**工数**: 1 日 (vocab 定数の表現も含めて)。

### 10. 算術ネスト 4 段以上

**動機**: 現在 stack slot が 4 段。`((a+b)*c+d)*e` のような長い式が ErrNotImplemented。

**スコープ**:
- `arithStackBase = -56`, max depth 4 を 8 か 16 まで拡張
- BPF stack 512 byte 制限内に収める
- 既存 stack 利用箇所 (`-48` の args ptr, bpf_loop ctx の `-128`〜 など) との衝突を再確認

**工数**: 0.5 日。

### B-1. `.exists` bool atom (where 句直接記述)

**動機**: §B で `proto.aux.exists` の resolver path は実装済み (`ir.AuxRef.Option.ExistsOnly` / `ir.FieldRef.IsExistsCheck`)。ただし where 句で `where gtp.opt.exists` を **裸の bool atom として書く** parser 拡張が未対応 — 現状 parser は field path 後に op を要求する。

**スコープ**:
- `parseWhereAtom` に「field path の末尾が `exists` なら bool atom として終端」分岐追加
- `parseArithCmp` の早期分岐で TokIdent → field path → `.exists` チェック
- codegen 側は既存の AuxRef gating-only emit を流用

**工数**: 0.5 日。

### B-2. IPv4 options vocab 拡張

**動機**: §B PR-D で TCP options の vocab 宣言と option-walk codegen は通った。同じ枠組みで IPv4 options (Router Alert, Record Route, Source Route, Timestamp, Security 等) を declare すれば追加 codegen なしで動く。

**スコープ**:
- `pkg/kunai/protocols/ipv4.p4` に `IPV4_OPT_TERMINATOR_KIND/PADDING_KIND/LENGTH_BYTE_OFF` + 各 option の `<NAME>_KIND/SIZE` + `header ipv4_opt_<name>_h`
- 主要対象: Router Alert (kind 148, 4 B 固定)、Record Route / LSR / SSR / Internet Timestamp (可変、内部 array — Phase 2 まで `.exists` のみ)
- dsltest E2E

**工数**: 1 日 (RA だけなら 2 時間)。

### B-3. CIDR / IPv4 / MAC literal を aux field に

**動機**: §B PR-A〜D で integer 比較の aux access は通ったが、IPv4 / IPv6 / MAC / CIDR literal を aux 経由で比較するパスは現状 `ErrNotImplemented`。`gtp[opt.flow_label == fe80::1]` 等は parse / resolve 通るが codegen 拒否。

**スコープ**:
- `pkg/kunai/codegen/predicate.go::emitIPv4Predicate` / `emitIPv6Predicate` / `emitMACPredicate` / `emitIPv4CIDRPredicate` / `emitIPv6CIDRPredicate` の `pred.Field.Aux != nil` ガードを通す
- aux byte offset を `fieldRefByteOffset` で取り、where 側の `genLiteralCompareDynamic` 同様に gating + 多 byte 読み出しを emit
- bracket form 同様

**工数**: 1-2 日 (5 関数に並列に対応)。

### B-4. Option 内部 array (SACK.blocks / RR.addrs)

**動機**: §B PR-D は TCP options を Schema A/B (固定フィールド + 単発) に絞った。SACK は `{left, right}` ブロックの配列 (Schema C)、IPv4 RR は IP アドレスの配列。これらにアクセスするには option 内部 array に `[N]` index と `any/all` を効かせる必要あり。

**スコープ**:
- vocab に array 宣言 (option header 後の trailing variable 領域 + 要素サイズ)
- resolver: `tcp.options.SACK.blocks[N].left` の 5-part path 受理
- codegen: option-walk で見つけた option base + `[N] * elem_size` で内部要素アクセス
- `any(tcp.options.SACK.blocks.left > 1000)` などの量化

**工数**: 2-3 日。chain quantifier 系のロジック流用可。

## P3: コード負債 / Sanity 系

### 11. Sanity self-dispatch chain

**動機**: chain self-dispatch は Field / NoCheck のみ。Sanity (NIBBLE) は codegen で明示拒否。

**スコープ**:
- 実用ケース稀 (MPLS s-bit は CHAIN_END で対応済み、SRv6 もまだ必要なし)
- 「dispatch 全種類が chain で使える」という API 対称性のため

**工数**: 0.5 日 (callback 内 sanity 検査の emit は既存ヘルパ流用)。

### 12. alternation の異種 header size + 異種 dispatch (= alt を実用化する)

**動機**: 現状 alternation が成立する組合せは `(vlan|qinq)` のみ。利用者が真に欲しい `(ipv4|ipv6)` のような alt は **2 つの MVP 制約** に引っかかって reject される:

1. **uniform header size 制約**: alt 各員が同じ size 必要。ipv4==20, ipv6==40 で fail
2. **alt 後 layer の dispatch agreement 制約**: 各 alt が次 layer に対し同じ field/value で dispatch することを要求。ipv4.protocol と ipv6.next_header はフィールド位置 / 名前異なるので fail

`(vlan|qinq)` だけ動くのは偶然の整合 (両方 4-byte、両方 ethertype field を同じ位置に持つ)。「alternation が便利」と謳うには両制約を緩める必要がある。

**スコープ**:
- alt ごとに matched flag を立て、各員別 advance する codegen (= 異種 size 対応)
- 後 layer の resolver が alt 各員の dispatch const を OR で受ける拡張 (= 異種 dispatch 対応)
- 命令数増加: alt N 員なら最大 N 倍の dispatch + advance code が並ぶ

**工数**: 2-3 日 (両制約を一括解除、test 含む)。

**インパクト**: 解除すると `eth/(ipv4|ipv6)/tcp` のような **大半のユーザーが直感する alt** が動くようになる。bundled 16 protocol で alt が成立する組合せが (vlan|qinq) 1 つ → 実用的な数に増える。

**関連 test**: `compile_test.go::TestCompileAlternationFollowedLayerDivergeRejected` を「成功」に flip + ipv4|ipv6 / tcp|udp / 等の expanded coverage 追加が必要。

### 13. alt-of-alt (ネストした alternation)

**動機**: `((a|b)|(c|d))` のような構造。

**工数**: 1 日。利用シーン稀。

## P3.5: 型システム関連 follow-up (`dsl-types.md` から派生)

[`dsl-types.md`](./dsl-types.md) で定義された型仕様の **段階展開** および **拡張**項目。型仕様自体は uniform に書かれているので、ここの実装が遅れても "型 OK / codegen ErrNotImplemented" の状態で安全。

### F1. Overflow lint mode ✅ 完了

`resolve.Options.StrictArithLint` opt-in pass として実装 (`resolve/typing.go::lintArithCondition`、`codegen.Capabilities.StrictArithLint` 経由で host が選択)。検出パターンは保守的: `field + field` / `field * field` の overflow、`field - field` で RHS ≥ LHS の underflow を error 化。`field + const` などの一般パターンは false-positive を避けるため pass。

### F2. 明示 cast 構文 ⏸ negative spec

`dsl-types.md §5.5` で「**入れない**」と決定。F1 が landed したので overflow ケアの代替も既に提供済。需要が出たら再検討する保留枠として残置。

### F3. `Int<128>` ordered cmp の codegen ✅ 完了 (bracket predicate)

`emitIPv6OrderedCmp` で lexicographic compare (high-half 決定 + low-half fall-through) を実装。bracket predicate 経路 (`ipv6[dst < fe80::ffff]`) で動作。where-arith 経路 (`where ipv6.src < ipv6.dst`) はまだ staged — 必要なら register-pair lex cmp の追加で landing 可能。

### F4. `Int<128>` arith binop (`+`, `-`) の codegen ✅ partial 完了

`genArithCompare128` / `genArith128` で `field == field` と `field op const == field` (op ∈ {+, -}) を実装。register-pair carry/borrow 伝播 (~5 命令)。`field + field`、ordered cmp on Int<128> in where はまだ staged。

### F5. `Int<128>` arith binop (`*`) の codegen ❌ 廃止

scope outside と判断。F11 bit-slice (`field[lo:hi]`) で「128bit 同士の比較 / prefix 抽出」を可能にしたため、ipv6 同士の乗算は実用 scenario が見当たらない。bit-slice の方が prefix/suffix 比較で広く使えるため。

### F6. bitwise op (`&`, `|`, `^`, `<<`, `>>`) ✅ 完了

`&` `<<` `>>` は mul/div 級 precedence、`|` `^` は add/sub 級。parser+AST+resolver+codegen 全 layer を network filter 用 idiom (`tcp.flags & 0x12 == 0x12`、`tcp.dport >> 4 == 0` 等) で landing。

### F7. `field in [v1, v2, ...]` 実装 ✅ partial 完了

`emitInPredicate` で **整数 alternatives** (`tcp[dport in [80, 443, 8080, 8443]]`) を OR-chain emit。IPv4 / IPv6 / MAC / CIDR alternatives は MVP scope outside (それぞれ専用 multi-word emit が必要、需要が出たら)。

### F8. `field has FLAG` 実装 ✅ F6 で superseded

F6 の bitwise `&` で `tcp.flags & 0x12 == 0x12` と書けるようになり、専用 emit は不要。vocab 著者が flag 定数を declare するかどうかは vocab 設計の自由。

### F10. `Bool == Bool` の precision-preserving codegen ✅ 完了

`genConditionAsBool` で各 operand を {0, 1} に評価して register に置き、scratch slot 経由で比較する形に置き換え。per-packet operand 評価が 1 回ずつになり、`(tcp.dport == 443) == gtp.opt.exists` のような式の dport 読みや gating が 1 回しか走らない。

### F9. `flow.*` dead syntax 削除 ✅ 完了

**動機**: `dsl-types.md` の型システムで `flow.*` は型を持たない (parser のみ受理、codegen reject)。spec に書かれていない死語なので parser から削除して整理。

**完了内容** (`feat/p4_based_dsl`):
- `lexer/token.go`: `TokFlow` 削除、keywords map から `"flow"` を取り除き
- `ast/kinds.go` / `ast/ast.go`: `WAtomFlow`、`FlowKind` フィールド削除
- `ir/ir.go`: `Condition.FlowKind` 削除
- `parser/where.go`: `parseFlowAtom` 関数削除、where atom の switch から `TokFlow` 分岐除去
- `resolve/where.go`: `WAtomFlow` ブランチ削除 (使われなくなった `fmt` import も同時削除)
- 関連 test (parser_test / resolve_test / ast_test / codegen_test) を全削除 or 入れ替え

これで「`flow.is_new` を書くと parser が単に `flow` を未知の識別子として扱う」状態になり、エラーは「`flow` という protocol が見つからない」系の通常 path に乗る。dead syntax の影響範囲が完全に消えた。

### F11. bit-slice `field[lo:hi]` MVP ✅ 完了

`dsl-types.md §3.4` で構文・意味・実装制限を導入。lexer (`TokColon`) + parser (`tryParseIndexExpr` の slice 分岐) + AST (`IndexExpr.IsSlice` / SliceLo / SliceHi) + IR (`FieldRef.Slice` + `EffectiveBits()`) + resolver (`detachTrailingSlice` / `attachSlice`) + codegen (`applySliceToOffset` + `slicePostAdjust` + `emitSliceShiftMask`) の全 layer を landed。bracket predicate / where-arith 双方で使用可能。

### F12. bit-slice mid-width cmp (`(64, 128]` 範囲) ✅ 完了

`tryDesugarMultiLDXSliceCmp` で resolver に desugar pass を追加。`splitSliceIntoLDXChunks` が greedy に 8 / 4 / 2 / 1 byte chunks に分解し、各 chunk が単一 LDX cmp として AND-chain (`==`) / OR-chain (`!=`) で連結される。`[0:96]` → `[0:64]` AND `[64:96]` のように展開。

### F13. bit-slice non-aligned 端点 ✅ 完了 (≤ 64bit 範囲)

`emitSliceShiftMask` で post-load shift+mask emit を追加。codegen が `pow2 ≥ cover` バイトを LDX し、bswap → shift → mask の順で slice bits を抽出。`tcp.dport[3:9]` のような sub-byte 範囲が動く。`> 64bit` の non-aligned slice は依然 staged (cross-byte の AND-chain × shift+mask の組み合わせ実装になる)。

## P4: 大物 (スコープ要再検討)

### 14. `flow.is_new` / `flow.age` / `flow.state` 状態 atom

**動機**: 連続パケット間の関係 (= flow tracking) に基づくフィルタ。

**スコープ**:
- BPF_MAP_TYPE_HASH で flow tuple → メタデータの map を持つ
- パケットごとに lookup + update
- map size, eviction policy, key 設計など考慮事項多い

**工数**: 数日〜1 週間。本格仕事。

## P5: ライブラリ化 (xdp-ninja の外で再利用可能に)

### 15. `internal/dsl/` → `pkg/kunai/` 移動 + 公開 API 設計 ✅ 完了

**動機**: 旧 `internal/dsl/` は Go の `internal/` 規約で xdp-ninja 外から import 不可だった。`p4lite + 一行 DSL + codegen` の機構自体は xdp-ninja 固有ではないので、**他プロジェクトから library として使える形** に出した。

**命名**: パッケージ名は **`kunai`** (苦無 — 多目的の ninja 道具)。`xdp-ninja` ecosystem を保ちつつ独立 library として通用する。

**完了内容** (`feat/p4_based_dsl`):
- `internal/dsl/` → `pkg/kunai/` 配下に全移動 (`codegen/` / `parser/` / `lexer/` / `resolve/` / `ir/` / `ast/` / `vocab/` / `dslvocab/` / `protocols/`)
- `compile.go` のパッケージ宣言 `package dsl` → `package kunai`、`compile_test.go` も同様
- import path 一括置換 (`xdp-ninja/internal/dsl` → `xdp-ninja/pkg/kunai`、42 ファイル)
- caller 側 (`internal/program/program.go`) の `dsl.Compile` → `kunai.Compile`
- ドキュメント / scripts / workflow YAML の全 `internal/dsl/` ref を `pkg/kunai/` に置換
- 全 unit test 緑、ビルド緑

**残作業 (任意)**:
- 公開 API: `kunai.Compile(expr string, caps codegen.Capabilities) (Output, error)`。サブパッケージは semi-internal、API 安定性は README で明示済み
- target 抽象化 → 次項 16 で扱う

### 16. Target 抽象化 (XDP / tc / pcap-replay 対応) ✅ 完了

**動機**: cBPF が pcap でも socket でも kernel でも動く portable bytecode だったように、`kunai` の codegen output (= `[R0, R1) のバイト列を見て R2 に accept/reject を書く eBPF subprogram`) も target portable にする。

**完了内容** (`feat/p4_based_dsl`):

段階 A (API decouple):
- `pkg/kunai/codegen/caps.go` 新設: `Capabilities`, `ActionFetcher` interface のみ (host 知識 0)
- `Mode` enum / `IsFExit()` 撤去 / `pkg/kunai/ast/xdp.go` 撤去
- parser / resolver / codegen を caps 経由に rewrite (`reservedLabels` / `allowedActions` / `caps.Action`)
- `Compile(expr, caps)` signature 変更、caller (`internal/program/program.go`) 対応

段階 B (host adapter サブパッケージ + ABI 契約明文化):
- `pkg/kunai/host/xdp/xdp.go` 新設: `Actions`, `FexitFetcher`, `FexitCapabilities()` を host adapter として export
- `caps.go` から XDP 知識を一掃 (interface 定義のみに)
- `codegen/codegen.go` package doc を **library 境界 (kunai ↔ host) ABI 契約** として整理:
  - 入力: R0/R1/R9 を host が設定
  - 出力: R2 = {0,1}、`filter_result` ラベルで終端
  - kunai 占有: R3-R5、stack [-56..-80] (arith) + [-128..-104] (bpf_loop ctx)
  - **host 占有 (kunai 触らない): R6-R8 callee-saved、stack [-1..-48]**
- `pkg/kunai/compile_test.go::TestZeroCapsIsHostAgnostic` 追加 — `Capabilities{}` で compile した出力が R6-R8 / stack[-48] を一切触らないことを CI で regression guard

**結果**: kunai 本体は完全に host-agnostic。新 host を追加するには `pkg/kunai/host/<name>/` を 1 つ作って `Capabilities` を返す関数を export するだけ。kunai コア無修正で:
- XDP fentry / fexit (実装済み, `host/xdp`)
- tc clsact ingress / egress (`host/tc/` に追加可能、未実装)
- userspace `BPF_PROG_TEST_RUN` (`host/userspace/` 等、未実装)
- 任意の独自 host (consumer 側で fetcher 実装)

**残課題 (別 PR、需要次第)**:
- tc clsact 用 host/tc adapter の実装 + 実 attach サンプル
- userspace simulator (`BPF_PROG_TEST_RUN` 経由 or 純 Go interpreter) — kernel 無しで unit test
- 必要なら `ScratchABI` / `StackBudget` の caps field 化 (host 別 register / stack offset) — premature 懸念があるので 2 つ目以上の host が出てから判断

## 進捗サマリ

**完了**:

```
P0-1  CI vimto             (255d9dd)
P0-2  IP リテラル predicate (766e8e8, 369d556, 02ba9c2, feat/p4_based_dsl)
P0-3  CHAIN_END 一般化      (befecd2, 64dff53)
P0-4  p4c CI 検証          (feat/p4_based_dsl: Dockerfile + cache)
A     可変長 header 対応    (feat/p4_based_dsl: parser machine + VAREXT/OPT)
B     aux header model      (feat/p4_based_dsl: PR-A〜PR-D + PR-B', dsl-internals.md §6)
P1-5  ソース位置統一        (d258272)
P1-6  --dsl-help            (6ad3b97)
P1-7  --list-protos         P1-6 で代替
P5-15 pkg/kunai/ 移動      (feat/p4_based_dsl: internal/dsl/ → pkg/kunai/)
P5-16 target 抽象化        (feat/p4_based_dsl: Capabilities + host/xdp + ABI 契約 + regression test)
```

**完了** (型システム関連):

```
F9    flow.* 削除           dead syntax を削除して parser/ast/ir/resolve からも完全除去
```

**完了 (型システム PR で対応済)**:

```
P2-8  field in              ✅ F7 で landed (整数 alternatives)
P2-9  field has             ✅ F6 bitwise & で superseded (`tcp.flags & 0x12 == 0x12`)
B-1   .exists bool atom     ✅ 型システム PR-2 で対応 (where 句直接記述)
F1-F13                       ✅ 上記 §F1-F13 を参照
```

**未着手 (需要次第)**:

```
P2-10 算術ネスト 4+
B-2   IPv4 options vocab    PR-D 枠組みで Router Alert 等を declare
B-3   aux field × literal   IPv4/IPv6/MAC/CIDR literal の aux access
B-4   option 内部 array     SACK.blocks / RR.addrs (Schema C)
P3-11 sanity self-disp     chain で sanity NIBBLE
P3-12 alt 異種 size        `(ipv4|ipv6)/tcp` を成立させる
P3-13 alt-of-alt
P4-14 flow state           BPF_MAP_TYPE_HASH 経由の flow tracking
```

P0 / P1 / P5 + §A / §B はすべて片付いた。残りは需要が出てから着手で良い水準。

## 中長期 (具体化はそのとき)

- **p4c とのインターオペ拡張**:
  - **kunai → p4c (既達)**: 自作 vocab 16 ファイルすべて `p4test --parse-only --Werror` 通過 (P0-4)。p4lite は P4-16 の strict subset として設計されており、`header` / `const` / `parser` (extract/select/accept/reject 含む) は full に対応。
  - **p4c → kunai (現状の限界)**: 任意の P4 file を p4lite で食えるのは「dsl が必要とする宣言だけが含まれるファイル」まで。`action` / `table` / `control` / `apply` / `extern` を含む実 dataplane プログラムは `lexer.go::rejectedKeywords` で明示 reject (詳細は `dsl-internals.md §5`)。dataplane `.p4` から header 定義と parser block だけを抽出する preprocessor、もしくは対応キーワードを silent skip するモードが、本格 P4 ecosystem との橋渡しに必要。
- **BTF auto-vocab**: kernel に load されている BPF プログラムの BTF から自動 vocab 生成
- **DSL→tcpdump ロスレス変換** (一部式): デバッグ時に「この DSL 式を tcpdump で書くと何か」を表示

これらは技術的に面白いが MVP の延長線にはない大物。要望ベースで考える。

## 参考

- 文法 (formal EBNF + 例文) — [`dsl-grammar.md`](./dsl-grammar.md)
- コード読解 — [`dsl-walkthrough.md`](./dsl-walkthrough.md)
- 利用者向けガイド — [`dsl-usage.md`](./dsl-usage.md)
- 開発経緯は git log を参照 (旧 `dsl-development-summary.md` / `plan_dsl.md` は本 followups と git 履歴に統合)
