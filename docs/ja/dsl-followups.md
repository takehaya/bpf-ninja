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
- `(本ブランチ)` IPv6 host / IPv6 CIDR / MAC で `!=` 対応 (multi-word match 用ラベル経路追加)

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

**完了内容** (本ブランチ):
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

**完了内容** (本ブランチの未コミット作業):

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

**追加で対応した項目** (本ブランチ):
- **kernel 6.1 BSWAP**: ✅ 解消。`asm.BSwap` (opcode `0xd7`、6.6+) を使っていた `predicate.go` / `where.go` を `asm.HostTo(asm.BE, ...)` (BPF_END family、5.x で動く) に置換。equality は constant 側を codegen 時に byte-swap して swap 命令を完全省略。**vimto kernel 6.1 で 35 chains 全 PASS** を確認
- **ESP terminal layer**: ✅ 完了。`pkg/kunai/protocols/esp.p4` 追加 — `eth/ipv4/esp` / `eth/ipv6/esp` で SPI/Sequence Number まで match できる (内側 encrypted は読めないので chain 終端)。dsltest E2E 追加 (`TestEthIPv{4,6}ESPMatch`)
- **SRv6 segment chain decomposition** (PR 2): 🔄 **採用見送り (rollback 対象)**。`srv6seg_h` を独立 chain protocol として切り出し、`eth/ipv6/srv6/srv6seg+/tcp` で書ける形を試作したが、**SRH segment list は SRH wrapper の中身であり外側の独立 layer ではない** という構造上の不整合が議論で明確化。aux header model (`srv6.segments[N]`) で再実装する方針に切り替え。本 PR で導入した `ChainCountSpec` (`<SELF>_<PARENT>_COUNT_FROM_<FIELD>`) は aux header stack の count source として再利用可能。詳細は dsl-internals.md §6 を参照
- **GTP-U ext header chain decomposition** (PR 3): 🔄 **採用見送り (rollback 対象)**。`gtpext.p4` を独立 chain protocol として切り出したが、PR 2 と同じ理由で aux header model (`gtp.exts[N]`) に切り替え。GTP ext は GTP wrapper の中身。本 PR の `*` / `?` quantifier silent-miss 問題 (NoCheck 親 dispatch との組合せ) も aux model なら parser block の state machine が gating を表現するので解消する

**(Y) aux header model の採択** (主要設計判断):
chain decomposition (PR 2/3) を試作する過程で、可変長構造には大きく **(A) stacked external headers** (= chain) と **(B/C/D) wrapper + aux headers** の 2 系統がある事実が明確化した。VLAN/MPLS/QinQ は (A)、SRv6 segment / GTP opt / GTP ext / TCP/IPv4 options は (B/C/D)。chain 機構で全部表現しようとすると wire 構造との対応が崩れる。aux header model (parser block の `out` 引数で aux を declare、state machine で gating 記述、DSL は `protocol.aux_name[.index][.field]` で access) に統一することで一貫性を確保。詳細な分類と実装指針は **`dsl-internals.md` §6 「可変長構造の分類と表現」** に集約。

**残課題 (低優先、別 PR で対応想定)**:
- **IPv6 ext + SRv6 Routing(43) 衝突**: 現状 scratch 512 で吸収。**fastpath JEq による verifier-narrowing を試行したが効果なし** — parser machine の done label に ext-walk path と fastpath path の両方が Ja で合流するため、verifier は両 path の R4 max を join して同じ広い bound を維持する (scratch 256 でも reject が再現)。fundamental には fastpath 専用の 別 done label + child dispatch 二重化が必要で、parser machine emit を大きく refactor する必要がある。scratch 512 (worst-case 320 B、余裕 192 B) で実用上は問題ないため defer
- **aux header predicate / access** (`gtp.opt.next_ext`, `srv6.segments[0].addr`, `tcp.options.MSS.value` 等): ✅ **完了** (PR-A〜PR-D + PR-B' で landing)。
  - PR-A: 単発 aux predicate + bracket form (`gtp[opt.next_ext == 0]` / `where gtp.opt.next_ext == 0`)
  - PR-B + PR-B': aux header stack の static / dynamic index access (`srv6.segments[0].addr`, `srv6.segments[srv6.last_entry].addr`)、IPv6 アドレス比較対応
  - PR-C: `any() / all()` 量化詞 (SRv6 segments を中心に、count guard 付き)
  - PR-D: TCP options walk codegen + parser block 経由の vocab declaration (`tcp.options.MSS.value == 1460` 他)
  - 残: `.exists` を bare bool atom として where parser に追加、IPv4 options vocab、CIDR/MAC literal の aux field 対応、option 内部 array (Phase 2 — SACK.blocks 等) はすべて future work

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

**完了内容** (本ブランチ):
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

**完了内容** (本ブランチ):

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

```
P0-1 CI vimto              ✅ 完了 (255d9dd)
P0-2 IP リテラル predicate  ✅ 完了 (766e8e8, 369d556, 02ba9c2, 本ブランチ)
P0-3 CHAIN_END 一般化       ✅ 完了 (befecd2, 64dff53)
P0-4 p4c CI 検証           ✅ 完了 (本ブランチ、Dockerfile + cache)
P1-5 ソース位置統一         ✅ 完了 (d258272)
P1-6 --dsl-help             ✅ 完了 (6ad3b97)
P1-7 --list-protos          ✅ P1-6 で代替
P2-8 field in              ⏳ 未着手
P2-9 field has             ⏳ 未着手
P2-10 算術ネスト 4+         ⏳ 未着手
P3-11 sanity self-disp     ⏳ 未着手
P3-12 alt 異種 size        ⏳ 未着手
P3-13 alt-of-alt           ⏳ 未着手
P4-14 flow state           ⏳ 未着手
P5-15 pkg/kunai/ 移動      ✅ 完了 (本ブランチ、internal/dsl/ → pkg/kunai/)
P5-16 target 抽象化         ✅ 完了 (本ブランチ、Capabilities API + host/xdp サブパッケージ + ABI 文書化 + regression test)
N0  PR2/3 rollback         ✅ 完了 (chain decomposition 撤回、aux model 採用)
PR-A 単発 aux predicate    ✅ 完了 (gtp.opt.next_ext, bracket + where 両形式)
PR-B aux header stack       ✅ 完了 (srv6.segments[N], gtp.exts[N] static + dynamic index)
PR-B' SRv6 segments E2E     ✅ 完了 (where literal compare で IPv6 aux field 対応)
PR-C any() / all()          ✅ 完了 (aux header stack 量化、count guard 付き)
PR-D TCP options walk       ✅ 完了 (tcp.options.MSS.value 等、option-walk codegen + parser block 宣言)
```

P0 / P1 / P5 すべて片付いた。残りは需要が出てから着手で良い水準。

## 中長期 (具体化はそのとき)

- p4c とのインターオペ: 標準 P4 ファイルを直接食えるようにする
- BTF auto-vocab: kernel に load されている BPF プログラムの BTF から自動 vocab 生成
- DSL→tcpdump ロスレス変換 (一部式): デバッグ時に「この DSL 式を tcpdump で書くと何か」を表示

これらは技術的に面白いが MVP の延長線にはない大物。要望ベースで考える。

## 参考

- 文法 (formal EBNF + 例文) — [`dsl-grammar.md`](./dsl-grammar.md)
- コード読解 — [`dsl-walkthrough.md`](./dsl-walkthrough.md)
- 利用者向けガイド — [`dsl-usage.md`](./dsl-usage.md)
- 開発経緯は git log を参照 (旧 `dsl-development-summary.md` / `plan_dsl.md` は本 followups と git 履歴に統合)
