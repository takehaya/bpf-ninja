# CLAUDE.md

このファイルは、Claude Code (claude.ai/code) がこのリポジトリのコードを扱うときの指針をまとめたものです。
必ず日本語で回答してね。
## プロジェクト概要

`xdp-ninja` は **non-invasive な XDP パケットキャプチャツール**。BPF trampoline (fentry/fexit) を使って *既にロード済みの* XDP プログラムに動的にアタッチする (元プログラムは無改変)。tcpdump 風フィルタ (cbpfc 経由) または `--dsl` チェイン (組み込みの `kunai` ライブラリ経由) を in-kernel eBPF にコンパイルし、マッチしたパケットだけを pcap-ng としてユーザー空間に転送できる。

リポジトリは Go module 1 個 (`go 1.25.5`、module `github.com/takehaya/xdp-ninja`)。バイナリ 1 個 (`cmd/xdp-ninja`) と、自己完結したサブライブラリ `pkg/kunai` (DSL → eBPF コンパイラ) を出荷する。

## よく使うコマンド

```bash
make build              # go build -o xdp-ninja ./cmd/xdp-ninja/
make test               # ユニットテスト (go test ./...) — root 不要
make test-bpf           # BPF verifier load テスト (sudo + clang)
make test-integration   # veth + dummy XDP の end-to-end (sudo + clang + tcpdump)
make test-all           # 上記 3 つ全部
make lint               # 全ファイル対象の lefthook pre-commit (go vet, golangci-lint, yamllint, ...)
make p4c-check          # `.p4` vocab を p4c で検証 (docker 必須)
```

単一の Go test を流す場合:

```bash
go test ./pkg/kunai/codegen -run TestSomething -v
```

特定カーネルで BPF verifier テストを流す場合は [vimto](https://github.com/lmb/vimto) + QEMU を使う (CI matrix は 6.1 / 6.6 / 6.12 / 6.18 / 7.0):

```bash
vimto -kernel :6.6 exec -- go test -v -count 1 -timeout 5m ./internal/program/ -run TestBpf
```

`make test-bpf` は `PATH/HOME/GOPATH/GOMODCACHE` を保ったまま `sudo` を呼ぶ。手動で同じテストを走らせるときも、その環境変数の保持を真似ること。

## アーキテクチャ

CLI は薄い配線層で、本質的なロジックは下記 2 つのツリーに集中している。

### `internal/` — host application

`cmd/xdp-ninja/main.go` で 1 回ずつ実行されるパイプライン:

1. `internal/attach` — ターゲット XDP プログラムを interface (`-i` → netlink lookup) または BPF program ID (`-p`) から特定し、BTF 名でエントリ関数 (または `--func` で指定されたサブ関数) を解決する。
2. `internal/filter` — `--func` と組み合わせる `--arg-filter` 式 (関数引数に対する predicate) を parse する。
3. `internal/program` — **コア部**。実行時に tracing program を組み立てる。`LoadEntry` / `LoadExit` (どちらも `loadProbe` を呼ぶ) は `ctx->data` / `ctx->data_end` をロードし、コンパイル済みフィルタ (tcpdump 構文なら cbpfc、`--dsl` なら `kunai.Compile`) を inline し、パケットスライスを per-CPU scratch map にコピーして perf-event ring に emit する `asm.Instructions` 列を構築する。`kunai` の host adapter は `pkg/kunai/host/xdp` (`--mode exit` のときは `xdphost.FexitCapabilities()` を渡す)。
4. `internal/capture` — ユーザー空間で perf ring をポンプする。
5. `internal/output` — pcap-ng を stdout または `-w` のファイルに書き出す。

`mode=entry` と `mode=exit` は別々の fentry/fexit attach type として配線されている。両者は ABI が違う (exit は XDP の return action が見えるが entry は見えない) ので、`kunai.Capabilities` に host 側から差し込む `ActionFetcher` がある。

### `pkg/kunai/` — DSL → eBPF コンパイラ (自己完結したサブライブラリ)

公開 API は意図的に 1 関数のみ: `kunai.Compile(expr, caps codegen.Capabilities) (codegen.Output, error)`。パイプライン:

```
expr → lexer → parser (AST) → resolve (vocab 解決済 IR) → codegen → asm.Instructions
```

サブパッケージマップ:

- `lexer/` — 手書きの tokenizer。位置付き token を返す。エラーは `*lexer.SyntaxError`。
- `parser/` — 再帰下降 parser。文法カテゴリごとに 1 ファイル (`layer.go`, `predicate.go`, `where.go`, `capture.go`)。
- `ast/` — AST ノード型と `Kind` enum。
- `vocab/` — `.p4` プロトコル定義をロード。`vocab/p4lite/` は手書きの **P4-16 strict subset** parser (`header` / `const` / `parser` block のみ。`action` / `table` / `control` / `apply` / `extern` は無し)。`protocols/` 配下の `.p4` は `p4c --parse-only` で通る必要がある (CI が `make p4c-check` でゲート)。
- `protocols/*.p4` — `//go:embed` で埋め込み (`protocols/embed.go`)。16+ プロトコル (eth, vlan, qinq, mpls, ipv4/6, tcp, udp, icmp/6, gre, vxlan, geneve, gtp, srv6, …)。dispatch 用定数の命名規約は `vocab/loader.go::classifyConsts` の regex 群で強制される。
- `dslvocab/` — bundled vocab の `sync.Once` cache。`Compile` 呼び出し間で再利用される。
- `resolve/` — layer 名 / field 参照を具体的な `*vocab.ProtocolSpec` にバインド。`*resolve.Error` (syntax error 型のエイリアス) を出すので位置情報が end-to-end で保持される。
- `ir/` — vocab 解決済の中間表現。codegen が消費する。
- `codegen/` — IR を `cilium/ebpf` の `asm.Instructions` に下ろす。コンパイルパイプラインと ABI は `codegen.go` の package doc 参照。`KunaiStackTop` が host との stack offset 契約。可変長 quantifier (`+`, `*`, `{n,m>4}`) と parser-machine の self-loop は bpf2bpf subprogram への `bpf_loop` 呼び出しに落ちる (subprogram 群は `Output.Callbacks` で返る) — **Linux 5.17+ 必須**。Predicate codegen は `BSWAP` 命令 (`0xd7`、6.6+) を避け、`BPF_END` byte-swap を使うことで下限を 5.17 に維持している。quantifier も parser-machine self-loop も無いチェインなら、もっと古いカーネルでも動く。
- `host/xdp/` — XDP 専用の `Capabilities` / `ActionFetcher` (例: fexit の `where action == XDP_DROP` 用に R3 へ XDP return code をロードする方法)。tc / userspace など他の host を増やすときは `host/<name>/` という兄弟パッケージを追加する。
- `dsltest/` — gopacket ベースのパケットレベルハーネス (experimental、1.0 までに breaking change の可能性あり)。

kunai の出力は **target-agnostic** — R0 (start) / R1 (end) で指される連続パケットウィンドウと作業用レジスタがあることだけを前提にしている。host 側はそれに自身の prologue (attach point の context からそのポインタを load する) と末尾の return を被せる。

### プロトコルの追加方法

`<name>.p4` を `pkg/kunai/protocols/` に置く。dispatch 定数の命名規約は startup 時に `pkg/kunai/vocab/loader.go` の regex (`classifyConsts`, `re*`) で強制される — 違反したファイルは reject される。`make p4c-check` で `p4c` が今でも parse できるか確認する。

## Convention と注意点

- コミットメッセージは Conventional Commits (`feat(scope):`、`fix:` など) — lefthook の `commit-msg` で強制。
- Lint は `go vet` + `golangci-lint` (`.golangci.yaml` に従って errcheck / govet / staticcheck) + `yamllint` + JSON 妥当性 + `*.{c,h}` への clang-format。
- 統合テスト用の事前ビルド済 XDP scratch program は `scripts/test/*.o`。`.c` ソースは隣にある。
- `host/` 境界は荷重がかかる場所 — XDP 固有の前提を `kunai` core に持ち込まない。新しい host adapter は `pkg/kunai/host/<name>/` に置く。`codegen/` には置かない。
- `kunai` の公開面 (`pkg/kunai/README.md` に従う) は **`kunai.Compile`、`codegen.{Capabilities,ActionFetcher,Output,CaptureInfo}`、`host/xdp` adapter、列挙されたエラー型のみ**。サブパッケージ内部は 1.0 までに動く可能性あり — 意図せず公開面を広げないこと。

## ドキュメント (日本語) のマップ

DSL の設計 / 内部ドキュメントは `docs/ja/` に集約。

- index: `docs/ja/dsl-overview.md`
- formal grammar (filter 式 + p4lite の EBNF): `docs/ja/dsl-grammar.md`
- 言語仕様 (Part I 型システム + Part II 抽象構文 / typing rule / 操作的意味論): `docs/ja/dsl-types.md`
- internals (アーキテクチャ / パッケージ別ツアー / コードリーディングマップ / codegen ABI / vocab 著者ガイド / P4-16 互換性 / レビューチェックリスト): `docs/ja/dsl-internals.md`
- ユーザー向け CLI ガイド: `docs/ja/dsl-usage.md`
- 残課題リスト: `docs/ja/dsl-followups.md`
- ベンチ方法論: `docs/ja/dsl-benchmark.md`

<!-- OCR:START -->
## Open Code Review Instructions

These instructions are for AI assistants handling code review in this project.

Always open `.ocr/skills/SKILL.md` when the request:
- Asks for code review, PR review, or feedback on changes
- Mentions "review my code" or similar phrases
- Wants multi-perspective analysis of code quality
- Asks to map, organize, or navigate a large changeset

Use `.ocr/skills/SKILL.md` to learn:
- How to run the 8-phase review workflow
- How to generate a Code Review Map for large changesets
- Available reviewer personas and their focus areas
- Session management and output format

Keep this managed block so `ocr init` can refresh the instructions.

<!-- OCR:END -->
