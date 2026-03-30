# TODO

## パフォーマンス最適化

- [ ] per-CPU goroutine での並列読み出し + CPU別pcapファイル出力 + マージソート
  - 現在は epoll ベースの単一 reader で全CPUをまとめて読んでいる
  - 高パケットレート (数Mpps) で `lost samples` が発生する場合に検討
  - per-CPU buffer サイズ増加 (`-b` オプション) を先に試すこと
  - マージは `mergecap` (Wireshark) で可能

- [ ] perf buffer サイズの自動チューニング or CLIオプション化
  - 現在は固定 256KB/CPU

- [ ] サンプリングモード (`--sample N`)
  - N パケットに1個だけキャプチャ
  - per-CPU カウンタで即 return することで 100GbE 環境でのオーバーヘッドを軽減
  - トランポリン起動 (~30ns) は消せないが、フル処理 (~170ns) を回避可能

## 既知の制限

- [ ] tail call 先プログラムへの fentry/fexit アタッチが動作しない
  - JIT が tail call 時にプロローグをスキップするため trampoline が発火しない
  - `__noinline` サブ関数への fentry も tail call 経由では発火しない（検証済み）
  - 詳細: [docs/ja/tailcall-trampoline-limitation.md](tailcall-trampoline-limitation.md)
  - 対処法:
    - `--wrap` モード: prog_array の value を wrapper に書き換えて leaf の前に挟む（設計済み、未実装）
      - entry 相当のみ。exit は取れない（tail call は制御が戻らないため）
      - 設計: [docs/ja/wrap-mode-design.md](wrap-mode-design.md)
    - カーネル側の対応を待つ（該当パッチは現時点で存在しない）

- [ ] フィルタ実行時の scratch buffer コピーオーバーヘッド (~80ns)
  - verifier が xdp_buff->data 経由のメモリロードを scalar として拒否するため、
    per-CPU array (PTR_TO_MAP_VALUE) にコピーしてからフィルタを実行している
  - xdp_buff の構造体フィールド読み出し (data, data_end) は直接アクセス可能（検証済み）
  - パケットデータの dereference は不可（検証済み: `R0 invalid mem access 'scalar'`）
  - 対策案: 必要なフィールドだけ bpf_probe_read_kernel で読む独自フィルタ生成

## 機能

- [x] `-p <prog-id>` でプログラム ID から直接アタッチ
- [x] 統合テストの自動化 (`scripts/test/run_tests.sh`)

- [ ] pcapng の Interface Description Block に XDP プログラム情報を記録
  - プログラム名、ID、mode (entry/exit) などをメタデータとして埋め込む

- [ ] fexit 時の XDP action を pcapng のコメントやカスタムブロックに記録
  - 現在は metadata に含まれるが pcapng 出力には反映されていない

## CI

- [ ] 統合テストを vimto/CI で実行可能にする
  - ci-kernels VM に veth モジュールがないため現在はローカル実行のみ
  - veth 入りカーネルイメージの作成 or self-hosted runner が必要
