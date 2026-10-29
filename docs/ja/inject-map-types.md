# Loader の ELF から map の型を補う

loader が BTF なしで map を作成しても、loader の ELF に key と value の型が残っていれば、`inject-run` の rule で hook の型を補完できる。
単一の `map` を明示する rule に、`map_types_elf` と必須の `map_types_sha256` を指定する。

```json
[
  {
    "program": "ingress",
    "map": "sessions",
    "hook": "observe",
    "stack_lowest_offset": -4,
    "map_types_elf": "/path/to/loader-generated.o",
    "map_types_sha256": "REPLACE_WITH_64_HEXADECIMAL_DIGITS"
  }
]
```

`sha256sum /path/to/loader-generated.o` で得た64桁のハッシュに置き換える。
大文字と小文字は区別しない。
`stack_lowest_offset` は実際の program の stack access を監査して指定する。
相対パスは supervisor の作業ディレクトリを基準とし、対象 program のロードごとに supervisor の filesystem から読み込む。
ハッシュを照合した同じ byte 列を ELF として解析する。

補完するのは生成 hook の BTF だ。
ELF の命令や map をロードせず、live map の内容も BTF も変更しない。
生成 program の BTF に型を追加することで、`--list-params --members` と `--arg-filter` から member を利用できる。

## 照合と拒否条件

`map` は15 bytes 以下の kernel 名を指定し、`auto` とは併用できない。
ELF map 名を15 bytes に切り詰めたときに一致する定義と、対象 program が参照する同名の live map が、それぞれ一意に存在する必要がある。
map type、key size、value size、flags は完全一致が必要で、補完する BTF の key と value もそれぞれ対応するサイズでなければならない。

| 条件 | 結果 |
|---|---|
| ELF を読めない、解析できない、byte order が異なる | 注入を拒否する |
| SHA-256 が不一致、または設定が64桁の16進数でない | 注入または設定を拒否する |
| ELF または live program に map がない、同名候補が複数ある | 注入を拒否する |
| map type、key/value size、flags が不一致 | 注入を拒否する |
| 必要な BTF 型がない、指定名が曖昧、BTF サイズが不一致 | 注入を拒否する |
| live map に既存 BTF がある | 型を置き換えず、注入を拒否する |

既存 value が匿名 byte 配列であっても、live map に BTF があれば補完対象にしない。
エラー時は通常の `inject-run` と同じ方針に従う。
`--fail-closed` がなければ元の program がそのままロードされ得るため、補完を必須にする場合はこの flag を指定する。

## Legacy map の型名指定

型ではなくサイズだけを宣言する legacy map には、任意の `map_key_type` と `map_value_type` で、同じ ELF の BTF にある型名を指定できる。
たとえば `"map_key_type": "__u32", "map_value_type": "real_definition"` は、各名前の型が一意に存在するときだけ利用できる。
struct の名前に C の `struct ` prefix は付けない。
指定を省略した側は ELF の map 定義の型を使うため、key と value の型を持たない定義には両方の型名が必要になる。
ソースから型を推測したり、存在しない型を生成したりはしない。

サイズ一致だけでは、選んだ型の意味、個々の member の byte order、loader relocation 後の layout の一致を証明できない。
CO-RE を含む loader 側の調整も考慮し、実 map に合う ELF と型を選ぶ責任は利用者にある。
ハッシュは選んだ artifact を固定するものであり、実 map との由来の一致を証明するものではない。

## Member の表示と capture

```sh
bpf-ninja inject-run --fail-closed --config rules.json --hooks-json hooks.json -- ./loader
bpf-ninja -p "$PROG_ID" --func observe --list-params --members
bpf-ninja -p "$PROG_ID" --func observe --arg-filter 'value->identity==7' -w selected.pcapng
```

`PROG_ID` には `hooks.json` に記録された program ID を使う。
loader を実行したまま、別の terminal で member の表示と capture を行う。
型を補完しない場合、BTF のない map の hook 引数は従来どおり opaque な byte 配列となり、元の struct member に対する条件は失敗する。
[CLI 統合テスト](../../scripts/test/map-types.py)は、BTF なしの map を作る loader で補完の有無を比較し、選択された packet bytes と既存 BTF の拒否を検証する。
[英語の inject-run guide](../en/inject-run.md#map-types-from-a-loader-elf)にも同じ設定を記載している。
