# Loader の ELF から map の型を補う

loader が BTF なしで map を作成しても、loader の ELF に key と value の型が残っていれば、`inject-run` の rule で hook の型を補完できる。
単一の `map` を明示する rule に、`map_btf.elf` と必須の `map_btf.sha256` を指定する。

```json
[
  {
    "program": "ingress",
    "map": "sessions",
    "hook": "observe",
    "stack_lowest_offset": -4,
    "map_btf": {
      "elf": "/path/to/loader-generated.o",
      "sha256": "REPLACE_WITH_64_HEXADECIMAL_DIGITS"
    }
  }
]
```

`map_btf` を指定する場合、`elf` と `sha256` は必須で、`key_type` と `value_type` は任意だ。
`map_btf` の省略と `null` は補完なしとして扱い、空オブジェクトと内部の未知キーは拒否する。

`sha256sum /path/to/loader-generated.o` で得た64桁のハッシュに置き換える。
大文字と小文字は区別しない。
`stack_lowest_offset` は実際の program の stack access を監査して指定する。
相対パスは supervisor の作業ディレクトリを基準とし、対象 program のロードごとに supervisor の filesystem から読み込む。
ハッシュを照合した同じ byte 列を ELF として解析する。

補完するのは生成 hook の BTF だ。
補完型は typedef や修飾子の内側も data kind に限り、spin lock、timer、kptr などの特殊 field を含む型と、特殊な pointer ABI を持つ `xdp_md`、`__sk_buff`、`bpf_dynptr` は拒否する。
この制約により、補完によって変わるのは hook metadata のみで、生成命令、pointer の信頼性、value copy の判断は変わらない。
ELF の命令や map をロードせず、live map の内容も BTF も変更しない。
生成 program の BTF に型を追加することで、`--list-params --members` と `--arg-filter` から member を利用できる。

live map の存在と既存 BTF の有無を確認してから、ELF をロードごとに読み込む。
ELF は64 MiB 以下の通常ファイルに限り、読み込み量にも上限を設ける。
起動時の事前読み込みやキャッシュは行わない。

## 照合と拒否条件

`map` は15 bytes 以下の kernel 名を指定し、`auto` や `dispatch` とは併用できない。
補完は、型付き lookup hook が扱える通常メモリの map kind（Hash、Array、PerCPUHash、PerCPUArray、LRUHash、LRUCPUHash、LPMTrie）に限る。
他の map kind と update/delete/push/pop/peek 操作は拒否する。
`ops: ["lookup:miss"]` の hook が渡すのは key だけだが、map 定義全体を検査するため value 型も必要になる。
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

型ではなくサイズだけを宣言する legacy map には、任意の `map_btf.key_type` と `map_btf.value_type` で、同じ ELF の BTF にある型名を指定できる。
たとえば `map_btf` 内の `"key_type": "u32", "value_type": "record"` は、各名前がサイズを持つ layout を一意に指す場合に利用できる。
型名指定はサイズだけの側を埋める fill-only とし、ELF の map 定義が既に型を持つ側は、同じ型を指す名前だけを受け入れる。
別の型を指定した場合は、同じサイズでも拒否する。
型名は完全一致で照合するため、一意な `record` は `record___old` や `record___other` と混在していても選択するが、これらの flavor しかなければ `record` の指定を拒否する。
struct の名前に C の `struct ` prefix は付けない。
前方宣言などサイズのない候補は除外し、同じ underlying type を指す typedef は一つの layout として扱う。
同名でも異なる layout や struct/union の衝突は曖昧として拒否する。
指定を省略した側は ELF の map 定義の型を使うため、key と value の型を持たない定義には両方の型名が必要になる。
ソースから型を推測したり、存在しない型を生成したりはしない。

サイズ一致だけでは、選んだ型の意味、個々の member の byte order、loader relocation 後の layout の一致を証明できない。
同じサイズで member の順序が異なる型は、これらの検査では検出できない。
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
