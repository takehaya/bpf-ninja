# Discovering and filtering pointer members

Use `--arg-filter` when a BPF function receives a struct or union pointer and the value needed to select calls lives inside that object.
For example, a UPF-style classifier may receive a query containing an IMSI and a packet detection rule ID.
`--arg-echo` prints selected values before committing to a capture filter.
These options work with `--mode entry` and `--mode exit`.

The target program must already be loaded with BTF, which describes its functions and types.
Use `-p <ID>` to select it and `--func classify` to select a function that survives compilation as a BPF subfunction.
The first context argument is excluded from parameter discovery.
An entry with supported parameters, such as an EXT replacement, can omit `--func`.
If the entry has only a context argument, select a subfunction with `--func`.
See the [README](../../README.md#attaching-to-subfunctions-entryexit-only) for attachment requirements.

## Discover members before writing a filter

Start with the program's function and parameter lists:

```sh
sudo bpf-ninja -p <ID> --list-funcs
sudo bpf-ninja -p <ID> --func classify --list-params
sudo bpf-ninja -p <ID> --func classify --list-params --members
```

The member view adds a tree for every listed struct/union pointer parameter.
Here is illustrative output for a query with an embedded target:

```text
Filterable parameters for classify (id=42):
  q: struct query * (arg index 1)
    q->imsi  u64  off 0  size 8  unsigned  filterable
    q->target  struct target  off 8  size 4  (not filterable: final member must be an integer or enum, got *btf.Struct)
      q->target.pdr_id  __u32  off 8  size 4  unsigned  filterable
    q->flags  __u32:3  off 12  size 4  unsigned  (not filterable: bitfield member "flags" is not supported)
```

Copy the expression at the start of a member row into `--arg-filter` or the positional arguments after `--arg-echo`.
`off` is the byte offset from `q`, including all enclosing members; it is not relative to the preceding tree row.
`size` is the BTF type's storage size in bytes, even for a bitfield, whose bit width follows `:`.
A non-byte-aligned member also shows the remaining bit offset.
Typedef names such as `__u32` are preserved, and integers and enums show signedness.
A struct/union row is not itself filterable, but its children can be.

`filterable` means the expression passes the same resolver used by filtering and echo.
It does not promise that a pointer is readable at runtime or that its field contains meaningful data on every call.
Anonymous struct/union members appear under their promoted names, with no anonymous component to type.
If multiple members expose the same name, their rows are marked ambiguous and cannot be used.
The rows keep each physical member's type and offset so the collision is visible.

The default depth is 3 named member levels; `q->target.pdr_id` is level 2.
Anonymous containers do not consume a level.
Use `--members-depth 1` for a compact first look, or increase it up to 32:

```sh
sudo bpf-ninja -p <ID> --func classify --list-params --members --members-depth 5
```

Omitted branches have an explicit marker.
Traversal also stops at cycles, after 32 anonymous nesting levels, and after 4096 displayed member rows per parameter.
The depth option controls discovery only; it does not change expression resolution.
`--members` requires `--list-params`, and `--members-depth` requires both.
Do not combine this view with `--list-funcs`, `--list-progs`, or `--dump-asm`.
Text stays on stderr, as with the ordinary parameter list.

## Use JSON for scripts

Add `--json` for the same information on stdout:

```sh
sudo bpf-ninja -p <ID> --func classify --list-params --members --json > params.json
jq '.. | objects | select(.filterable? == true) | .expression' params.json
```

The existing top-level array, `func`, `id`, and parameter fields remain unchanged.
With `--members`, pointer parameters gain `type` and a `members` array, including an empty array when the pointee has no members.
An individual member looks like this:

```json
{
  "expression": "q->target.pdr_id",
  "type": "__u32",
  "offset": 8,
  "size": 4,
  "signed": false,
  "filterable": true
}
```

Nested aggregates have their own `members` arrays.
Rejected expressions include `reason`; integers and enums include `signed`, even when false.
`bitfield_size` is a width in bits, while `bit_offset` is the remaining 1–7 bits beyond the byte `offset`; these fields are omitted when zero.
`size` is null if BTF cannot determine the type's storage size.
`members_truncated` on a parameter or member explains omitted children.
Without `--members`, the previous JSON shape is preserved.

## Write expressions and comparisons

Use exactly one `->` to follow the parameter pointer, then `.` for named embedded structs or unions.
Quote expressions so the shell does not interpret `>` as redirection.
The argument filter syntax is separate from the packet DSL:

| Expression | Meaning |
|---|---|
| `q->imsi=262010000000001` | Equal to the numeric value |
| `q->target.pdr_id>=3` | Greater than or equal to 3 |
| `q->target.pdr_id<=9` | Less than or equal to 9 |
| `q->target.pdr_id=3..9` | Inclusive range |

Values may be decimal or hexadecimal with `0x`; signed members also accept negative decimal values.
Use numeric values for enums, not enumerator names.
Values must fit the member's width and signedness.
Repeat `--arg-filter` to require all conditions.
`!=`, strict `<`/`>`, array indexing, and a second `->` are not supported.

Echo takes member expressions as positional arguments, without comparison operators:

```sh
sudo bpf-ninja -p <ID> --func classify --arg-echo -c 10 'q->imsi' 'q->target.pdr_id'
```

Bare `--arg-echo` prints integer parameters only; it does not automatically expand pointer members.
Echo supports one target and one mode, and can be gated by ordinary `--arg-filter` expressions.

## How BTF resolution and reads work

bpf-ninja reads the target program's BTF and locates the selected function's prototype.
It finds the parameter's argument index, unwraps typedefs and qualifiers to identify its pointer target, and walks struct/union members by name.
Anonymous members promote names into the enclosing scope.
Member offsets accumulate from the original pointee; the final integer or enum supplies the width and signedness.
This uses the loaded program's types, not a guessed C layout or a same-named kernel type.

The generated entry/exit probe retrieves the argument pointer, checks for null, adds the resolved offset, and reads the member with the kernel-read helper `bpf_probe_read_kernel`.
It reads exactly 1, 2, 4, or 8 bytes, then sign-extends signed values or zero-extends unsigned values for comparisons and echo.
No additional probe is attached for a member read.
If argument retrieval or the kernel read fails, or the pointer is null, the call fails the argument filter.
For echo, a failed read suppresses the entire record; it is not reported as a zero value.
These checks do not modify the target program's return value or drop its packet.

Supported leaves are byte-aligned integers or enums of 1, 2, 4, or 8 bytes, with no bitfield on the selected path.
Bitfields, arrays, whole structs/unions, and pointer-valued leaves are rejected.
A pointer member is shown but never followed, including a pointer back to the same struct.
Union discovery describes layout; it does not identify which alternative the caller currently uses.
Ambiguous promoted names and offsets beyond the resolver's supported range are also rejected.
Set references (`@NAME`) and `key(field=arg:param)` mappings cannot select members; `--arg-echo` does not support sets.

## Check an IMSI before filtering calls

Consider this simplified UPF-style function signature and query layout:

```c
struct target { __u32 pdr_id; };
struct query {
    __u64 imsi;
    struct target target;
    __u32 flags : 3;
};

__attribute__((noinline))
int classify(struct xdp_md *ctx, struct query *q);
```

First discover `q->imsi`, then echo it at the capture point where the filter will run:

```sh
sudo bpf-ninja -p <ID> --func classify --list-params --members
sudo bpf-ninja -p <ID> --func classify --mode entry --arg-echo -c 10 'q->imsi'
sudo bpf-ninja -p <ID> --func classify --mode entry \
  --arg-filter 'q->imsi=262010000000001' -w subscriber.pcap
```

At entry, `q->imsi` is whatever the caller placed in the object before the call.
A reused query may contain a previous packet's IMSI, and some paths may never fill it.
A member being filterable does not mean the caller sets it on every path.
Check echo against traffic and the caller's assignments before trusting the filter; receiving no echo records can also mean read failures or no calls, rather than an IMSI of zero.

If `classify` fills `imsi` inside its body, prefer `--mode exit` or a different function reached after initialization.
Verify again at that point before using the filter:

```sh
sudo bpf-ninja -p <ID> --func classify --mode exit --arg-echo -c 10 'q->imsi'
sudo bpf-ninja -p <ID> --func classify --mode exit \
  --arg-filter 'q->imsi=262010000000001' -w subscriber-exit.pcap
```

Exit mode reads the object at exit; it is not an entry snapshot.
It still requires a readable pointer and a field initialized on the paths of interest.

There is a separate compiler pitfall: `clang -O2` can drop an unused argument from the calling convention while BTF still lists it.
The listing can therefore look correct while the probe observes a stale register value.
If a capture-point argument would otherwise be unused, include [`keep_args.h`](../../include/keep_args.h) and put `KEEP_ARGS(ctx, q);` in the function body.
This preserves the arguments without adding instructions, but does not initialize `q->imsi`.
Confirm that the function still appears in `--list-funcs` and verify the observed values with echo.

[日本語版](../ja/arg-member-filter.md)
