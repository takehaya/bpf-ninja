# Changelog

## [0.20.0](https://github.com/takehaya/bpf-ninja/compare/v0.19.1...v0.20.0) (2026-07-10)


### 🎉 Features

* **setmap:** add `set resize` to change a pinned set's capacity ([#80](https://github.com/takehaya/bpf-ninja/issues/80)) ([37e5ee9](https://github.com/takehaya/bpf-ninja/commit/37e5ee9b32b5b5e3af477d492fc9afc088f32fe2))

## [0.19.1](https://github.com/takehaya/bpf-ninja/compare/v0.19.0...v0.19.1) (2026-07-06)


### 🐛 Bug Fixes

* **cli:** stop comma-splitting root slice flags so --set key(...) works ([#74](https://github.com/takehaya/bpf-ninja/issues/74)) ([be2d194](https://github.com/takehaya/bpf-ninja/commit/be2d194e87e1d98e443511d56a4c073b13c9f3b6))

## [0.19.0](https://github.com/takehaya/bpf-ninja/compare/v0.18.0...v0.19.0) (2026-07-04)


### 🎉 Features

* **cli:** --prog-name, --json for list-*, and combined list-progs/list-funcs ([#71](https://github.com/takehaya/bpf-ninja/issues/71)) ([16a7825](https://github.com/takehaya/bpf-ninja/commit/16a782564aa33331ca69f2903b42f5ea2814a5e5))
* split capture into per-tag pcaps with --split-by-tag ([#72](https://github.com/takehaya/bpf-ninja/issues/72)) ([84c36e2](https://github.com/takehaya/bpf-ninja/commit/84c36e28c978c7ee26f776fdeb66f0557f317062))


### 📝 Documentation

* **usage:** hand-test walkthrough for the set map CLI ([#69](https://github.com/takehaya/bpf-ninja/issues/69)) ([6b5407d](https://github.com/takehaya/bpf-ninja/commit/6b5407dcb340541fcf76007aea57526e02b9e855))

## [0.18.0](https://github.com/takehaya/bpf-ninja/compare/v0.17.0...v0.18.0) (2026-07-04)


### 🎉 Features

* 128-bit (IPv6/SRv6 SID) packet-field set matching (ipv6[dst in [@sids](https://github.com/sids)]) ([#67](https://github.com/takehaya/bpf-ninja/issues/67)) ([bd718d5](https://github.com/takehaya/bpf-ninja/commit/bd718d5ceb852cee26ec22d3fc0e05ecf5cf8b59))
* static [N] aux-stack index in bracket predicates (srv6[segments[0].addr in [@sids](https://github.com/sids)]) ([#68](https://github.com/takehaya/bpf-ninja/issues/68)) ([a73346a](https://github.com/takehaya/bpf-ninja/commit/a73346ad1bc510035afc4159a4f4e6ce73eb9b6e))


### 🐛 Bug Fixes

* **kunai:** clamp parser-machine self-loop cursor (gtp entry-mode on kernels &lt;=6.6) ([#65](https://github.com/takehaya/bpf-ninja/issues/65)) ([81c7f35](https://github.com/takehaya/bpf-ninja/commit/81c7f35f5c36ea90576457c8d4c166cea046cc4a))

## [0.17.0](https://github.com/takehaya/bpf-ninja/compare/v0.16.0...v0.17.0) (2026-07-04)


### 🎉 Features

* **kunai:** DSL packet-field set matching (layer[field in @NAME]) ([#61](https://github.com/takehaya/bpf-ninja/issues/61)) ([e2dd172](https://github.com/takehaya/bpf-ninja/commit/e2dd172b2d7055982f83cdc6648008148451ff1d))


### 📝 Documentation

* naturalize the internal-reference Japanese docs (natural-ja) ([#63](https://github.com/takehaya/bpf-ninja/issues/63)) ([8ac3ffd](https://github.com/takehaya/bpf-ninja/commit/8ac3ffdf90d934ffa71a1b0d515c7627723a2dc8))
* naturalize the user-facing Japanese guides (natural-ja) ([#62](https://github.com/takehaya/bpf-ninja/issues/62)) ([98633e4](https://github.com/takehaya/bpf-ninja/commit/98633e4908793315e26e4dfa4dec782dec340c8f))

## [0.16.0](https://github.com/takehaya/bpf-ninja/compare/v0.15.0...v0.16.0) (2026-07-03)


### 🎉 Features

* **filter:** pinned-map match sets (--set / @NAME + set subcommand) ([#58](https://github.com/takehaya/bpf-ninja/issues/58)) ([7de0eaa](https://github.com/takehaya/bpf-ninja/commit/7de0eaa490cbbcaa142f5cee3fd979be3a4aad38))

## [0.15.0](https://github.com/takehaya/bpf-ninja/compare/v0.14.0...v0.15.0) (2026-07-03)


### 🎉 Features

* **attach:** attach multiple (program, func) pairs in one run ([#56](https://github.com/takehaya/bpf-ninja/issues/56)) ([61aca63](https://github.com/takehaya/bpf-ninja/commit/61aca63deb864f26a2d0d2fc41b576d39c646747))

## [0.14.0](https://github.com/takehaya/bpf-ninja/compare/v0.13.1...v0.14.0) (2026-07-02)


### 🎉 Features

* **capture:** merge per-CPU shards into a single pcap-ng file ([#53](https://github.com/takehaya/bpf-ninja/issues/53)) ([e40929c](https://github.com/takehaya/bpf-ninja/commit/e40929c485364f714bcccd78b2c139492461df60))

## [0.13.1](https://github.com/takehaya/bpf-ninja/compare/v0.13.0...v0.13.1) (2026-07-01)


### 🐛 Bug Fixes

* **capture:** round per-shard ringbuf size to a power of two ([#51](https://github.com/takehaya/bpf-ninja/issues/51)) ([7bf1c3d](https://github.com/takehaya/bpf-ninja/commit/7bf1c3d09a9fccd2775f582a88a0ad6ffa01cdd8))

## [0.13.0](https://github.com/takehaya/bpf-ninja/compare/v0.12.0...v0.13.0) (2026-07-01)


### 🎉 Features

* **attach:** follow redirect/tail-call chains transitively in --list-progs ([#49](https://github.com/takehaya/bpf-ninja/issues/49)) ([b4e2f2a](https://github.com/takehaya/bpf-ninja/commit/b4e2f2a8afc452d2d2d3c27adca640e212eedc92))

## [0.12.0](https://github.com/takehaya/bpf-ninja/compare/v0.11.1...v0.12.0) (2026-07-01)


### 🎉 Features

* **attach:** list CPUMAP/DEVMAP redirect targets in --list-progs ([#47](https://github.com/takehaya/bpf-ninja/issues/47)) ([c5a7595](https://github.com/takehaya/bpf-ninja/commit/c5a75958242ef7e7500cecf02da708c1b164682d))

## [0.11.1](https://github.com/takehaya/bpf-ninja/compare/v0.11.0...v0.11.1) (2026-06-29)


### 🐛 Bug Fixes

* **capture:** copy packet payload into a per-shard arena to stop batch aliasing ([#43](https://github.com/takehaya/bpf-ninja/issues/43)) ([24463fa](https://github.com/takehaya/bpf-ninja/commit/24463fa83805e3fa90440b40563a662d8b9c5bd1))


### 📝 Documentation

* **todo:** drop resolved items from the backlog ([#46](https://github.com/takehaya/bpf-ninja/issues/46)) ([7dc9016](https://github.com/takehaya/bpf-ninja/commit/7dc9016d762955e597630bb13e0b3c8189422736))

## [0.11.0](https://github.com/takehaya/bpf-ninja/compare/v0.10.2...v0.11.0) (2026-06-24)


### 🎉 Features

* **codegen:** multi-option TCP where-clauses via a converging accumulator loop ([#40](https://github.com/takehaya/bpf-ninja/issues/40)) ([80bab43](https://github.com/takehaya/bpf-ninja/commit/80bab430492c6ecaa0fbbe67b848510feec123ee))
* **kunai:** bpf_loop aux-walks, annotation-free SRv6, and the KUNAI_ dispatch convention ([#42](https://github.com/takehaya/bpf-ninja/issues/42)) ([4915d9b](https://github.com/takehaya/bpf-ninja/commit/4915d9bb48435f6eed884d5b5e0774f5dbb29da4))
* **kunai:** Geneve option-TLV filtering, sub-byte field reads, and optional VLAN at tc ([#38](https://github.com/takehaya/bpf-ninja/issues/38)) ([76bf81c](https://github.com/takehaya/bpf-ninja/commit/76bf81c66cf70c5f1cd6b85153c9107af0a061b2))
* **vocab:** skip Geneve option section to resolve inner offset ([#36](https://github.com/takehaya/bpf-ninja/issues/36)) ([1db3507](https://github.com/takehaya/bpf-ninja/commit/1db3507a5e4cac3d4dda13cdc2622d6022a142c5))


### 🐛 Bug Fixes

* **codegen:** chain-quantifier termination + nested bool-eq, with a packet-level corpus suite ([#37](https://github.com/takehaya/bpf-ninja/issues/37)) ([cad3b19](https://github.com/takehaya/bpf-ninja/commit/cad3b19966758e5c872f0fe088aed0a19e48162d))
* **resolve:** reject any/all over two distinct aux stacks ([#34](https://github.com/takehaya/bpf-ninja/issues/34)) ([47d01a0](https://github.com/takehaya/bpf-ninja/commit/47d01a0917f940affc044e4563fc8f1a3f2f37a3))

## [0.10.2](https://github.com/takehaya/bpf-ninja/compare/v0.10.1...v0.10.2) (2026-06-11)


### 🐛 Bug Fixes

* **codegen:** make dispatch reads PTR_TO_PACKET-safe for native XDP ([#33](https://github.com/takehaya/bpf-ninja/issues/33)) ([cdff69f](https://github.com/takehaya/bpf-ninja/commit/cdff69ff194cfc52214da43d2682b7df8332aa88))


### 📝 Documentation

* **ja:** add vocab authoring guide, unify prose style, fix stale claims ([#31](https://github.com/takehaya/bpf-ninja/issues/31)) ([563dd6b](https://github.com/takehaya/bpf-ninja/commit/563dd6b5446f500a887cc0559445da7c8b24c607))

## [0.10.1](https://github.com/takehaya/bpf-ninja/compare/v0.10.0...v0.10.1) (2026-05-24)


### 🐛 Bug Fixes

* **codegen:** reject vlan/qinq layers at the tc host ([#28](https://github.com/takehaya/bpf-ninja/issues/28)) ([601f423](https://github.com/takehaya/bpf-ninja/commit/601f423e1faed7f59773775908d71b2fbcd70f6f))


### ♻️ Code Refactoring

* **kunai:** split Capabilities into phase-scoped groups ([#30](https://github.com/takehaya/bpf-ninja/issues/30)) ([7bdfe3f](https://github.com/takehaya/bpf-ninja/commit/7bdfe3ff0743140abd2a06b9026c4d22fd60754d))

## [0.10.0](https://github.com/takehaya/bpf-ninja/compare/v0.9.0...v0.10.0) (2026-05-20)


### 🎉 Features

* **capture:** split-core capture mode + tuning docs ([#24](https://github.com/takehaya/bpf-ninja/issues/24)) ([deb4ce9](https://github.com/takehaya/bpf-ninja/commit/deb4ce964253f3f425900f92076410fefb971c1f))


### 🔧 Miscellaneous Chores

* untrack local instruction files ([ec9343b](https://github.com/takehaya/bpf-ninja/commit/ec9343b06699e820c4ad4a74979146c81cf513e0))

## [0.9.0](https://github.com/takehaya/bpf-ninja/compare/v0.8.0...v0.9.0) (2026-05-18)


### 🎉 Features

* sharded ringbuf hoist, kunai filter-min-prefix, snaplen Option A, perf flags ([#20](https://github.com/takehaya/bpf-ninja/issues/20)) ([3809df6](https://github.com/takehaya/bpf-ninja/commit/3809df6b96c30afe8335e6db85e51b02825ee55a))

## [0.8.0](https://github.com/takehaya/bpf-ninja/compare/v0.7.0...v0.8.0) (2026-05-06)


### 🎉 Features

* **cli:** --dump-asm hand-test + --mode xdp standalone capture ([2ef87ba](https://github.com/takehaya/bpf-ninja/commit/2ef87bae2896957b26b7373947af369da42fde01))
* **codegen:** aux-targeted IPv4/IPv6/MAC/CIDR literal predicates (B-3 PR-1) ([8fcf307](https://github.com/takehaya/bpf-ninja/commit/8fcf3079e05dbb6f366a6c0901b7c43f724b4ffc))
* **codegen:** demand-driven AuxLayout slot region (Phase 2 land) ([aa29b4f](https://github.com/takehaya/bpf-ninja/commit/aa29b4fc537b2ddec3a0287be7c5ce2b3d2c337e))
* **codegen:** demand-driven bulk-advance fallback for counter walks ([e784c74](https://github.com/takehaya/bpf-ninja/commit/e784c74bcf8f704b4d22f974672107d6354977e8))
* **codegen:** land 10b arith depth 8→16 + B-2a malformed TCP test pin ([b2ca32c](https://github.com/takehaya/bpf-ninja/commit/b2ca32ce43d9ca49df3b1244b87e45b4e8a7f701))
* **dsl:** alt expansion (F3 + P3-12 + P3-13 + het-alt where/capture) ([791918b](https://github.com/takehaya/bpf-ninja/commit/791918b1dd77b2f212b70be9c0ebdac0dc14d48a))
* **dsl:** aux header system — gating, stacks, dynamic indices, option walk ([ff3acd5](https://github.com/takehaya/bpf-ninja/commit/ff3acd5588c43660cb984a67c7b4bece9976b29d))
* **dsl:** F1-F13 follow-up landings (bit-slice, bitwise, Int&lt;128&gt;, etc.) ([e8a1d0f](https://github.com/takehaya/bpf-ninja/commit/e8a1d0fafae08deaa338643f6f757897ae5c4c32))
* **dsl:** kunai — embedded DSL → eBPF compiler for layered packet filters ([3507cb8](https://github.com/takehaya/bpf-ninja/commit/3507cb8c7082eb2306f7029a0d5919ef27a00b45))
* **dsl:** kunai DSL compiler — scaffolding through multi-protocol vocab ([28cd871](https://github.com/takehaya/bpf-ninja/commit/28cd871d4d49ac7a5709be3f909f44dc180859cf))
* **dsl:** static type system + formal spec (PR-1 ~ D8) ([f2287cd](https://github.com/takehaya/bpf-ninja/commit/f2287cdbb8ba67d415ab8d97f48360df2bed0e14))
* **host,attach,cmd:** tc clsact host adapter (F15) ([53beb5d](https://github.com/takehaya/bpf-ninja/commit/53beb5d1bee4e9170463ab87bb1d6893cfd73847))
* **p4lite,vocab,codegen:** pkt.advance migration (PR-2 — templates A wire + tcp/ipv4 cutover + retire HDRLEN_*) ([d98150d](https://github.com/takehaya/bpf-ninja/commit/d98150d9d9525ab3c7ba2d213e321779e6efe54f))
* **p4lite,vocab,codegen:** TLV-walk migration (PR-3 — lookahead + bit-slice + multi-state TCP options) ([be1d537](https://github.com/takehaya/bpf-ninja/commit/be1d53759f5b7c41eb457e0d4b6301baa0b53b45))
* **p4lite:** ParserCounter extern + counter ops + bool match-key ([488290c](https://github.com/takehaya/bpf-ninja/commit/488290c667a2072f0ccb3b25af0f3314516f6e27))
* **vocab,codegen:** pc.decrement(&lt;aux&gt;.&lt;field&gt;) field-expr (B-4a PR-2) ([3566c00](https://github.com/takehaya/bpf-ninja/commit/3566c00257ffeaa0352aea3ffae97c01f17a95a3))
* **vocab,dsltest:** IPIP / IP6IP6 layered dispatch ([#11](https://github.com/takehaya/bpf-ninja/issues/11) Option H) ([5c3525a](https://github.com/takehaya/bpf-ninja/commit/5c3525a2c2fc04a1b60351eb8ce7cf4c6c6e8032))
* **vocab:** B-1b — cross-check HDRLEN_* against the primary header layout ([fb38fb1](https://github.com/takehaya/bpf-ninja/commit/fb38fb12ea4c2b6de742abbdc33f6cc6b5dba641))
* **vocab:** owner-bound HeaderStack for option-internal arrays (B-4 PR-1) ([5298834](https://github.com/takehaya/bpf-ninja/commit/52988346dd21450e26733216ba2406048988add5))


### 🐛 Bug Fixes

* **codegen,host:** TC_ACT_UNSPEC + boundary leaks (round-2 blockers) ([38de3e6](https://github.com/takehaya/bpf-ninja/commit/38de3e6e6bc1287a7e11f6cf79ff146b91ac3c0a))
* **codegen:** elide unqueried-aux dispatch cases in TLV-walk cascade ([a200a5b](https://github.com/takehaya/bpf-ninja/commit/a200a5b3703aee47ead20ffc55a8f42d391fe22b))


### 📝 Documentation

* sync grammar / usage / internals to the landed branch state ([121408e](https://github.com/takehaya/bpf-ninja/commit/121408e90af07638630851c5f93ab356f1857cf5))


### ♻️ Code Refactoring

* **codegen:** shift bpf_loop ctx down 16 bytes to free arith slots ([2bc329f](https://github.com/takehaya/bpf-ninja/commit/2bc329fcd8e6aeb3d053aba0d247ade22440e379))
* **dsl:** rename VAREXT_LEN family to HDRLEN — network-conventional ([97a093b](https://github.com/takehaya/bpf-ninja/commit/97a093bbe5d324a74b5c46c2f6326d4d5e55f27c))
* **dsl:** vocab maintenance — self-validating dispatch + p4c interop ([59e6ab9](https://github.com/takehaya/bpf-ninja/commit/59e6ab969f2f75433d0a80386e960ad734cc61a0))

## [0.7.0](https://github.com/takehaya/bpf-ninja/compare/v0.6.0...v0.7.0) (2026-04-08)


### 🎉 Features

* add --arg-filter and --list-params for fentry/fexit argument filtering ([139c568](https://github.com/takehaya/bpf-ninja/commit/139c5683cb5322ecd4aecf57ca3473e1fa584a48))
* add --arg-filter and --list-params for function argument filtering ([ffb5c80](https://github.com/takehaya/bpf-ninja/commit/ffb5c80df3848916f86d3139aff605edbb911efb))


### 🐛 Bug Fixes

* address Copilot review on signed arg filter correctness ([98bb76a](https://github.com/takehaya/bpf-ninja/commit/98bb76ac4921b4dcf36026c7710f41754ce8d637))
* address Copilot review round 2 ([9ea8d78](https://github.com/takehaya/bpf-ninja/commit/9ea8d785df87c6ad80799e9242303b2a6dc25751))
* allow negative values for signed 64-bit arg filter parameters ([52df696](https://github.com/takehaya/bpf-ninja/commit/52df6969f67bf62e2fa8f800a8dad9f20e5ee624))
* update golangci-lint install path to v2 ([a79a40c](https://github.com/takehaya/bpf-ninja/commit/a79a40c011d836a17b1d9855d3e79fdaa280f54a))
* validate signed range min&lt;=max after BTF signedness is resolved ([237fe4a](https://github.com/takehaya/bpf-ninja/commit/237fe4aec6621e47a3ba9b47b9447de887b32178))


### 📝 Documentation

* rename handtest-func-tailcall.md to handtest.md ([4128c03](https://github.com/takehaya/bpf-ninja/commit/4128c03ba4f4ccb10bdabfee4f33de2e19574198))
* rename handtest-func-tailcall.md to handtest.md ([3dab58f](https://github.com/takehaya/bpf-ninja/commit/3dab58fe7291aaba20dfbd76635af0c4064e74f5))


### ♻️ Code Refactoring

* remove dead code, noise comment, and test boilerplate ([ac2c6d6](https://github.com/takehaya/bpf-ninja/commit/ac2c6d6b7af8484bc4d18cb585c3266e09aab266))

## [0.6.0](https://github.com/takehaya/bpf-ninja/compare/v0.5.0...v0.6.0) (2026-04-04)


### 🎉 Features

* add --func, --list-funcs, --list-progs for __noinline subfunction probing ([cd7cb27](https://github.com/takehaya/bpf-ninja/commit/cd7cb27ef0041d78484c6113c4da144625db655b))
* add --func/--list-funcs/--list-progs for __noinline subfunction probing ([15484b1](https://github.com/takehaya/bpf-ninja/commit/15484b1341420a0f3a9151ab55025578342ae530))
* add --version flag ([aad7541](https://github.com/takehaya/bpf-ninja/commit/aad754152a6ea254a684e4198bc947028b1c745e))
* add --version flag Set via -ldflags "-X main.version=X.Y.Z" at build time. Defaults to "dev" for development builds. ([33b16f5](https://github.com/takehaya/bpf-ninja/commit/33b16f5fedbb8d180785f5622b91452cdf502b02))
* add CLI ([3080e9a](https://github.com/takehaya/bpf-ninja/commit/3080e9ae8133b77c02f1b95c3c17aa001b0337a3))
* add core eBPF program generation and packet capture ([4403c86](https://github.com/takehaya/bpf-ninja/commit/4403c8664d9bde91bb4e719d79bc38cde40579cf))
* add install script for one-liner installation ([6b3976f](https://github.com/takehaya/bpf-ninja/commit/6b3976f6c5d7b1f6c76650e8b9cd07781f95b2fd))
* BTF func resolution, exit mode pcapng, version flag & CI fixes ([f464819](https://github.com/takehaya/bpf-ninja/commit/f464819b449775c0ea5bca94616b1316ee7440b5))
* embed XDP action as pcapng interface names in exit mode ([1ca525f](https://github.com/takehaya/bpf-ninja/commit/1ca525f76cffee591d961eb73ac6055738f2fc8b))
* embed XDP action as pcapng interface names in exit mode ([5eedd7b](https://github.com/takehaya/bpf-ninja/commit/5eedd7be439cd2d947a471178cc51ffc240d8715))
* resolve XDP entry function name via BTF and update tail call notes ([eb52cb0](https://github.com/takehaya/bpf-ninja/commit/eb52cb0e1f93b93c20896865f3d0356ac9dc4c35))


### 🐛 Bug Fixes

* add libbpf-dev to CI, skip tests when bpftool unavailable ([5f26824](https://github.com/takehaya/bpf-ninja/commit/5f26824ff3aa57d9323cecf2d7f1f8ca9eb1716b))
* address Copilot review feedback on error handling, safety, and docs ([b8d42a2](https://github.com/takehaya/bpf-ninja/commit/b8d42a2af87eccf3127e188c5f403a0008eec054))
* correct project root path in run_tests.sh after move to scripts/test/ ([47b7386](https://github.com/takehaya/bpf-ninja/commit/47b7386bac64118983929b57c8587e861834455c))
* install bpftool in CI and remove set -e from test runner ([aea8ff2](https://github.com/takehaya/bpf-ninja/commit/aea8ff2e331a46819fc395cc1dddeb18902560b5))
* remove arm64 from goreleaser (CGO cross-compile not available) ([fc019d9](https://github.com/takehaya/bpf-ninja/commit/fc019d9733ac97dee098b7ea893947044dbf48e6))
* resolve -v flag conflict between --verbose and --version ([baad18e](https://github.com/takehaya/bpf-ninja/commit/baad18e69fc3e799ac30a26bba740099ca664af8))
* skip bpftool-dependent tests when bpftool is not functional ([ba25ae8](https://github.com/takehaya/bpf-ninja/commit/ba25ae8146a497f7e9e5c0e72af21836d64eb3d9))


### 📝 Documentation

* add handtest guide and TODO ([a644840](https://github.com/takehaya/bpf-ninja/commit/a64484058c14d6a9ab266146dc2a8edbf4e64188))
* add manual test guide for --func and tail call probing (ja/en) ([27013ba](https://github.com/takehaya/bpf-ninja/commit/27013ba9141580fc82476cc28e75a5661a968392))
* add README, Makefile, and gitignore ([e63930f](https://github.com/takehaya/bpf-ninja/commit/e63930f6b4a77303a4179eed93b2618627c25048))
* note jq requirement for install script ([13a00ff](https://github.com/takehaya/bpf-ninja/commit/13a00ffddc6a2d91376fc0046f0e950aa0b21710))


### 🔧 Miscellaneous Chores

* add goreleaser snapshot target to Makefile ([91a52fb](https://github.com/takehaya/bpf-ninja/commit/91a52fb8c19e1a9f73af8d0936169640a4cddc6e))
* add lefthook pre-commit hooks and conventional commit check ([95205a4](https://github.com/takehaya/bpf-ninja/commit/95205a4fd39d325ace8f18bc7b8f0b6306ece525))
* add lefthook pre-commit, golangci-lint errcheck, and lint CI workflow ([4f0f934](https://github.com/takehaya/bpf-ninja/commit/4f0f93452362364aa22011a9aecc738b77a2e6e6))
* **main:** release 0.1.0 ([6d39854](https://github.com/takehaya/bpf-ninja/commit/6d39854f0b02b74db7ee2ee6336c97e21a9886bc))
* **main:** release 0.1.0 ([f1ec845](https://github.com/takehaya/bpf-ninja/commit/f1ec8458de9e88f54c3e37176eef7bc2e8099b9c))
* **main:** release 0.1.0 ([ee01b99](https://github.com/takehaya/bpf-ninja/commit/ee01b991b69a337102f68b21081ba71316fe3fec))
* **main:** release 0.1.0 ([398bb9b](https://github.com/takehaya/bpf-ninja/commit/398bb9bf7e4970696bf65a10c047ac9a3044ab5a))
* **main:** release 0.1.1 ([0e13c8c](https://github.com/takehaya/bpf-ninja/commit/0e13c8caeaf31a66816bfeeff517dfaa0090a001))
* **main:** release 0.1.1 ([5253ee8](https://github.com/takehaya/bpf-ninja/commit/5253ee8440ae566086d7a01cc141a7f70a086784))
* **main:** release 0.2.0 ([15bda8a](https://github.com/takehaya/bpf-ninja/commit/15bda8a9a411a424d5b78e99f5e540a3ac56806e))
* **main:** release 0.2.0 ([c952939](https://github.com/takehaya/bpf-ninja/commit/c952939424849f0369591952619b19914f2f60f3))
* **main:** release 0.2.0 ([e67f60e](https://github.com/takehaya/bpf-ninja/commit/e67f60ec877fd37a66b495363133e6c997739c2a))
* **main:** release 0.2.0 ([0f029b9](https://github.com/takehaya/bpf-ninja/commit/0f029b9a92a30704cba37266a5a64f02656587de))
* **main:** release 0.3.0 ([2ec55a3](https://github.com/takehaya/bpf-ninja/commit/2ec55a3c35264c0958fd80f9ea306e9ba576a2a5))
* **main:** release 0.3.0 ([76f4abf](https://github.com/takehaya/bpf-ninja/commit/76f4abfc7e95e4d7f01c099079eaadd34dc56b70))
* **main:** release 0.4.0 ([79486d4](https://github.com/takehaya/bpf-ninja/commit/79486d4e499697e5c413c3c3deca87d0c253aaab))
* **main:** release 0.4.0 ([da00fa8](https://github.com/takehaya/bpf-ninja/commit/da00fa8b599cd18194900abea2d9c14691710e81))
* **main:** release 0.5.0 ([32e7d52](https://github.com/takehaya/bpf-ninja/commit/32e7d528920d601b71aaeb97caa4d100c1276353))
* **main:** release 0.5.0 ([d30d98d](https://github.com/takehaya/bpf-ninja/commit/d30d98d4a93b9eaf2f4d2c17a7b953e3701f8231))
* reset version to 0.0.1 ([36a6ae3](https://github.com/takehaya/bpf-ninja/commit/36a6ae358e4d1dbeb3e0b10adfa2476040960dab))


### ♻️ Code Refactoring

* move test/ to scripts/test/ ([396133a](https://github.com/takehaya/bpf-ninja/commit/396133add0f0d18f5ded21a91e9d4076584935c1))

## [0.5.0](https://github.com/takehaya/bpf-ninja/compare/v0.4.0...v0.5.0) (2026-04-04)


### 🎉 Features

* add --func, --list-funcs, --list-progs for __noinline subfunction probing ([cd7cb27](https://github.com/takehaya/bpf-ninja/commit/cd7cb27ef0041d78484c6113c4da144625db655b))
* add --func/--list-funcs/--list-progs for __noinline subfunction probing ([15484b1](https://github.com/takehaya/bpf-ninja/commit/15484b1341420a0f3a9151ab55025578342ae530))


### 🐛 Bug Fixes

* address Copilot review feedback on error handling, safety, and docs ([b8d42a2](https://github.com/takehaya/bpf-ninja/commit/b8d42a2af87eccf3127e188c5f403a0008eec054))


### 📝 Documentation

* add manual test guide for --func and tail call probing (ja/en) ([27013ba](https://github.com/takehaya/bpf-ninja/commit/27013ba9141580fc82476cc28e75a5661a968392))


### 🔧 Miscellaneous Chores

* add lefthook pre-commit hooks and conventional commit check ([95205a4](https://github.com/takehaya/bpf-ninja/commit/95205a4fd39d325ace8f18bc7b8f0b6306ece525))
* add lefthook pre-commit, golangci-lint errcheck, and lint CI workflow ([4f0f934](https://github.com/takehaya/bpf-ninja/commit/4f0f93452362364aa22011a9aecc738b77a2e6e6))

## [0.4.0](https://github.com/takehaya/bpf-ninja/compare/v0.3.0...v0.4.0) (2026-03-30)


### 🎉 Features

* BTF func resolution, exit mode pcapng, version flag & CI fixes ([f464819](https://github.com/takehaya/bpf-ninja/commit/f464819b449775c0ea5bca94616b1316ee7440b5))
* resolve XDP entry function name via BTF and update tail call notes ([eb52cb0](https://github.com/takehaya/bpf-ninja/commit/eb52cb0e1f93b93c20896865f3d0356ac9dc4c35))


### 🐛 Bug Fixes

* resolve -v flag conflict between --verbose and --version ([baad18e](https://github.com/takehaya/bpf-ninja/commit/baad18e69fc3e799ac30a26bba740099ca664af8))

## [0.3.0](https://github.com/takehaya/bpf-ninja/compare/v0.2.0...v0.3.0) (2026-03-29)


### 🎉 Features

* add --version flag ([aad7541](https://github.com/takehaya/bpf-ninja/commit/aad754152a6ea254a684e4198bc947028b1c745e))
* add --version flag Set via -ldflags "-X main.version=X.Y.Z" at build time. Defaults to "dev" for development builds. ([33b16f5](https://github.com/takehaya/bpf-ninja/commit/33b16f5fedbb8d180785f5622b91452cdf502b02))


### 🔧 Miscellaneous Chores

* add goreleaser snapshot target to Makefile ([91a52fb](https://github.com/takehaya/bpf-ninja/commit/91a52fb8c19e1a9f73af8d0936169640a4cddc6e))

## [0.2.0](https://github.com/takehaya/bpf-ninja/compare/v0.1.0...v0.2.0) (2026-03-29)


### 🎉 Features

* embed XDP action as pcapng interface names in exit mode ([1ca525f](https://github.com/takehaya/bpf-ninja/commit/1ca525f76cffee591d961eb73ac6055738f2fc8b))
* embed XDP action as pcapng interface names in exit mode ([5eedd7b](https://github.com/takehaya/bpf-ninja/commit/5eedd7be439cd2d947a471178cc51ffc240d8715))

## [0.1.0](https://github.com/takehaya/bpf-ninja/compare/v0.0.1...v0.1.0) (2026-03-24)


### 🎉 Features

* add CLI ([3080e9a](https://github.com/takehaya/bpf-ninja/commit/3080e9ae8133b77c02f1b95c3c17aa001b0337a3))
* add core eBPF program generation and packet capture ([4403c86](https://github.com/takehaya/bpf-ninja/commit/4403c8664d9bde91bb4e719d79bc38cde40579cf))
* add install script for one-liner installation ([6b3976f](https://github.com/takehaya/bpf-ninja/commit/6b3976f6c5d7b1f6c76650e8b9cd07781f95b2fd))


### 🐛 Bug Fixes

* add libbpf-dev to CI, skip tests when bpftool unavailable ([5f26824](https://github.com/takehaya/bpf-ninja/commit/5f26824ff3aa57d9323cecf2d7f1f8ca9eb1716b))
* correct project root path in run_tests.sh after move to scripts/test/ ([47b7386](https://github.com/takehaya/bpf-ninja/commit/47b7386bac64118983929b57c8587e861834455c))
* install bpftool in CI and remove set -e from test runner ([aea8ff2](https://github.com/takehaya/bpf-ninja/commit/aea8ff2e331a46819fc395cc1dddeb18902560b5))
* remove arm64 from goreleaser (CGO cross-compile not available) ([fc019d9](https://github.com/takehaya/bpf-ninja/commit/fc019d9733ac97dee098b7ea893947044dbf48e6))
* skip bpftool-dependent tests when bpftool is not functional ([ba25ae8](https://github.com/takehaya/bpf-ninja/commit/ba25ae8146a497f7e9e5c0e72af21836d64eb3d9))


### 📝 Documentation

* add handtest guide and TODO ([a644840](https://github.com/takehaya/bpf-ninja/commit/a64484058c14d6a9ab266146dc2a8edbf4e64188))
* add README, Makefile, and gitignore ([e63930f](https://github.com/takehaya/bpf-ninja/commit/e63930f6b4a77303a4179eed93b2618627c25048))
* note jq requirement for install script ([13a00ff](https://github.com/takehaya/bpf-ninja/commit/13a00ffddc6a2d91376fc0046f0e950aa0b21710))


### 🔧 Miscellaneous Chores

* **main:** release 0.1.0 ([ee01b99](https://github.com/takehaya/bpf-ninja/commit/ee01b991b69a337102f68b21081ba71316fe3fec))
* **main:** release 0.1.0 ([398bb9b](https://github.com/takehaya/bpf-ninja/commit/398bb9bf7e4970696bf65a10c047ac9a3044ab5a))
* **main:** release 0.1.1 ([0e13c8c](https://github.com/takehaya/bpf-ninja/commit/0e13c8caeaf31a66816bfeeff517dfaa0090a001))
* **main:** release 0.1.1 ([5253ee8](https://github.com/takehaya/bpf-ninja/commit/5253ee8440ae566086d7a01cc141a7f70a086784))
* **main:** release 0.2.0 ([e67f60e](https://github.com/takehaya/bpf-ninja/commit/e67f60ec877fd37a66b495363133e6c997739c2a))
* **main:** release 0.2.0 ([0f029b9](https://github.com/takehaya/bpf-ninja/commit/0f029b9a92a30704cba37266a5a64f02656587de))
* reset version to 0.0.1 ([36a6ae3](https://github.com/takehaya/bpf-ninja/commit/36a6ae358e4d1dbeb3e0b10adfa2476040960dab))


### ♻️ Code Refactoring

* move test/ to scripts/test/ ([396133a](https://github.com/takehaya/bpf-ninja/commit/396133add0f0d18f5ded21a91e9d4076584935c1))

## [0.2.0](https://github.com/takehaya/bpf-ninja/compare/v0.1.1...v0.2.0) (2026-03-24)


### 🎉 Features

* add install script for one-liner installation ([42643ff](https://github.com/takehaya/bpf-ninja/commit/42643ffb0696c9d600f494966e1c0248dac3a49c))


### 🐛 Bug Fixes

* correct project root path in run_tests.sh after move to scripts/test/ ([1ed7844](https://github.com/takehaya/bpf-ninja/commit/1ed78444062782d5e07288b923f2c8f105968f80))


### 📝 Documentation

* note jq requirement for install script ([82a38cc](https://github.com/takehaya/bpf-ninja/commit/82a38cc63f3dd8299697040a98ba2f1dbea801e7))


### ♻️ Code Refactoring

* move test/ to scripts/test/ ([a8aed03](https://github.com/takehaya/bpf-ninja/commit/a8aed034808a9baa594056afc3d06a0452ebbb21))

## [0.1.1](https://github.com/takehaya/bpf-ninja/compare/v0.1.0...v0.1.1) (2026-03-24)


### 🐛 Bug Fixes

* remove arm64 from goreleaser (CGO cross-compile not available) ([6ca90f7](https://github.com/takehaya/bpf-ninja/commit/6ca90f7340766b65991e29e1718f00e2e889a26e))

## [0.1.0](https://github.com/takehaya/bpf-ninja/compare/v0.0.1...v0.1.0) (2026-03-24)


### 🎉 Features

* add CLI ([3080e9a](https://github.com/takehaya/bpf-ninja/commit/3080e9ae8133b77c02f1b95c3c17aa001b0337a3))
* add core eBPF program generation and packet capture ([4403c86](https://github.com/takehaya/bpf-ninja/commit/4403c8664d9bde91bb4e719d79bc38cde40579cf))


### 🐛 Bug Fixes

* add libbpf-dev to CI, skip tests when bpftool unavailable ([5f26824](https://github.com/takehaya/bpf-ninja/commit/5f26824ff3aa57d9323cecf2d7f1f8ca9eb1716b))
* install bpftool in CI and remove set -e from test runner ([aea8ff2](https://github.com/takehaya/bpf-ninja/commit/aea8ff2e331a46819fc395cc1dddeb18902560b5))
* skip bpftool-dependent tests when bpftool is not functional ([ba25ae8](https://github.com/takehaya/bpf-ninja/commit/ba25ae8146a497f7e9e5c0e72af21836d64eb3d9))


### 📝 Documentation

* add handtest guide and TODO ([a644840](https://github.com/takehaya/bpf-ninja/commit/a64484058c14d6a9ab266146dc2a8edbf4e64188))
* add README, Makefile, and gitignore ([e63930f](https://github.com/takehaya/bpf-ninja/commit/e63930f6b4a77303a4179eed93b2618627c25048))
