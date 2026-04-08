# Changelog

## [0.7.0](https://github.com/takehaya/xdp-ninja/compare/v0.6.0...v0.7.0) (2026-04-08)


### 🎉 Features

* add --arg-filter and --list-params for fentry/fexit argument filtering ([139c568](https://github.com/takehaya/xdp-ninja/commit/139c5683cb5322ecd4aecf57ca3473e1fa584a48))
* add --arg-filter and --list-params for function argument filtering ([ffb5c80](https://github.com/takehaya/xdp-ninja/commit/ffb5c80df3848916f86d3139aff605edbb911efb))


### 🐛 Bug Fixes

* address Copilot review on signed arg filter correctness ([98bb76a](https://github.com/takehaya/xdp-ninja/commit/98bb76ac4921b4dcf36026c7710f41754ce8d637))
* address Copilot review round 2 ([9ea8d78](https://github.com/takehaya/xdp-ninja/commit/9ea8d785df87c6ad80799e9242303b2a6dc25751))
* allow negative values for signed 64-bit arg filter parameters ([52df696](https://github.com/takehaya/xdp-ninja/commit/52df6969f67bf62e2fa8f800a8dad9f20e5ee624))
* update golangci-lint install path to v2 ([a79a40c](https://github.com/takehaya/xdp-ninja/commit/a79a40c011d836a17b1d9855d3e79fdaa280f54a))
* validate signed range min&lt;=max after BTF signedness is resolved ([237fe4a](https://github.com/takehaya/xdp-ninja/commit/237fe4aec6621e47a3ba9b47b9447de887b32178))


### 📝 Documentation

* rename handtest-func-tailcall.md to handtest.md ([4128c03](https://github.com/takehaya/xdp-ninja/commit/4128c03ba4f4ccb10bdabfee4f33de2e19574198))
* rename handtest-func-tailcall.md to handtest.md ([3dab58f](https://github.com/takehaya/xdp-ninja/commit/3dab58fe7291aaba20dfbd76635af0c4064e74f5))


### ♻️ Code Refactoring

* remove dead code, noise comment, and test boilerplate ([ac2c6d6](https://github.com/takehaya/xdp-ninja/commit/ac2c6d6b7af8484bc4d18cb585c3266e09aab266))

## [0.6.0](https://github.com/takehaya/xdp-ninja/compare/v0.5.0...v0.6.0) (2026-04-04)


### 🎉 Features

* add --func, --list-funcs, --list-progs for __noinline subfunction probing ([cd7cb27](https://github.com/takehaya/xdp-ninja/commit/cd7cb27ef0041d78484c6113c4da144625db655b))
* add --func/--list-funcs/--list-progs for __noinline subfunction probing ([15484b1](https://github.com/takehaya/xdp-ninja/commit/15484b1341420a0f3a9151ab55025578342ae530))
* add --version flag ([aad7541](https://github.com/takehaya/xdp-ninja/commit/aad754152a6ea254a684e4198bc947028b1c745e))
* add --version flag Set via -ldflags "-X main.version=X.Y.Z" at build time. Defaults to "dev" for development builds. ([33b16f5](https://github.com/takehaya/xdp-ninja/commit/33b16f5fedbb8d180785f5622b91452cdf502b02))
* add CLI ([3080e9a](https://github.com/takehaya/xdp-ninja/commit/3080e9ae8133b77c02f1b95c3c17aa001b0337a3))
* add core eBPF program generation and packet capture ([4403c86](https://github.com/takehaya/xdp-ninja/commit/4403c8664d9bde91bb4e719d79bc38cde40579cf))
* add install script for one-liner installation ([6b3976f](https://github.com/takehaya/xdp-ninja/commit/6b3976f6c5d7b1f6c76650e8b9cd07781f95b2fd))
* BTF func resolution, exit mode pcapng, version flag & CI fixes ([f464819](https://github.com/takehaya/xdp-ninja/commit/f464819b449775c0ea5bca94616b1316ee7440b5))
* embed XDP action as pcapng interface names in exit mode ([1ca525f](https://github.com/takehaya/xdp-ninja/commit/1ca525f76cffee591d961eb73ac6055738f2fc8b))
* embed XDP action as pcapng interface names in exit mode ([5eedd7b](https://github.com/takehaya/xdp-ninja/commit/5eedd7be439cd2d947a471178cc51ffc240d8715))
* resolve XDP entry function name via BTF and update tail call notes ([eb52cb0](https://github.com/takehaya/xdp-ninja/commit/eb52cb0e1f93b93c20896865f3d0356ac9dc4c35))


### 🐛 Bug Fixes

* add libbpf-dev to CI, skip tests when bpftool unavailable ([5f26824](https://github.com/takehaya/xdp-ninja/commit/5f26824ff3aa57d9323cecf2d7f1f8ca9eb1716b))
* address Copilot review feedback on error handling, safety, and docs ([b8d42a2](https://github.com/takehaya/xdp-ninja/commit/b8d42a2af87eccf3127e188c5f403a0008eec054))
* correct project root path in run_tests.sh after move to scripts/test/ ([47b7386](https://github.com/takehaya/xdp-ninja/commit/47b7386bac64118983929b57c8587e861834455c))
* install bpftool in CI and remove set -e from test runner ([aea8ff2](https://github.com/takehaya/xdp-ninja/commit/aea8ff2e331a46819fc395cc1dddeb18902560b5))
* remove arm64 from goreleaser (CGO cross-compile not available) ([fc019d9](https://github.com/takehaya/xdp-ninja/commit/fc019d9733ac97dee098b7ea893947044dbf48e6))
* resolve -v flag conflict between --verbose and --version ([baad18e](https://github.com/takehaya/xdp-ninja/commit/baad18e69fc3e799ac30a26bba740099ca664af8))
* skip bpftool-dependent tests when bpftool is not functional ([ba25ae8](https://github.com/takehaya/xdp-ninja/commit/ba25ae8146a497f7e9e5c0e72af21836d64eb3d9))


### 📝 Documentation

* add handtest guide and TODO ([a644840](https://github.com/takehaya/xdp-ninja/commit/a64484058c14d6a9ab266146dc2a8edbf4e64188))
* add manual test guide for --func and tail call probing (ja/en) ([27013ba](https://github.com/takehaya/xdp-ninja/commit/27013ba9141580fc82476cc28e75a5661a968392))
* add README, Makefile, and gitignore ([e63930f](https://github.com/takehaya/xdp-ninja/commit/e63930f6b4a77303a4179eed93b2618627c25048))
* note jq requirement for install script ([13a00ff](https://github.com/takehaya/xdp-ninja/commit/13a00ffddc6a2d91376fc0046f0e950aa0b21710))


### 🔧 Miscellaneous Chores

* add goreleaser snapshot target to Makefile ([91a52fb](https://github.com/takehaya/xdp-ninja/commit/91a52fb8c19e1a9f73af8d0936169640a4cddc6e))
* add lefthook pre-commit hooks and conventional commit check ([95205a4](https://github.com/takehaya/xdp-ninja/commit/95205a4fd39d325ace8f18bc7b8f0b6306ece525))
* add lefthook pre-commit, golangci-lint errcheck, and lint CI workflow ([4f0f934](https://github.com/takehaya/xdp-ninja/commit/4f0f93452362364aa22011a9aecc738b77a2e6e6))
* **main:** release 0.1.0 ([6d39854](https://github.com/takehaya/xdp-ninja/commit/6d39854f0b02b74db7ee2ee6336c97e21a9886bc))
* **main:** release 0.1.0 ([f1ec845](https://github.com/takehaya/xdp-ninja/commit/f1ec8458de9e88f54c3e37176eef7bc2e8099b9c))
* **main:** release 0.1.0 ([ee01b99](https://github.com/takehaya/xdp-ninja/commit/ee01b991b69a337102f68b21081ba71316fe3fec))
* **main:** release 0.1.0 ([398bb9b](https://github.com/takehaya/xdp-ninja/commit/398bb9bf7e4970696bf65a10c047ac9a3044ab5a))
* **main:** release 0.1.1 ([0e13c8c](https://github.com/takehaya/xdp-ninja/commit/0e13c8caeaf31a66816bfeeff517dfaa0090a001))
* **main:** release 0.1.1 ([5253ee8](https://github.com/takehaya/xdp-ninja/commit/5253ee8440ae566086d7a01cc141a7f70a086784))
* **main:** release 0.2.0 ([15bda8a](https://github.com/takehaya/xdp-ninja/commit/15bda8a9a411a424d5b78e99f5e540a3ac56806e))
* **main:** release 0.2.0 ([c952939](https://github.com/takehaya/xdp-ninja/commit/c952939424849f0369591952619b19914f2f60f3))
* **main:** release 0.2.0 ([e67f60e](https://github.com/takehaya/xdp-ninja/commit/e67f60ec877fd37a66b495363133e6c997739c2a))
* **main:** release 0.2.0 ([0f029b9](https://github.com/takehaya/xdp-ninja/commit/0f029b9a92a30704cba37266a5a64f02656587de))
* **main:** release 0.3.0 ([2ec55a3](https://github.com/takehaya/xdp-ninja/commit/2ec55a3c35264c0958fd80f9ea306e9ba576a2a5))
* **main:** release 0.3.0 ([76f4abf](https://github.com/takehaya/xdp-ninja/commit/76f4abfc7e95e4d7f01c099079eaadd34dc56b70))
* **main:** release 0.4.0 ([79486d4](https://github.com/takehaya/xdp-ninja/commit/79486d4e499697e5c413c3c3deca87d0c253aaab))
* **main:** release 0.4.0 ([da00fa8](https://github.com/takehaya/xdp-ninja/commit/da00fa8b599cd18194900abea2d9c14691710e81))
* **main:** release 0.5.0 ([32e7d52](https://github.com/takehaya/xdp-ninja/commit/32e7d528920d601b71aaeb97caa4d100c1276353))
* **main:** release 0.5.0 ([d30d98d](https://github.com/takehaya/xdp-ninja/commit/d30d98d4a93b9eaf2f4d2c17a7b953e3701f8231))
* reset version to 0.0.1 ([36a6ae3](https://github.com/takehaya/xdp-ninja/commit/36a6ae358e4d1dbeb3e0b10adfa2476040960dab))


### ♻️ Code Refactoring

* move test/ to scripts/test/ ([396133a](https://github.com/takehaya/xdp-ninja/commit/396133add0f0d18f5ded21a91e9d4076584935c1))

## [0.5.0](https://github.com/takehaya/xdp-ninja/compare/v0.4.0...v0.5.0) (2026-04-04)


### 🎉 Features

* add --func, --list-funcs, --list-progs for __noinline subfunction probing ([cd7cb27](https://github.com/takehaya/xdp-ninja/commit/cd7cb27ef0041d78484c6113c4da144625db655b))
* add --func/--list-funcs/--list-progs for __noinline subfunction probing ([15484b1](https://github.com/takehaya/xdp-ninja/commit/15484b1341420a0f3a9151ab55025578342ae530))


### 🐛 Bug Fixes

* address Copilot review feedback on error handling, safety, and docs ([b8d42a2](https://github.com/takehaya/xdp-ninja/commit/b8d42a2af87eccf3127e188c5f403a0008eec054))


### 📝 Documentation

* add manual test guide for --func and tail call probing (ja/en) ([27013ba](https://github.com/takehaya/xdp-ninja/commit/27013ba9141580fc82476cc28e75a5661a968392))


### 🔧 Miscellaneous Chores

* add lefthook pre-commit hooks and conventional commit check ([95205a4](https://github.com/takehaya/xdp-ninja/commit/95205a4fd39d325ace8f18bc7b8f0b6306ece525))
* add lefthook pre-commit, golangci-lint errcheck, and lint CI workflow ([4f0f934](https://github.com/takehaya/xdp-ninja/commit/4f0f93452362364aa22011a9aecc738b77a2e6e6))

## [0.4.0](https://github.com/takehaya/xdp-ninja/compare/v0.3.0...v0.4.0) (2026-03-30)


### 🎉 Features

* BTF func resolution, exit mode pcapng, version flag & CI fixes ([f464819](https://github.com/takehaya/xdp-ninja/commit/f464819b449775c0ea5bca94616b1316ee7440b5))
* resolve XDP entry function name via BTF and update tail call notes ([eb52cb0](https://github.com/takehaya/xdp-ninja/commit/eb52cb0e1f93b93c20896865f3d0356ac9dc4c35))


### 🐛 Bug Fixes

* resolve -v flag conflict between --verbose and --version ([baad18e](https://github.com/takehaya/xdp-ninja/commit/baad18e69fc3e799ac30a26bba740099ca664af8))

## [0.3.0](https://github.com/takehaya/xdp-ninja/compare/v0.2.0...v0.3.0) (2026-03-29)


### 🎉 Features

* add --version flag ([aad7541](https://github.com/takehaya/xdp-ninja/commit/aad754152a6ea254a684e4198bc947028b1c745e))
* add --version flag Set via -ldflags "-X main.version=X.Y.Z" at build time. Defaults to "dev" for development builds. ([33b16f5](https://github.com/takehaya/xdp-ninja/commit/33b16f5fedbb8d180785f5622b91452cdf502b02))


### 🔧 Miscellaneous Chores

* add goreleaser snapshot target to Makefile ([91a52fb](https://github.com/takehaya/xdp-ninja/commit/91a52fb8c19e1a9f73af8d0936169640a4cddc6e))

## [0.2.0](https://github.com/takehaya/xdp-ninja/compare/v0.1.0...v0.2.0) (2026-03-29)


### 🎉 Features

* embed XDP action as pcapng interface names in exit mode ([1ca525f](https://github.com/takehaya/xdp-ninja/commit/1ca525f76cffee591d961eb73ac6055738f2fc8b))
* embed XDP action as pcapng interface names in exit mode ([5eedd7b](https://github.com/takehaya/xdp-ninja/commit/5eedd7be439cd2d947a471178cc51ffc240d8715))

## [0.1.0](https://github.com/takehaya/xdp-ninja/compare/v0.0.1...v0.1.0) (2026-03-24)


### 🎉 Features

* add CLI ([3080e9a](https://github.com/takehaya/xdp-ninja/commit/3080e9ae8133b77c02f1b95c3c17aa001b0337a3))
* add core eBPF program generation and packet capture ([4403c86](https://github.com/takehaya/xdp-ninja/commit/4403c8664d9bde91bb4e719d79bc38cde40579cf))
* add install script for one-liner installation ([6b3976f](https://github.com/takehaya/xdp-ninja/commit/6b3976f6c5d7b1f6c76650e8b9cd07781f95b2fd))


### 🐛 Bug Fixes

* add libbpf-dev to CI, skip tests when bpftool unavailable ([5f26824](https://github.com/takehaya/xdp-ninja/commit/5f26824ff3aa57d9323cecf2d7f1f8ca9eb1716b))
* correct project root path in run_tests.sh after move to scripts/test/ ([47b7386](https://github.com/takehaya/xdp-ninja/commit/47b7386bac64118983929b57c8587e861834455c))
* install bpftool in CI and remove set -e from test runner ([aea8ff2](https://github.com/takehaya/xdp-ninja/commit/aea8ff2e331a46819fc395cc1dddeb18902560b5))
* remove arm64 from goreleaser (CGO cross-compile not available) ([fc019d9](https://github.com/takehaya/xdp-ninja/commit/fc019d9733ac97dee098b7ea893947044dbf48e6))
* skip bpftool-dependent tests when bpftool is not functional ([ba25ae8](https://github.com/takehaya/xdp-ninja/commit/ba25ae8146a497f7e9e5c0e72af21836d64eb3d9))


### 📝 Documentation

* add handtest guide and TODO ([a644840](https://github.com/takehaya/xdp-ninja/commit/a64484058c14d6a9ab266146dc2a8edbf4e64188))
* add README, Makefile, and gitignore ([e63930f](https://github.com/takehaya/xdp-ninja/commit/e63930f6b4a77303a4179eed93b2618627c25048))
* note jq requirement for install script ([13a00ff](https://github.com/takehaya/xdp-ninja/commit/13a00ffddc6a2d91376fc0046f0e950aa0b21710))


### 🔧 Miscellaneous Chores

* **main:** release 0.1.0 ([ee01b99](https://github.com/takehaya/xdp-ninja/commit/ee01b991b69a337102f68b21081ba71316fe3fec))
* **main:** release 0.1.0 ([398bb9b](https://github.com/takehaya/xdp-ninja/commit/398bb9bf7e4970696bf65a10c047ac9a3044ab5a))
* **main:** release 0.1.1 ([0e13c8c](https://github.com/takehaya/xdp-ninja/commit/0e13c8caeaf31a66816bfeeff517dfaa0090a001))
* **main:** release 0.1.1 ([5253ee8](https://github.com/takehaya/xdp-ninja/commit/5253ee8440ae566086d7a01cc141a7f70a086784))
* **main:** release 0.2.0 ([e67f60e](https://github.com/takehaya/xdp-ninja/commit/e67f60ec877fd37a66b495363133e6c997739c2a))
* **main:** release 0.2.0 ([0f029b9](https://github.com/takehaya/xdp-ninja/commit/0f029b9a92a30704cba37266a5a64f02656587de))
* reset version to 0.0.1 ([36a6ae3](https://github.com/takehaya/xdp-ninja/commit/36a6ae358e4d1dbeb3e0b10adfa2476040960dab))


### ♻️ Code Refactoring

* move test/ to scripts/test/ ([396133a](https://github.com/takehaya/xdp-ninja/commit/396133add0f0d18f5ded21a91e9d4076584935c1))

## [0.2.0](https://github.com/takehaya/xdp-ninja/compare/v0.1.1...v0.2.0) (2026-03-24)


### 🎉 Features

* add install script for one-liner installation ([42643ff](https://github.com/takehaya/xdp-ninja/commit/42643ffb0696c9d600f494966e1c0248dac3a49c))


### 🐛 Bug Fixes

* correct project root path in run_tests.sh after move to scripts/test/ ([1ed7844](https://github.com/takehaya/xdp-ninja/commit/1ed78444062782d5e07288b923f2c8f105968f80))


### 📝 Documentation

* note jq requirement for install script ([82a38cc](https://github.com/takehaya/xdp-ninja/commit/82a38cc63f3dd8299697040a98ba2f1dbea801e7))


### ♻️ Code Refactoring

* move test/ to scripts/test/ ([a8aed03](https://github.com/takehaya/xdp-ninja/commit/a8aed034808a9baa594056afc3d06a0452ebbb21))

## [0.1.1](https://github.com/takehaya/xdp-ninja/compare/v0.1.0...v0.1.1) (2026-03-24)


### 🐛 Bug Fixes

* remove arm64 from goreleaser (CGO cross-compile not available) ([6ca90f7](https://github.com/takehaya/xdp-ninja/commit/6ca90f7340766b65991e29e1718f00e2e889a26e))

## [0.1.0](https://github.com/takehaya/xdp-ninja/compare/v0.0.1...v0.1.0) (2026-03-24)


### 🎉 Features

* add CLI ([3080e9a](https://github.com/takehaya/xdp-ninja/commit/3080e9ae8133b77c02f1b95c3c17aa001b0337a3))
* add core eBPF program generation and packet capture ([4403c86](https://github.com/takehaya/xdp-ninja/commit/4403c8664d9bde91bb4e719d79bc38cde40579cf))


### 🐛 Bug Fixes

* add libbpf-dev to CI, skip tests when bpftool unavailable ([5f26824](https://github.com/takehaya/xdp-ninja/commit/5f26824ff3aa57d9323cecf2d7f1f8ca9eb1716b))
* install bpftool in CI and remove set -e from test runner ([aea8ff2](https://github.com/takehaya/xdp-ninja/commit/aea8ff2e331a46819fc395cc1dddeb18902560b5))
* skip bpftool-dependent tests when bpftool is not functional ([ba25ae8](https://github.com/takehaya/xdp-ninja/commit/ba25ae8146a497f7e9e5c0e72af21836d64eb3d9))


### 📝 Documentation

* add handtest guide and TODO ([a644840](https://github.com/takehaya/xdp-ninja/commit/a64484058c14d6a9ab266146dc2a8edbf4e64188))
* add README, Makefile, and gitignore ([e63930f](https://github.com/takehaya/xdp-ninja/commit/e63930f6b4a77303a4179eed93b2618627c25048))
