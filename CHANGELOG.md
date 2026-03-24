# Changelog

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
