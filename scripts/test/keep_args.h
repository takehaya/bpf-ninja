// keep_args.h — fentry/fexit で読めるように関数引数を ABI に残すヘルパ。
//
// 未使用の引数はコンパイラが ABI (r1..r5) から落とすことがある。そうなると
// xdp-ninja の fentry/fexit 観測 (--arg-filter など) がその引数を読めなくなる。
// KEEP_ARGS(a, b, ...) を関数本体の先頭に置くと各引数を「使用済み」に固定し、
// ABI から落ちるのを防ぐ。対象プログラムの .c に #include して使う。
//
// 使い方の例:
//
//   __attribute__((noinline)) int capture_point(__u64 imsi, __u32 teid) {
//       KEEP_ARGS(imsi, teid);
//       return 0;
//   }
#ifndef XDP_NINJA_KEEP_ARGS_H
#define XDP_NINJA_KEEP_ARGS_H

// barrier_var は変数をレジスタに読み込んで「使用済み」にし、未使用引数が ABI
// から落ちて fentry/fexit (xdp-ninja の arg-filter 等) で読めなくなるのを防ぐ。
// 入力専用の制約なので const 修飾された引数でもコンパイルが通る (ABI に残す目的
// にはこれで十分)。libbpf (bpf_helpers.h)
// が同名マクロを提供していればそれを使う。
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : : "r"(var))
#endif

// KEEP_ARGS は可変長の各変数へ barrier_var を自動展開する。
// BPF の関数引数上限は 5 (r1..r5) なので最大 5 個。
#define KA_1(f, a) f(a);
#define KA_2(f, a, ...)                                                        \
  f(a);                                                                        \
  KA_1(f, __VA_ARGS__)
#define KA_3(f, a, ...)                                                        \
  f(a);                                                                        \
  KA_2(f, __VA_ARGS__)
#define KA_4(f, a, ...)                                                        \
  f(a);                                                                        \
  KA_3(f, __VA_ARGS__)
#define KA_5(f, a, ...)                                                        \
  f(a);                                                                        \
  KA_4(f, __VA_ARGS__)
#define KA_PICK(_1, _2, _3, _4, _5, N, ...) N
#define FOR_EACH(f, ...)                                                       \
  KA_PICK(__VA_ARGS__, KA_5, KA_4, KA_3, KA_2, KA_1)(f, __VA_ARGS__)
// do/while(0) で単一文にまとめ、`if (...) KEEP_ARGS(...); else ...` のような
// 文脈でも安全にする。
#define KEEP_ARGS(...)                                                         \
  do {                                                                         \
    FOR_EACH(barrier_var, __VA_ARGS__)                                         \
  } while (0)

#endif /* XDP_NINJA_KEEP_ARGS_H */
