// Minimal ELF relocation fixtures; only parsed, never loaded or executed.
#define SEC(name) __attribute__((section(name), used))
extern int CONFIG_HZ __attribute__((section(".kconfig")));
extern void external_symbol __attribute__((section(".ksyms")));
extern int external_function(int) __attribute__((section(".ksyms")));
struct record {
  int value;
} __attribute__((preserve_access_index));
SEC("socket/config") int config(void *ctx) { return CONFIG_HZ; }
SEC("socket/symbol") int symbol(void *ctx) { return (long)&external_symbol; }
SEC("socket/function") int function(void *ctx) { return external_function(1); }
SEC("socket/core") int core(struct record *ctx) { return ctx->value; }
char _license[] SEC("license") = "GPL";
