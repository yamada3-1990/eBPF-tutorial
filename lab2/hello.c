//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

#define MAX_PATH 256



struct path_key {
    char path[MAX_PATH];
};

struct {
    // マップの種類(今回はハッシュマップ)
    __uint(type, BPF_MAP_TYPE_HASH);

    // 保存できるデータ(キー/値のペア)の最大件数
    __uint(max_entries, 16384);

    // キーの定義
    __type(key, struct path_key);

    // 値の定義
    __type(value, __u64);
} exec_count SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
    // このプログラムは入力コンテキストであるstruct trace_event_raw_sys_enterの第1引数を読み取る
    const char *filename = (const char *)ctx->args[0];
    
    // * The second argument `ctx->args[1]` is `char *const argv[]` -> array of pointers to strings passed to the 
    //   new program as its command-line arguments

    // * The third argument `ctx->args[2]` is `char *const envp[]` -> array of pointers to strings, conventionally of 
    //   the form key=value, which are passed as the environment of the new program (a.k.a. env variables)

    // Instantiate and store the first argument as our key of the eBPF map using `bpf_probe_read_user_str` which is a
    // handy eBPF helper function, to copy a NULL terminated string from an (unsafe) user address
    struct path_key key = {};
    long n = bpf_probe_read_user_str(key.path, sizeof(key.path), filename);
    // Validate the copy operation was succesfull
    // On success, the strictly positive length of the output string, including the trailing NULL character is returned. 
    // On error, a negative value is returned.
    if (n <= 0) {
        return 0;
    }

    // Check whether this key (binary executable path) already exists in our map and 
    __u64 *val = bpf_map_lookup_elem(&exec_count, &key);
    if (val) {
        // Update the value of the counter under that key we found in the map
        // NOTE: this is not a safe way to update the value - we'll learn about atomic operations in the upcoming tutorial
        *val += 1;
    } else {
        // If this binary is executed for the first time since our eBPF application has been run, we just set the counter value to 1
        __u64 init = 1;
        bpf_map_update_elem(&exec_count, &key, &init, BPF_NOEXIST);
    }

    // Optional: print to debug
    bpf_printk("execve: %s\n", key.path);

    return 0;
}