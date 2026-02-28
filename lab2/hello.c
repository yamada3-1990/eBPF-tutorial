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

    // 保存できるデータ(key/valueのペア)の最大件数
    __uint(max_entries, 16384);

    // keyの定義
    __type(key, struct path_key);

    // valueの定義
    __type(value, __u64);
} exec_count SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
    // このプログラムは入力コンテキストであるstruct trace_event_raw_sys_enter(vmlinux.hの中で定義されている)の第1引数を読み取る
    // execveシステムコールの定義：int execve(const char *pathname, char *const _Nullable argv[], char *const _Nullable envp[]);
    // だからargs[0]を指定するとpathnameが返ってくる
    // pathname: 実行するファイルのパス
    // argv: コマンドライン引数
    // envp: 環境変数
    const char *filename = (const char *)ctx->args[0];
    
    struct path_key key = {};

    // pathnameをインスタンス化する
    // bpf_probe_read_user_str(ヘルパー関数): 安全でないユーザー空間のアドレスから文字列をコピーするための関数
    long n = bpf_probe_read_user_str(key.path, sizeof(key.path), filename);

    // コピーが成功したかをバリデーションする
    // 成功したら出力文字列の長さ
    // 失敗したら負の値
    if (n <= 0) {
        return 0;
    }

    // key(pathname)が既にマップ内にあるかを確認する

    // bpf_map_lookup_elem(ヘルパー関数):
    // void *bpf_map_lookup_elem(void *map, void *key);
    // マップに保存されている値(value)へのポインタを探して返す
    // https://prototype-kernel.readthedocs.io/en/latest/bpf/ebpf_maps.html#:~:text=Kernel%2Dside%20eBPF%20program
    __u64 *val = bpf_map_lookup_elem(&exec_count, &key);

    // keyが既にマップ内にあったら
    if (val) {
        // keyに対応するカウンターの値(value)を更新する
        *val += 1;
    } else {
        // keyが無かったら(=初めて実行された)
        // keyに対応するカウンターの値(value)を1に設定
        __u64 init = 1;

        // bpf_map_update_elem(ヘルパー関数):
        // int bpf_map_update_elem(void *map, void *key, void *value, unsigned long long flags);
        // マップに新しいkey/valueペアを追加または更新
        // flagsパラメータは更新の動作を制御する
        // 第4引数のフラグは3種類ある
        // BPF_ANY: 新しく作成するまたはアップデート
        // BPF_NOEXIST: キーが存在しない場合のみ
        // BPF_EXIST: キーが存在する場合のみ
        bpf_map_update_elem(&exec_count, &key, &init, BPF_NOEXIST);
    }

    // デバッグ用
    bpf_printk("execve: %s\n", key.path);

    return 0;
}