//go:build ignore
// 上記はビルドタグ
// go buildやgo install実行時にファイルがコンパイル対象から外される



#include "vmlinux.h"
// $ bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
// で生成されたファイル


#include <bpf/bpf_helpers.h>
// https://github.com/libbpf/libbpf/blob/master/src/bpf_helpers.h
// SEC()やbpf_printk()といったヘルパー関数をインポートする


char _license[] SEC("license") = "GPL";
// カーネルヘルパーを呼び出す場合、eBPFプログラムにはこの行が必要


SEC("tracepoint/syscalls/sys_enter_execve")
// SECは続く関数(ここではhandle_execve_tp())をELFセクション内に配置する
// -> この関数はsys_enter_execve専用のコードですよ、という情報をプログラム内に書き込む
// eBPFプログラムのエントリーポイントでもある
// lsコマンドを打った場合、カーネルはsys_enter_execveを呼び出し、handle_execve_tp()が呼び出されるということ


int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
    // ctxはカーネルが渡してくれる構造体で、どのユーザが実行したか、どんなコマンドを打ったかなどの情報が書かれている
    // 構造体の定義がvmlinux.hに書かれている

    bpf_printk("Hello world form eBPF");
    // カーネルのログに出力する
    // $ sudo cat /sys/kernel/debug/tracing/trace_pipe で確認できる
    // busyとか言われたら $ sudo cat /sys/kernel/debug/tracing/trace

    return 0;
    // こういうトレースポイントのeBPFプログラムは通常0を返す
    // 一般的に戻り値は無視される
    // システムコールの動作自体を変更するとかなら戻り値が重要
}