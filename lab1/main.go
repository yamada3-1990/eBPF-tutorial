package main
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf hello hello.c
// go generrateを実行した際に、上記のコマンドが実行される
// hello.cをhello_bpf.goにコンパイルして、hello_bpf.goを生成する

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// デフォルト（Linux 5.11 未満）では、Linux はプロセスが RAM 内にロックできるメモリ量を制限するRLIMIT_MEMLOCKが設定されている
    // eBPFのマップやプログラムはこの制限対象のメモリを利用している
    // この制限を引き上げるか削除しないと、大きなeBPFプログラムやマップをロードする際に「operation not permitted」や「memory locked limit exceeded」といったエラーでする
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// コンパイルされたeBPF ELFオブジェクトをカーネルにロードする
	// ここのヘルパー関数は`hello_bpf.go(自動生成済み)`で定義されている
	var objs helloObjects
	if err := loadHelloObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// ロードされた eBPFプログラムを、eBPFトレースポイントのフックポイントにアタッチする
	// eBPFプログラムをカーネル内に入れて、イベント(ここではsys_enter_execve)と繋ぐ
	// イベント(ここではsys_enter_execve)が発生するたびにeBPFプログラムが実行されるようにする
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecveTp, nil)
	if err != nil {
		log.Fatalf("Attaching Tracepoint: %s", err)
	}
	defer tp.Close()

	log.Println("eBPF program attached to tracepoint. Press Ctrl+C to exit.")

	// SIGINT/SIGTERMを待つ
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	log.Println("Received signal, exiting...")
}