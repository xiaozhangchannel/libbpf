#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_established, struct sock *sk){
    struct tcp_sock *tp =(struct tcp_sock *)sk;
    
    u32 snd_cwnd = BPF_CORE_READ(tp,snd_cwnd);  //tp->snd_cwnd
    u32 snd_ssthresh = BPF_CORE_READ(tp,snd_ssthresh);//tp->snd_ssthresh
    u32 sndbuf = BPF_CORE_READ(sk,sk_sndbuf);//sk->sk_sndbuf
    u32 sk_wmem_queued = BPF_CORE_READ(sk,sk_wmem_queued);//sk->sk_wmem_queued


    u16 lport = BPF_CORE_READ(sk,__sk_common.skc_num); //sk->__sk_common.skc_num
    u16 dport = BPF_CORE_READ(sk,__sk_common.skc_dport); //sk->__sk_common.skc_dport
    //u32 state = BPF_CORE_READ(sk,sk_state); //sk->sk_state
    u32 saddr = BPF_CORE_READ(sk,__sk_common.skc_rcv_saddr); //sk->__sk_common.skc_rcv_saddr
    u32 daddr = BPF_CORE_READ(sk,__sk_common.skc_daddr); //sk->__sk_common.skc_daddr

    bpf_printk("%d,%d,%d,%d,%d,%d,%d,%d",snd_cwnd,snd_ssthresh,sndbuf,sk_wmem_queued,lport,dport,saddr,daddr);
}