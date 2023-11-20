#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "tcp_connect.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");


SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept, struct sock *sk){
    struct tcp_sock *tp = (struct tcp_sock *)sk;

    u32 pid = bpf_get_current_pid_tgid();

    u16 protocol = BPF_CORE_READ(sk, sk_protocol);
    if (protocol != IPPROTO_TCP)
        return 0;

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    if(family == AF_INET){
        u64 ts_us = bpf_ktime_get_ns() / 1000;;
        u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);


        struct ipv4_data_t *data4;
        data4 = bpf_ringbuf_reserve(&rb, sizeof(*data4), 0);
        if(!data4)
            return 0;

        data4->ts_us = bpf_ktime_get_ns() / 1000;
        data4->pid = pid;
        data4->daddr = daddr;
        data4->sport = sport;
        data4->dport = __bpf_ntohs(dport);
        data4->ip = 4;
        data4->direction = 0;
        bpf_get_current_comm(data4->task, sizeof(data4->task));

        bpf_ringbuf_submit(data4, 0);
        
    }else if(family == AF_INET6){
        u64 ts_us = bpf_ktime_get_ns() / 1000;;
        u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

        struct ipv6_data_t *data6;
        data6 = bpf_ringbuf_reserve(&rb, sizeof(*data6), 0);
        if(!data6)
            return 0;

        data6->ts_us = bpf_ktime_get_ns() / 1000;
        data6->pid = pid;
        data6->daddr = daddr;
        data6->sport = sport;
        data6->dport = __bpf_ntohs(dport);
        data6->ip = 6;
        data6->direction = 0;
        bpf_get_current_comm(data6->task, sizeof(data6->task));

        bpf_ringbuf_submit(data6, 0);
    }

    return 0;
}



struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10800);
	__type(key, u32);
	__type(value, struct sock *);
} ipv4_data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10800);
	__type(key, u32);
	__type(value, struct sock *);
} ipv6_data SEC(".maps");


static __always_inline int
enter_tcp_v4_connect(struct pt_regs *ctx, struct sock *sk){
    u32 pid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&ipv4_data, &pid, &sk, 0);

    return 0;
}


static __always_inline int
enter_tcp_v6_connect(struct pt_regs *ctx, struct sock *sk){
    u32 pid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&ipv6_data, &pid, &sk, 0);

    return 0;
}


static __always_inline int
exit_tcp_v4_connect(struct pt_regs *ctx, struct sock* sk){

	u32 pid = bpf_get_current_pid_tgid();

	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&ipv4_data, &pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

    // pull in details
    struct sock *skp = *skpp;
    u16 dport = BPF_CORE_READ(skp, __sk_common.skc_dport);


    u64 ts_us = bpf_ktime_get_ns() / 1000;;
    u32 daddr = BPF_CORE_READ(skp, __sk_common.skc_daddr);
    u16 sport = BPF_CORE_READ(skp, __sk_common.skc_num);
    

    struct ipv4_data_t *data4;
    data4 = bpf_ringbuf_reserve(&rb, sizeof(*data4), 0);
    if(!data4)
        return 0;

    data4->ts_us = bpf_ktime_get_ns() / 1000;
    data4->pid = pid;
    data4->daddr = daddr;
    data4->sport = sport;
    data4->dport = __bpf_ntohs(dport);
    data4->ip = 4;
    data4->direction = 0;
    bpf_get_current_comm(data4->task, sizeof(data4->task));

    bpf_ringbuf_submit(data4, 0);
    bpf_map_delete_elem(&ipv4_data, &pid);

	return 0;
}

static __always_inline int
exit_tcp_v6_connect(struct pt_regs *ctx, struct sock* sk){

	u32 pid = bpf_get_current_pid_tgid();

	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&ipv6_data, &pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

    // pull in details
    struct sock *skp = *skpp;
    u16 dport = BPF_CORE_READ(skp, __sk_common.skc_dport);


    u64 ts_us = bpf_ktime_get_ns() / 1000;;
    u32 daddr = BPF_CORE_READ(skp, __sk_common.skc_daddr);
    u16 sport = BPF_CORE_READ(skp, __sk_common.skc_num);

    struct ipv6_data_t *data6;
    data6 = bpf_ringbuf_reserve(&rb, sizeof(*data6), 0);
    if(!data6)
        return 0;

    data6->ts_us = bpf_ktime_get_ns() / 1000;
    data6->pid = pid;
    data6->daddr = daddr;
    data6->sport = sport;
    data6->dport = __bpf_ntohs(dport);
    data6->ip = 6;
    data6->direction = 0;
    bpf_get_current_comm(data6->task, sizeof(data6->task));

    bpf_ringbuf_submit(data6, 0);
    bpf_map_delete_elem(&ipv6_data, &pid);

	return 0;
}


SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
	return enter_tcp_v4_connect(ctx, sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret, struct sock *sk)
{
	return exit_tcp_v4_connect(ctx, sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk)
{
	return enter_tcp_v6_connect(ctx, sk);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(tcp_v6_connect_ret, struct sock *sk)
{
	return exit_tcp_v6_connect(ctx, sk);
}