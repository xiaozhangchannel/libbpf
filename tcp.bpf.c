#define KBUILD_MODNAME "foo"
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include "bpf_helpers.h"

#include <net/tcp.h>
#include <linux/tcp.h>

#define _(P) ({typeof(P) val; bpf_probe_read(&val, sizeof(val), &P); val;})

struct bpf_map_def SEC("maps") tcp_delay_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(unsigned long),
	.max_entries = 1024,
};

SEC("kprobe/tcp_rcv_established")
int bpf_prog1(struct pt_regs *ctx)
{
	//get srtt
 	struct sock *sk = (void *)PT_REGS_PARM1(ctx);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int srtt = 0;

	//data process and judge
	unsigned int key = 0;
	unsigned long init_val = 1;
	unsigned long *value;

	srtt = _(tp->srtt_us);
	srtt >>= 3;
	key = srtt / 100000;
	if (key > 5) 
		key = 5;

	value = bpf_map_lookup_elem(&tcp_delay_map, &key);
	if (value)
		*value += 1;
	else
		bpf_map_update_elem(&tcp_delay_map, &key, &init_val, BPF_ANY);

	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;