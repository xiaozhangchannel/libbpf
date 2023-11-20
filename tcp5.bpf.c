#define KBUILD_MODNAME "foo"
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include "bpf_helpers.h"
#include <net/tcp.h>

struct data_t {
	unsigned long long send;
	unsigned long long recv;
};

struct bpf_map_def SEC("maps") tcp_flow_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(struct data_t),
	.max_entries = 1024,
};

SEC("kprobe/tcp_sendmsg")
int bpf_prog1(struct pt_regs *ctx)
{
	unsigned int key = bpf_get_current_pid_tgid() >> 32;
	unsigned int tmp = (unsigned int)PT_REGS_PARM3(ctx);
	struct data_t *value = bpf_map_lookup_elem(&tcp_flow_map, &key);
	if (value)
		value->send += tmp;
	else {
		struct data_t val = {.send = tmp, .recv = 0};
		bpf_map_update_elem(&tcp_flow_map, &key, &val, BPF_ANY);
	}
	return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int bpf_prog2(struct pt_regs *ctx)
{
	unsigned int key = bpf_get_current_pid_tgid() >> 32;
	int tmp = (int)PT_REGS_PARM2(ctx);
	struct data_t *value = bpf_map_lookup_elem(&tcp_flow_map, &key);
	if (value)
		value->recv += tmp;
	else {
		struct data_t val = {.recv = tmp, .send = 0};
		bpf_map_update_elem(&tcp_flow_map, &key, &val, BPF_ANY);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
unsigned int _version SEC("version") = LINUX_VERSION_CODE;