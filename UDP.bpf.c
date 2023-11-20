#define KBUILD_MODNAME "foo"
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include "bpf_helpers.h"

#include <net/tcp.h>

struct bpf_map_def SEC("maps") udp_delay_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(unsigned long),
	.max_entries = 1024,
};

struct bpf_map_def SEC("maps") udp_time_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(unsigned long long),
	.max_entries = 1024,	
};

SEC("kprobe/udp_rcv")
int bpf_prog1(struct pt_regs *ctx)
{
	unsigned int pid = bpf_get_current_pid_tgid() >> 32;	
	unsigned long long tm = bpf_ktime_get_ns();

	//computation delay
	unsigned long long *tp = bpf_map_lookup_elem(&udp_time_map, &pid);
	if (tp)
		tm -= *tp;
	else
		return 0;

	//data process and judge
	unsigned int key = tm / 100000000;
	if (key > 50)
		return 0;
	else if (key > 10) 
		key = 10;
	unsigned long *value = bpf_map_lookup_elem(&udp_delay_map, &key);
	if (value)
		*value += 1;
	else {
		unsigned long init_val = 1;
		bpf_map_update_elem(&udp_delay_map, &key, &init_val, BPF_ANY);
	}

	//delete map
	bpf_map_delete_elem(&udp_time_map, &pid);	

	return 0;
}

SEC("kprobe/udp_sendmsg")
int bpf_prog2(struct pt_regs *ctx)
{
	unsigned int pid = bpf_get_current_pid_tgid() >> 32;	
	unsigned long long tm = bpf_ktime_get_ns();
    if (tp)
        return 0;
    bpf_map_update_elem(&udp_time_map, &pid, &tm, BPF_ANY);

	return 0;
}
char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;