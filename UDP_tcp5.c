#include <stdio.h>
#include <unistd.h>
#include "libbpf.h"
#include "bpf_load.h"

struct val {
	unsigned long long send;
	unsigned long long recv;
};

struct data {
	unsigned int pid;
	struct val value;
	unsigned long long total;
};

int main(int argc, char **argv)
{
	//load ebpf
	char filename[256];

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	//read map's data to user buffer
	unsigned int next_key, lookup_key;
	struct data buffer[1024];
	unsigned int num;
	int fd = map_fd[0];
	struct val value; 
	int count;
	int i, j;

loop:
Reread:
	sleep(5);
	lookup_key = -1;
	num = 0;
	while (bpf_map_get_next_key(fd, &lookup_key, &next_key) == 0) {
		if (buffer[0].pid == next_key)
			num = 0;

		num++;	
		lookup_key = next_key;
		bpf_map_lookup_elem(fd, &lookup_key, &value);
		buffer[num].pid = lookup_key;
		buffer[num].value = value;
		buffer[num].total = value.send + value.recv;
		if (num == 1) 
			buffer[0].pid = lookup_key;	
	}
	if (bpf_map_lookup_elem(fd, &buffer[0].pid, &value))
		goto Reread;	

	//number
	count = 5;
	if (num < 5)
		count = num;

	//sort
	for (i = 1; i <= count; i++) {
		for (j = i+1; j <= num; j++) {
			if (buffer[i].total < buffer[j].total) {
				struct data tmp;
				tmp = buffer[i];
				buffer[i] = buffer[j];
				buffer[j] = tmp;
			}
		}	
	}	

	//print top5
	for (i = 1; i <= count; i++)
		printf("udp:pid=%5u, send=%15lld, recv=%15lld, total=%15lld\n", buffer[i].pid, buffer[i].value.send, buffer[i].value.recv, buffer[i].total);
	
	printf("**********************************\n\n");
	goto loop;

	return 0;
}