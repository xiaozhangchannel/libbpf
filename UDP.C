#include <stdio.h>
#include <unistd.h>
#include "libbpf.h"
#include "bpf_load.h"

int main(int argc, char **argv)
{
	//load ebpf
	char filename[256];

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	
	//read map and display per 5s
	int fd = map_fd[0];
	unsigned int key;
loop:
	sleep(5);

	unsigned long value;
	for (key = 0; key <= 10; key++) {
		value = 0;
		bpf_map_lookup_elem(fd, &key, &value);
		if (key < 10)
			printf("The statistical number of time in the range of %u ms to %u ms is %lu\n", key*100, (key+1)*100, value);
		else
			printf("The statistical number of time in the range of 1s to 5s was %lu\n", value);
	}

	printf("\n");
	goto loop;

	return 0;
}