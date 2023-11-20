// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "tcp_backlog.skel.h"

static volatile sig_atomic_t stop;
//sig_atomic_t是C语言标准库中定义的一个整数类型，用于在信号处理函数中表示原子操作的整数类型。

static void sig_int(int signo)
{
	stop = 1;
}

int main(int argc, char **argv)
{
	struct tcp_backlog_bpf *skel;
	int err;

	/* Open load and verify BPF application */
	skel = tcp_backlog_bpf__open_and_load();
	//tcp_a_bpf__open_and_load()函数的功能是打开并加载TCP分析的BPF（Berkeley Packet Filter）程序的骨架。
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		//stderr是C语言标准库提供的一个预定义文件指针，用于表示标准错误输出流。
		//fprintf函数被用于将错误消息输出到标准错误流（stderr）。
		return 1;
	}

	/* Attach tracepoint handler */
	err = tcp_backlog_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
    //SIGINT是表示键盘中断信号的常量。它的值通常是2，
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		//在代码中，signal(SIGINT, sig_int)用于设置对SIGINT信号的处理函数为sig_int函数。如果设置信号处理函数失败，即signal()函数返回SIG_ERR，那么代码会通过fprintf函数将错误消息输出到标准错误流(stderr)，其中包含了通过strerror()函数获取的具体错误信息。
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	while (!stop) {
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	tcp_backlog_bpf__destroy(skel);
	return -err;
}