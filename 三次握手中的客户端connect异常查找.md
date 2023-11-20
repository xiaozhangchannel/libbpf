# 三次握手中的客户端connect异常

在 TCP 连接中，客户端在发起连接请求前会先确定一个客户端端口，然后用这个端口去和服务器端进行握手建立连接。客户端在发起 connect 系统调用的时候，主要工作就是端口选择。确切来说是端口选择的异常

#### connect 调用过程

```
SYSCALL_DEFINE3(connect
	|->inet_stream_ops
		|->inet_stream_connect
			|->tcp_v4_connect
				|->tcp_set_state(sk, TCP_SYN_SENT);设置状态为TCP_SYN_SENT
			 	|->inet_hash_connect
				|->tcp_connect
```

在客户端机上调用 connect 函数的时候，事实上会进入到内核的系统调用源码中进行执行。

```
//file: net/socket.c
SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr,
  int, addrlen)
{
 struct socket *sock;

 //根据用户 fd 查找内核中的 socket 对象
 sock = sockfd_lookup_light(fd, &err, &fput_needed);

 //进行 connect
 err = sock->ops->connect(sock, (struct sockaddr *)&address, addrlen,
     sock->file->f_flags);
 ...
}
```

这段代码首先根据用户传入的 fd（文件描述符）来查询对应的 socket 内核对象。接下来 sock->ops->connect 其实调用的是 inet_stream_connect 函数。

```
//file: ipv4/af_inet.c
int inet_stream_connect(struct socket *sock, ...)
{ 
 ...
 __inet_stream_connect(sock, uaddr, addr_len, flags);
}

int __inet_stream_connect(struct socket *sock, ...)
{
 struct sock *sk = sock->sk;

 switch (sock->state) {
  case SS_UNCONNECTED:
   err = sk->sk_prot->connect(sk, uaddr, addr_len);
   sock->state = SS_CONNECTING;
   break;
 }
 ...
}
```

刚创建完毕的 socket 的状态就是 SS_UNCONNECTED，所以在 __inet_stream_connect 中的 switch 判断会进入到 case SS_UNCONNECTED 的处理逻辑中。

sk->sk_prot->connect 实际上对应的是 tcp_v4_connect 方法。

tcp_v4_connect 函数，它位于 net/ipv4/tcp_ipv4.c。

```
//file: net/ipv4/tcp_ipv4.c
int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
 //设置 socket 状态为 TCP_SYN_SENT
 tcp_set_state(sk, TCP_SYN_SENT);

 //动态选择一个端口
 err = inet_hash_connect(&tcp_death_row, sk);

 //函数用来根据 sk 中的信息，构建一个完成的 syn 报文，并将它发送出去。
 err = tcp_connect(sk);
}
```

在 tcp_v4_connect 中看到选择端口的函数，就是 inet_hash_connect。

#### 选择可用端口

```
//file:net/ipv4/inet_hashtables.c
int inet_hash_connect(struct inet_timewait_death_row *death_row,
        struct sock *sk)
{
 return __inet_hash_connect(death_row, sk, inet_sk_port_offset(sk),
   __inet_check_established, __inet_hash_nolisten);
}
```

在调用 __inet_hash_connect 时传入的两个重要参数。

- inet_sk_port_offset(sk)：这个函数是根据要连接的目的 IP 和端口等信息生成一个随机数。
- __inet_check_established：检查是否和现有 ESTABLISH 的连接是否冲突的时候用的函数

 __inet_hash_connect。

<img src="三次握手中的客户端connect异常查找.assets/v2-2f2653d04acd6df86da9ff864f71248b_r.jpg" alt="img" style="zoom: 50%;" />

长连接（长期连接）和短连接（短期连接）是两种不同的网络连接方式。

1. 长连接：长连接是指在客户端和服务器之间建立一次连接后，可以持久保持该连接的状态进行双向通信。在长连接中，客户端和服务器可以随时进行数据的传输和接收，而无需频繁地建立和关闭连接。长连接通常用于实时通信、实时数据传输等场景，能够提供更快的响应和更高的性能效率。
2. 短连接：短连接是指在客户端和服务器之间进行一次请求和响应后，立即关闭连接。在短连接中，每次请求都需要重新建立连接，并在完成后立即关闭连接。短连接适用于简单的请求和响应场景，如传统的 HTTP 请求。短连接相对于长连接来说，每次连接都需要额外的开销，但在一些场景中，短连接可以更好地控制连接资源和避免连接的长时间空闲。

选择长连接还是短连接取决于具体应用的需求和场景。长连接适合需要保持实时通信或频繁数据交互的场景，而短连接适合于简单的单向请求和响应。

```
//file:net/ipv4/inet_hashtables.c
int __inet_hash_connect(...)
{
 //是否绑定过端口
 const unsigned short snum = inet_sk(sk)->inet_num;

 //获取本地端口配置
 inet_get_local_port_range(&low, &high);
  remaining = (high - low) + 1;

 if (!snum) {
  //遍历查找
  for (i = 1; i <= remaining; i++) {
   port = low + (i + offset) % remaining;
   ...
  }
 }
}
```

在这个函数中首先判断了 inet_sk(sk)->inet_num，如果我们调用过 bind绑定端口，那么这个函数会选择好端口并设置在 inet_num 上。没有调用过 bind， snum 为 0。

接着调用 inet_get_local_port_range，这个函数读取的是 net.ipv4.ip_local_port_range 这个内核参数。来读取可用的端口范围。

##### 获取端口号范围

首先，我们从内核中获取connect能够使用的端口号范围，在这里采用了Linux中的顺序锁(seqlock)。

```
void inet_get_local_port_range(int *low, int *high)
{
	unsigned int seq;

	do {
		// 顺序锁
		seq = read_seqbegin(&sysctl_local_ports.lock);

		*low = sysctl_local_ports.range[0];
		*high = sysctl_local_ports.range[1];
	} while (read_seqretry(&sysctl_local_ports.lock, seq));
}
```

顺序锁事实上就是结合内存屏障等机制的一种乐观锁，主要依靠一个序列计数器。在读取数据之前和之后，序列号都被读取,如果两者的序列号相同，说明在读操作的时候没有被写操作打断过。 这也保证了上面的读取变量都是一致的，也即low和high不会出现low是改前值而high是改后值得情况。

##### 通过hash决定端口号起始搜索范围

在Linux上进行connect,内核给其分配的端口号并不是线性增长的，但是也符合一定的规律。

```
int __inet_hash_connect(...)
{
		// 注意，这边是static变量
		static u32 hint;
		// 这边的port_offset是用对端ip:port hash的一个值
		// 也就是说对端ip:port固定,port_offset固定
		u32 offset = hint + port_offset;
		for (i = 1; i <= remaining; i++) {
			port = low + (i + offset) % remaining;
			/* port是否占用check */
			....
			goto ok;
		}
		.......
ok:
		hint += i;
		......
}
```

这里面有几个小细节，为了安全原因，Linux本身用对端ip:port做了一次hash作为搜索的初始offset，所以不同远端ip:port初始搜索范围可以基本是不同的！但同样的对端ip:port初始搜索范围是相同的！

![img](三次握手中的客户端connect异常查找.assets/v2-a26507e1c2fd5263457fc8a76bee6383_r.jpg)

接下来进入到了 for 循环中。其中offset 就是通过 inet_sk_port_offset(sk) 计算出的随机数。那这段循环的作用就是从某个随机数开始，把整个可用端口范围来遍历一遍。直到找到可用的端口后停止。

```
//file:net/ipv4/inet_hashtables.c
int __inet_hash_connect(...)
{
 for (i = 1; i <= remaining; i++) {
  port = low + (i + offset) % remaining;

  //查看是否是保留端口，是则跳过
  if (inet_is_reserved_local_port(port))
   continue;

  // 查找和遍历已经使用的端口的哈希链表
  head = &hinfo->bhash[inet_bhashfn(net, port,
    hinfo->bhash_size)];
  inet_bind_bucket_for_each(tb, &head->chain) {

   //如果端口已经被使用
   if (net_eq(ib_net(tb), net) &&
       tb->port == port) {

                //通过 check_established 继续检查是否可用
    if (!check_established(death_row, sk,
       port, &tw))
     goto ok;
   }
  }

  //未使用的话，直接 ok
  goto ok;
 }

 return -EADDRNOTAVAIL;
ok: 
 ...  
}
```

首先判断的是 inet_is_reserved_local_port，这个很简单就是判断要选择的端口是否在 net.ipv4.ip_local_reserved_ports 中，在的话就不能用。

整个系统中会维护一个所有使用过的端口的哈希表，它就是 hinfo->bhash。接下来的代码就会在这里进行查找。**如果在哈希表中没有找到，那么说明这个端口是可用的。至此端口就算是找到了。**

遍历完所有端口都没找到合适的，就返回 -EADDRNOTAVAIL。

#### 端口被使用过怎么办，已经建立连接的端口？

这个问题在 __inet_hash_connect函数中进行处理，

```
//file:net/ipv4/inet_hashtables.c
int __inet_hash_connect(...)
{
 for (i = 1; i <= remaining; i++) {
  port = low + (i + offset) % remaining;

  ...
  //如果端口已经被使用
  if (net_eq(ib_net(tb), net) &&
       tb->port == port) {
   //通过 check_established 继续检查是否可用
   if (!check_established(death_row, sk, port, &tw))
    goto ok;
  }
 }
}
```

port 已经在 bhash 中如果已经存在，就表示有其它的连接使用过该端口了。**注意，如果 check_established 返回 0，该端口仍然可以接着使用！**。

check_established 作用就是检测现有的 TCP 连接中是否四元组和要建立的连接四元素完全一致。如果不完全一致，那么该端口仍然可用！！！

四元组

![image-20230827103258508](三次握手中的客户端connect异常查找.assets/image-20230827103258508.png)

如果两对儿四元组中只要任意一个元素不同，都算是两条不同的连接。

例如：

```
连接1：192.168.1.101 5000 192.168.1.100 8090
连接2：192.168.1.101 5000 192.168.1.100 8091
```

这个 check_established ，实际上使用的是 __inet_check_established。

```
//file: net/ipv4/inet_hashtables.c
static int __inet_check_established(struct inet_timewait_death_row *death_row,
        struct sock *sk, __u16 lport,
        struct inet_timewait_sock **twp)
{
 //找到hash队列
 struct inet_ehash_bucket *head = inet_ehash_bucket(hinfo, hash);

 //遍历看看有没有四元组一样的，一样的话就报错
 sk_nulls_for_each(sk2, node, &head->chain) {
  if (sk2->sk_hash != hash)
   continue;
  if (likely(INET_MATCH(sk2, net, acookie,
          saddr, daddr, ports, dif)))
   goto not_unique;
 }

unique:
 //要用了，记录，返回 0 （成功）
 return 0;
not_unique:
 return -EADDRNOTAVAIL; 
}
```

该函数首先找到 inet_ehash_bucket，这个和 bhash 类似，只不过是所有 ESTABLISH 状态的 socket 组成的哈希表。然后遍历这个哈希表，使用 INET_MATCH 来判断是否可用。

这里 INET_MATCH 源码如下：

```
// include/net/inet_hashtables.h
#define INET_MATCH(__sk, __net, __cookie, __saddr, __daddr, __ports, __dif) \
 ((inet_sk(__sk)->inet_portpair == (__ports)) &&  \
  (inet_sk(__sk)->inet_daddr == (__saddr)) &&  \
  (inet_sk(__sk)->inet_rcv_saddr == (__daddr)) &&  \
  (!(__sk)->sk_bound_dev_if ||    \
    ((__sk)->sk_bound_dev_if == (__dif)))  &&  \
  net_eq(sock_net(__sk), (__net)))
```

在 INET_MATCH 中将 _ _saddr、_ _daddr、__ports 都进行了比较。

如果 MATCH，就是说就四元组完全一致的连接，所以这个端口不可用。也返回 -EADDRNOTAVAIL。

如果不 MATCH，哪怕四元组中有一个元素不一样，例如服务器的端口号不一样，那么就 return 0，表示该端口仍然可用于建立新连接。

再回到 tcp_v4_connect，这时我们的 inet_hash_connect 已经返回了一个可用端口了。接下来就进入到 tcp_connect，来发送 syn 包。如下源码所示。

```
//file: net/ipv4/tcp_ipv4.c
int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
 ......

 //动态选择一个端口
 err = inet_hash_connect(&tcp_death_row, sk);

 //函数用来根据 sk 中的信息，构建一个完成的 syn 报文，并将它发送出去。
 err = tcp_connect(sk);
}
```





**当端口不充足的时候**，会导致 connect 系统调用的时候过多地执行自旋锁等待与 Hash 查找，会引起 CPU 开销上涨。严重情况下会耗光 CPU，影响用户业务逻辑的执行。改善方法：

- 通过调整 ip_local_port_range 来尽量加大端口范围
- 尽量复用连接，使用长连接来削减频繁的握手处理
- 改换查找算法

![image-20230731133434208](三次握手中的客户端connect异常查找.assets/image-20230731133434208.png)

![image-20230731134100250](三次握手中的客户端connect异常查找.assets/image-20230731134100250.png)



tcp_connect_time.bpf.c

```
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "tcp_connect_time.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 10800);
	__type(key, u32);
	__type(value, struct delay);
} start SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");



SEC("kprobe/inet_hash_connect")
int BPF_KPROBE(inet_hash_connect, struct sock* sk){

	u32 pid = bpf_get_current_pid_tgid();
	u64 exec = bpf_ktime_get_ns()/1000;	

	struct delay data = {};
	data.pid = pid;
	data.exec = exec;
	data.exit = 0;
	data.delay = 0;
    bpf_map_update_elem(&start, &pid, &data, BPF_ANY);

	return 0;
}


SEC("kretprobe/inet_hash_connect")
int BPF_KRETPROBE(inet_hash_connect_exit, struct sock* sk){

	u32 pid = bpf_get_current_pid_tgid();
	u64 exit = bpf_ktime_get_ns()/1000;

	struct delay *delay_exec = bpf_map_lookup_elem(&start, &pid);
	if (delay_exec == 0) 
	{
		return 0;
	}

	u64 delay = exit - delay_exec->exec;
	
	struct delay data = {};
	
	data.pid = pid;
	data.exec = delay_exec->exec;
	data.exit = exit;
	data.delay = delay;
	
	bpf_map_update_elem(&start, &pid, &data, BPF_ANY);
	
	return 0;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect, struct sock* sk){
    u32 pid = bpf_get_current_pid_tgid();


	struct delay *delay;
	delay = bpf_map_lookup_elem(&start, &pid);
	if(!delay) {
		return 0;
	}
    
    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);


    struct ip_data *data;
    data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
    if(!data){
        return 0;
    }


    data->pid = pid;
	data->exec = delay->exec;
	data->exit = delay->exit;
	data->delay = delay->delay;
    data->saddr = saddr;
    data->daddr = daddr;
    data->dport = dport;
    data->sport = sport;

    bpf_ringbuf_submit(data, 0);


    return 0;
}
```

tcp_connect_time.c

```
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>


#include "tcp_connect_time.h"
#include "tcp_connect_time.skel.h"


static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG )
		return 0;
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct ip_data *d = data;
    char s_str[INET_ADDRSTRLEN];
	char d_str[INET_ADDRSTRLEN];

    struct in_addr src;
	struct in_addr dst;
	char s_ipv4_port_str[INET_ADDRSTRLEN+6];
	char d_ipv4_port_str[INET_ADDRSTRLEN+6];

	src.s_addr = d->saddr;
	dst.s_addr = d->daddr;
	sprintf(s_ipv4_port_str,"%s:%d",inet_ntop(AF_INET, &src, s_str, sizeof(s_str)),d->sport);
	sprintf(d_ipv4_port_str,"%s:%d",inet_ntop(AF_INET, &dst, d_str, sizeof(d_str)),d->dport);
	printf("%-22s %-22s %-11d %-11llu %-11llu %-11d\n",
		s_ipv4_port_str,
		d_ipv4_port_str,
		d->pid,
		d->exec,
		d->exit,
		d->delay
	);


    return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct tcp_connect_time_bpf *skel;
	int err = 0;

    

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = tcp_connect_time_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

    /* Load & verify BPF programs */
	err = tcp_connect_time_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    /* Attach tracepoints */
	err = tcp_connect_time_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */

	
	printf("%-22s %-22s %-11s %-11s %-11s %-11s \n",
        "SADDR:SPORT", "DADDR:DPORT", "PID", "EXEC", "EXIT", "DElAY");
	

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	tcp_connect_time_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
```

tcp_connect_time.h

```
#ifndef __TCP_CONNECT_TIME_H
#define __TCP_CONNECT_TIME_H

#define u8 unsigned char
#define u16 unsigned short
#define u32 unsigned int
#define u64 unsigned long long


struct delay {
	u32 pid;
	u64 exec;
	u64 exit;
	u32 delay;
};

struct ip_data {
	u32 pid;
	u64 exec;
	u64 exit;
	u32 delay;
	u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};


#endif
```

