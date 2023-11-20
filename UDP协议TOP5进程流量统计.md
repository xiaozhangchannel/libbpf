# UDP协议TOP5进程流量统计

**指标解读**

流量：用户态程序发送和接收的数据大小。

**项目需求**

在网络传输层以进程粒度提取udp协议发送数据包所用的流量和接收数据包所用的流量信息，并计算进程粒度下的流量总和，输出TOP5进程udp流量统计。

**提取思路**

UDP协议流量发送和接收的执行流程如下：

<img src="C:\Users\22803\AppData\Roaming\Typora\typora-user-images\image-20231117181000872.png" alt="image-20231117181000872" style="zoom:50%;" />

通过上面的执行流程分析，选取的监控点：

**发送函数原型：**

```c
int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
```

可以看到它有三个参数：

- `struct sock *sk`表示发送数据对应的套接字
- `struct msghdr *msg`表示要发送的数据
- `size_t len`表示发送数据的大小

统计udp协议发送流量，只需要监控内核中的`udp_sendmsg`函数。当它触发时，对其发送信息的大小做累加，也就是kprobe监控`udp_sendmsg`，提取第三个参数做累加，一段时间内的累加值就是udp协议在此期间发送的流量大小。

**接收函数原型：**

```c
int udp_recvmsg(struct sock *sk, struct msghdr *msg，size_t len, int noblock , int flags, int *addr_len);
```

可以看到它有六个参数：

- `struct sock *sk`表示接收数据对应的套接字
- `struct msghdr *msg`表示接收的数据
- ` size_t len`表示接受数据的大小
- ` int noblock`表示非阻塞
- `int flags`表示标志位
- `int *addr_len`表示地址长度

统计udp协议接收流量，只需要监控内核中的`udp_recv`函数。当它触发时，对其接收数据的大小做累加，也就是kprobe监控`udp_recvmsg`，提取第三个参数` size_t len`做累加，一段时间内的累加值就是udp协议在此期间接收的流量大小。

**bpf提取思路**

<img src="C:\Users\22803\AppData\Roaming\Typora\typora-user-images\image-20231117181027821.png" alt="image-20231117181027821" style="zoom:50%;" />

程序运行结果如下，可以看到统计出了top5进程UDP协议的流量。

![image-20231117181050556](C:\Users\22803\AppData\Roaming\Typora\typora-user-images\image-20231117181050556.png)