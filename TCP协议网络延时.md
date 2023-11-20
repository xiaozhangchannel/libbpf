# TCP协议网络延时

**指标解读**

  tcp网络延时：发送端发送一个数据包给接收端，到发送端接收到接收端发送的对应的数据包的应答数据包ACK，所花费的时间。

**项目需求**

  统计系统一段时间内，tcp网络延时所处的时间间隔内的个数。如系统这段时间落在0-100ms，100-200ms等间隔的个数。

<img src="C:\Users\22803\AppData\Roaming\Typora\typora-user-images\image-20231117180723860.png" alt="image-20231117180723860" style="zoom:50%;" />

### 提取思路

tcp协议是面向连接保证可靠性传输的协议，每当发送一个数据包时都会开启重传定时器，当重传定时器的值到期时，还没有接收ack的应答数据包，就会对数据包进行重传，并扩大定时器的重传时间间隔rto。若是在定时器到期时间内，接收到ack的应答数据包。就会根据ack数据包的应答序列号，将重传队列中被应答的数据包进行释放，并进行rtt采样，更加采样到的rtt值进行rto计算，重新定时重传定时器的时间rto，执行流程如下：

<img src="C:\Users\22803\AppData\Roaming\Typora\typora-user-images\image-20231117180743501.png" alt="image-20231117180743501" style="zoom:50%;" />

根据上面的执行流程，选取的监控点函数原型：

```c
void tcp_rcv_established(struct sock *sk, struct sk_buff *skb)
```

其中`struct sock *sk`字段中，保存着srtt字段。srtt字段就是tcp平滑后的网络延时。

<img src="C:\Users\22803\AppData\Roaming\Typora\typora-user-images\image-20231117180801754.png" alt="image-20231117180801754" style="zoom:50%;" />

**bpf执行流程**

<img src="C:\Users\22803\AppData\Roaming\Typora\typora-user-images\image-20231117180817045.png" alt="image-20231117180817045" style="zoom: 50%;" />

下图可以看到，程序可以统计到区间网络延时的次数。

![image-20231117180913806](TCP协议网络延时.assets/image-20231117180913806.png)