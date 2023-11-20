# UDP协议网络延时

### 指标解读

统计系统一段时间内，网络延时所处的时间间隔内的个数，如系统这段时间落在等间隔的个数。

### 提取思路

当发送端不断的发送数据的时候，记录最近一次发送的时间戳t1，当发送端接收到最近一次的数据包时，记录当前的系统时间戳t2，udp的网络延时t=t2 - t1。判断时间t所属的时间范围内，进行个数累加。

<img src="C:\Users\22803\AppData\Roaming\Typora\typora-user-images\image-20231117181142330.png" alt="image-20231117181142330" style="zoom:50%;" />

程序运行结果 

![image-20231117181200822](C:\Users\22803\AppData\Roaming\Typora\typora-user-images\image-20231117181200822.png)