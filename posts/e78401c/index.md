# 某沙盒游戏残血ACE反作弊ring3下的绕过分析

某沙盒游戏残血ACE反作弊ring3下的绕过分析
&lt;!--more--&gt;
## 前言
**研究仅供学习交流目的，请勿用于任何违法用途**

前几个月就听说了mw在新版本上实装了ACE反作弊，上个月有空的时候去研究了一下，发现绕过方式出奇的简单，最近有空就分享一下分析过程吧

## 分析过程
### 尝试
正常启动游戏，又是那个熟悉的蓝色UI

![alt text](/images/某沙盒游戏残血ACE反作弊ring3下的绕过分析/image.png)

刚开始先是尝试了很多ring3下常用的绕过方法，如删除驱动文件，关闭驱动句柄等等

但都会触发反作弊的奇奇怪怪的检测，然后触发异常，最后没办法也就只能去具体分析了

### 分析
对比更新前的目录，发现在更新之后多了一个`minigameappbase.dll`，IDA启动看两眼

看一眼调试信息就知道这个就是加载ACE的模块了，不过很明显有加壳什么的，也没有进一步探究了 (太菜了😥)
![alt text](/images/某沙盒游戏残血ACE反作弊ring3下的绕过分析/image-1.png)

转而去分析加载这个模块的`minigameapp.exe`，很明显他也加壳了，难道接下来只能硬刚ACE了吗
![alt text](/images/某沙盒游戏残血ACE反作弊ring3下的绕过分析/image-2.png)

nonono! 我们还可以去分析一下它在实装ACE前是什么样的

这不看不知道，一看吓一跳啊，原来这玩意就仅仅只是调用了`libiworld.dll`中的`WinMainEntry`导出函数而已...

顺便去瞟了一眼`libiworld.dll`，也没有发现什么可疑的东西
![alt text](/images/某沙盒游戏残血ACE反作弊ring3下的绕过分析/image-3.png)

结果看起来已经很明显了，那就直接把原来的`minigameapp.exe`给替换过来，这样不就既可以正常加载游戏，又不会加载ACE模块了

nice，理论存在，开始实践!

可恶，居然触发了游戏的文件校验自动更新了程序


![alt text](/images/某沙盒游戏残血ACE反作弊ring3下的绕过分析/image-4.png)

接着去分析一下怎么绕过文件校验部分，因为`minigameapp.exe`是由`MicroMiniNew.exe`启动的，那么就分析一下看看他在启动前后者还做了些什么

跟了一下`ReadFile`的交叉引用，没有发现跟文件校验有关的代码，猜测是不是有调用其他的dll

于是看了一下`LoadLibraryA`的交叉引用，发现了一个有趣的东西，`start.mnw`是个什么东西?，很可疑，拉IDA里分析一下
![alt text](/images/某沙盒游戏残血ACE反作弊ring3下的绕过分析/image-5.png)

搜一下关键字符串，果然发现有东西，猜测一下文件的md5就是存在`md5filesdata.dat`里用作校验了
![alt text](/images/某沙盒游戏残血ACE反作弊ring3下的绕过分析/image-6.png)

看了一下根目录，有两个相关的文件，干脆两个一起改了吧

![alt text](/images/某沙盒游戏残血ACE反作弊ring3下的绕过分析/image-7.png)

010Editor简单替换一下

![alt text](/images/某沙盒游戏残血ACE反作弊ring3下的绕过分析/image-8.png)

现在重新启动游戏，右下角已经不会出现ACE加载的提示了，CE测试了一下内存读写，下断调试都是没有问题的
![alt text](/images/某沙盒游戏残血ACE反作弊ring3下的绕过分析/image-9.png)

## 总结
一次有趣的研究，对于游戏这个ACE加载位置的设计有点难以置信，过于好绕过了，而且后面也没有心跳检测什么的，不加载ACE也不会导致游戏掉线，感觉就像...把vmp当upx加一样，也希望相关游戏厂商能尽快修复该问题吧

---

> Author: yuro  
> URL: /posts/e78401c/  

