# 某二游v4.8版本 IL2CPP Runtime Dump

某二游v4.8版本 IL2CPP Runtime Dump
&lt;!--more--&gt;
# 前言
**研究仅供学习交流，如有侵权请联系删除**

好久没有登过游戏了，趁着暑假有空来研究学习一下，看看现在版本的保护强度如何

# 分析
下完游戏，下意识的去找`UserAssembly.dll`，结果发现找了半天没找到，返回去看到`UnityPlayer.dll`也没了，懵了一下，然后才看到了264MB的exe...好嘛全给编译到一起了

Metadata下也多了个`startup-metadata.dat`，不知道干啥的

随手过一下保护，然后dump一下直接丢IDA了，跑了近10h才跑完，得到了一个3个多G的idb

本来是想照着`Zygisk-Il2CppDumper`去写dumper的，后面发现很多函数都内联了，加上结构被魔改，看着太乱了，弄的时候已经大半夜了，有些实在懒得找了，就选择了简单Hook一下 `il2cpp::vm::SetupMethodsLocked`来获取符号信息了

# 定位 il2cpp_vm_SetupMethodsLocked
自己编译一份同版本的带pdb的游戏，IDA把两个dll分析完然后对比分析

找交叉引用，可以看到在`il2cpp::vm::Class::GetMethods`中有调用`il2cpp::vm::SetupMethodsLocked`

利用一些关键字符串，可以直接从UnityPlayer.dll部分开始找一条链子来定位，正巧他把两个dll都编译到一起了，省的两个ida切来切去了

`ExtractStacktrace-&gt;il2cpp_class_get_methods-&gt;il2cpp::vm::Class::GetMethods-&gt;il2cpp::vm::SetupMethodsLocked`

可以看到很多函数都被内联了，结构也都魔改了
![](/images/Genshin-v4.8-IL2CPP-Runtime-Dump/image1.png)

# dump method
在`ReportRecursionDepthError`下可以找到`il2cpp_class_get_namespace`和`il2cpp_class_get_name`
![](/images/Genshin-v4.8-IL2CPP-Runtime-Dump/image2.png)

其余的同理，费点力气慢慢找就行了
```cpp
DO_API(0x9ac990, const char*, il2cpp_class_get_namespace, (void* klass));
DO_API(0x9ac980, const char*, il2cpp_class_get_name,      (void* klass));
DO_API(0x9ac940, void*,       il2cpp_class_get_methods,   (void* klass, void** iter));

DO_API(0x9ad1a0, const char*, il2cpp_method_get_name,     (void* method));
```
在dump的时候我犯了个蠢，在hook函数里直接开始调用`il2cpp_class_get_methods`了，

后面才想起他会调用`il2cpp::vm::SetupMethodsLocked`，导致无限递归然后炸掉了。可以先把klass存入一个容器里，等游戏全部加载完后再去dump

最后写了一个简易的dumper，代码主打一个能跑就行哈哈
```cpp
void dump_method(void* klass)
{
    outFile &lt;&lt; &#34;// Namespace: &#34; &lt;&lt; il2cpp_class_get_namespace(klass) &lt;&lt; &#34;\n&#34;;
    outFile &lt;&lt; &#34;\n\t// Methods\n&#34;;
    void* iter = 0;
    while (void* method = il2cpp_class_get_methods(klass, &amp;iter))
    {
        LOGI(&#34;0x%x&#34;, method);
        uintptr_t p = reinterpret_cast&lt;uintptr_t*&gt;(method)[0];
        if (p) {
            outFile &lt;&lt; &#34;\t// RVA: 0x&#34;;
            outFile &lt;&lt; std::hex &lt;&lt; (uint64_t)p - base;
            outFile &lt;&lt; &#34; VA: 0x&#34;;
            outFile &lt;&lt; std::hex &lt;&lt; (uint64_t)p;
        }
        else {
            outFile &lt;&lt; &#34;\t// RVA: 0x VA: 0x0&#34;;
        }
 
        outFile &lt;&lt; &#34;\n\t&#34;;
        outFile &lt;&lt; il2cpp_method_get_name(method) &lt;&lt; &#34;(...){ };\n&#34;;
    }
 
}
 
void il2cpp_vm_SetupMethodsLocked_Hook(void* klass, void* lock)
{
    klazzs.push_back(klass);
    return CALL_ORIGIN(il2cpp_vm_SetupMethodsLocked_Hook, klass, lock);
}
 
void il2cpp_dump()
{
    DisableLogReport();
    HookManager::install(il2cpp_vm_SetupMethodsLocked, il2cpp_vm_SetupMethodsLocked_Hook);
    // 按回车开始dump
    int a;
    std::cin &gt;&gt; a;
    for (const auto&amp; klass : klazzs) {
        dump_method(klass);
    }
}
```
部分method的信息就dump出来了
![](/images/Genshin-v4.8-IL2CPP-Runtime-Dump/image3.png)

点到为止，剩下的其实全是力气活了，事实上有比这更好的dump的方法，这里就不介绍了

---

> Author: yuro  
> URL: /posts/56da8d7/  

