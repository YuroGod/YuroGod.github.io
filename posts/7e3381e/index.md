# NewStar CTF 2024 Writeup


NewStar CTF 2024 Week5 Reverse Writeup
&lt;!--more--&gt;
## 前言
时隔一年, 也是第二次参加NewStar CTF了，虽然是新生赛不过也是学到了很多东西

今年的Rev除了Week4那一周太多事情实在太忙了唉没时间做，其他几周的运气好都解决了哈哈

前面几周难度不算太难，这里就只放Week5的wp了🥳

## Reverse
### MY_ARM
题目为一个arm32程序，ida启动分析一下，通过字符串交叉引用找到主要逻辑，凭经验恢复一下符号
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // r1
  int v4; // r2
  int len; // r3
  int v6; // r1
  int v7; // r2
  int f; // r3
  int v9; // r0
  char input[100]; // [sp&#43;0h] [bp-6Ch] BYREF
  int v12; // [sp&#43;64h] [bp-8h]

  v12 = dword_A5154;
  printf(&#34;please input your flag:&#34;, argv, envp, 0);
  scanf(&#34;%65s&#34;, input);
  len = strlen((int)input);
  if ( len != 64 )
  {
    printf(&#34;you are wrong!&#34;, v3, v4, len);
    ((void (__fastcall *)(_DWORD))loc_177AC)(0);
  }
  tea_encrypt((int)input, (int)&amp;key);
  f = check((int)input, (int)&amp;enc_data);
  if ( f )
    v9 = printf(&#34;you are right!&#34;, v6, v7, f);
  else
    v9 = printf(&#34;you are wrong!&#34;, v6, v7, 0);
  if ( v12 != dword_A5154 )
    sub_3511C(v9, v12 ^ dword_A5154, 0, 0);
  return 0;
}
```
加密算法也能很明显看出来是tea
```c
void __fastcall tea(int *v, _DWORD *k)
{
  int v0; // [sp&#43;8h] [bp-14h]
  int v1; // [sp&#43;Ch] [bp-10h]
  int sum; // [sp&#43;10h] [bp-Ch]
  int i; // [sp&#43;14h] [bp-8h]

  v0 = *v;
  v1 = v[1];
  sum = 0;
  for ( i = 0; i &lt; rounds; &#43;&#43;i )
  {
    sum &#43;= delta;
    v0 &#43;= ((v1 &gt;&gt; 5) &#43; k[1]) ^ (16 * v1 &#43; *k) ^ (v1 &#43; sum);
    v1 &#43;= ((v0 &gt;&gt; 5) &#43; k[3]) ^ (16 * v0 &#43; k[2]) ^ (v0 &#43; sum);
  }
  *v = v0;
  v[1] = v1;
}
```
不过这题既然是想让选手调试，那么就肯定不会这么简单的了，又去看了一眼`.init_array`段，果然发现有东西，在里面修改了密文和key
```c
void __cdecl sub_107D8()
{
  enc_data = 0xA0F8CB44;
  unk_A626C = 0xF82F83CF;
  unk_A6270 = 0xA55E48C2;
  unk_A6274 = 0x7A26E00A;
  unk_A6278 = 0xF1E354C9;
  unk_A627C = 0x687D9915;
  unk_A6280 = 0xF88816E8;
  unk_A6284 = 0x90878E86;
  unk_A6288 = 0x3AB06298;
  unk_A628C = 0xCBCFE78B;
  unk_A6290 = 0x578F0F50;
  unk_A6294 = 0xC39E3C65;
  unk_A6298 = 0xBBE92B84;
  unk_A629C = 0x128A2CA2;
  unk_A62A0 = 0xDB8F03F5;
  unk_A62A4 = 0x8482F8E2;
  key = 0x11223344;
  unk_A62BC = 0x55667788;
  unk_A62C0 = 0x9900AABB;
  unk_A62C4 = 0xCCDDEEFF;
}
```
那么分析差不多完毕了，加密算法看起来&#34;貌似&#34;也是没有魔改的，那么就火速写起了解密脚本，发现死都解不出来

没办法最终还是只能调试一下看看哪里出了问题，由于没有设备，所以需要用`qemu`模拟然后开启调试端口，ida启用`Remote GDB Debugger`进行调试

对比标准的加密算法，发现在第一轮加密的时候，返回的结果就不太对，经过苦思冥想之后发现，原来`v0`, `v1`的类型被改成了int，是有符号的...

好吧，是我疏忽大意了，exp:
```c
#include &lt;cstdint&gt;
#include &lt;iso646.h&gt;
#include &lt;stdio.h&gt;
#include &lt;stdint.h&gt;

void decrypt(uint32_t *v, uint32_t *k)
{
    int v0 = v[0], v1 = v[1], i;
    uint32_t delta = 0x9E3779B9;
    uint32_t sum = delta * 32;
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    for (i = 0; i &lt; 32; i&#43;&#43;)
    {
        v1 -= ((v0 &lt;&lt; 4) &#43; k2) ^ (v0 &#43; sum) ^ ((v0 &gt;&gt; 5) &#43; k3);
        v0 -= ((v1 &lt;&lt; 4) &#43; k0) ^ (v1 &#43; sum) ^ ((v1 &gt;&gt; 5) &#43; k1);
        sum -= delta;
    }
    v[0] = v0; v[1] = v1;
}


uint32_t enc[] = {0xA0F8CB44, 0xF82F83CF, 0xA55E48C2, 0x7A26E00A, 0xF1E354C9, 0x687D9915, 0xF88816E8, 0x90878E86, 0x3AB06298, 0xCBCFE78B, 0x578F0F50, 0xC39E3C65, 0xBBE92B84, 0x128A2CA2, 0xDB8F03F5, 0x8482F8E2};
uint32_t key[4] = {0x11223344, 0x55667788, 0x9900AABB, 0xCCDDEEFF};

int main()
{
    for (int i = 0; i &lt; 16; i&#43;=2)
        decrypt(enc &#43; i, key);

    puts((char*)enc);
// flag{ARM__@rch1t3ctuRe_-n3eds_-t0__be_-deBugged__us1ng-_QEMU__!}
}
```

### Lock
又是可恶的cpython，不过好像很简单，先strings一下看看python版本
```shell
$ strings check.pyd | grep python
python312.dll
```
然后看了眼代码，发现他给出了密码的长度和字符范围，并且`check`的返回值会告诉你第一个字符错了
```python
import check


print(&#39;&#39;&#39;
                                                                    
 /$$$$$$ /$$$$$$ /$$$$$$ /$$$$$$ /$$$$$$ /$$$$$$ /$$$$$$ 
|______/|______/|______/|______/|______/|______/|______/
                                                                  
 /$$$$         /$$$$$$             /$$$$$$         /$$$$                  
| $$_/        /$$$_  $$           /$$__  $$       |_  $$                  
| $$         | $$$$\\ $$ /$$   /$$| $$  \\ $$         | $$                  
| $$         | $$ $$ $$|  $$ /$$/| $$$$$$$$         | $$                  
| $$         | $$\\ $$$$ \\  $$$$/ | $$__  $$         | $$                  
| $$         | $$ \\ $$$  &gt;$$  $$ | $$  | $$         | $$                  
| $$$$       |  $$$$$$/ /$$/\\  $$| $$  | $$        /$$$$                  
|____/        \\______/ |__/  \\__/|__/  |__/       |____/                                                                                                                                                     
 /$$$$$$ /$$$$$$ /$$$$$$ /$$$$$$ /$$$$$$ /$$$$$$ /$$$$$$
|______/|______/|______/|______/|______/|______/|______/
                                                                                                                                                                    
&#39;&#39;&#39;)
print(&#39;&#39;&#39;The secret is locked.
You must enter the correct password to unlock it.
Hint: The password is 20 characters long and only contains letters and numbers from 0 to f.
      
&#39;&#39;&#39;)


while True:
    password = input(&#39;\npassword&gt;&#39;)
    ret = check.check(password)
    
    if ret == 20:
        print(&#39;\nCongratulation!\nFlag is flag{your_input.lower()}&#39;)
        break

    if ret == 114:
        print(&#39;Error input: only 0-f allowed. Lower case needed.&#39;)
        continue

    if ret == 514:
        print(&#39;Error length.&#39;)
        continue

    print(f&#39;[{ret}] Good [{20-ret}] Bad , try again.&#39;)

```
那还等什么，写脚本直接开爆呗
```python
import check

s = &#34;0123456789abcdef&#34;
flag = list(&#34;00000000000000000000&#34;)

f = 1
for i in range(20):
    for j in s:
        flag[i] = j
        t = &#34;&#34;.join(flag)
        r = check.check(t)
        if r != f:
            f = r
            print(&#34;&#34;.join(flag))
            break
# d6cf51e2736849b4ba21
```

### jun...junkcode?
简单的花指令随手nop一下，完整的main函数就展现出来了，不过题目名字告诉我们他肯定没有表面上这么简单
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char i; // bl
  char j; // bl

  main();
  printf_0(&#34;Input your flag:\n&#34;);
  sub_4017A9(&#34;%43s&#34;, (__int64)input);
  for ( i = 0; i &lt;= 9; &#43;&#43;i )
    input[i] &#43;= table[i];
  while ( i &lt;= 19 )
  {
    input[i] ^= table[i];
    &#43;&#43;i;
  }
  while ( i &lt;= 29 )
  {
    input[i] &#43;= table[i];
    &#43;&#43;i;
  }
  while ( i &lt;= 41 )
  {
    input[i] ^= table[i];
    &#43;&#43;i;
  }
  for ( j = 0; j &lt;= 42; &#43;&#43;j )
  {
    if ( input[j] != enc_data[j] )
    {
      puts(&#34;Incorrect!&#34;);
      return 0;
    }
  }
  puts(&#34;Correct!&#34;);
  return 0;
}
```
你以为`sub_4017A9`是scanf？没错我但是就是这么想的，后面才发现里面偷偷摸摸藏了脏东西

看着import表里有导入好多奇奇怪怪的东西，于是跟了一下交叉引用，于是就发现了这俩玩意

通过 CreateFileMapping 和 MapViewOfFile 实现文件或内存的映射，允许进程间的内存共享

`sub_4017A9`保存了当前的返回地址，然后起了一个子进程，`sub_401550`里有个反调试，没有调试的状态下会修改返回地址为`0x401A89`
```c
BOOL sub_4017A9(const char *a1, __int64 a2, ...)
{
  void *retaddr; // [rsp&#43;58h] [rbp&#43;8h] BYREF

  scanf(a1, a2);
  *((_QWORD *)mappedView &#43; 1) = &amp;retaddr;       // 保存返回地址
  CreateProcessA(ApplicationName, 0i64, 0i64, 0i64, 0, 0, 0i64, 0i64, &amp;StartupInfo, (LPPROCESS_INFORMATION)&amp;hObject);
  WaitForSingleObject(hObject, 0xFFFFFFFF);
  UnmapViewOfFile(mappedView);
  CloseHandle(hFileMapping[0]);
  CloseHandle(hObject);
  return CloseHandle(*(&amp;hObject &#43; 1));
}

DWORD sub_401550()
{
  _DWORD *v0; // rbx
  DWORD result; // eax
  __int64 Buffer; // [rsp&#43;30h] [rbp-50h] BYREF
  HANDLE hProcess; // [rsp&#43;38h] [rbp-48h]

  hFileMapping[0] = OpenFileMappingA(0xF001Fu, 0, &#34;jun...junkcode?&#34;);
  if ( hFileMapping[0] )
  {
    mappedView = MapViewOfFile(hFileMapping[0], 0xF001Fu, 0, 0, 0x18ui64);
    if ( DebugActiveProcess(*(_DWORD *)mappedView) )
    {
      hProcess = OpenProcess(0x1F0FFFu, 0, *(_DWORD *)mappedView);
      Buffer = *((_QWORD *)mappedView &#43; 2);
      WriteProcessMemory(hProcess, *((LPVOID *)mappedView &#43; 1), &amp;Buffer, 8ui64, 0i64);// 修改sub_4017A9的返回地址
      DebugActiveProcessStop(*(_DWORD *)mappedView);
    }
    UnmapViewOfFile(mappedView);
    CloseHandle(hFileMapping[0]);
    CloseHandle(hProcess);
    exit(0);
  }
  GetModuleFileNameA(0i64, ApplicationName, 0x104u);
  hFileMapping[0] = CreateFileMappingA((HANDLE)0xFFFFFFFFFFFFFFFFi64, 0i64, 4u, 0, 0x18u, &#34;jun...junkcode?&#34;);
  mappedView = MapViewOfFile(hFileMapping[0], 0xF001Fu, 0, 0, 0x18ui64);
  *((_QWORD *)mappedView &#43; 2) = 0x401A89i64;
  v0 = mappedView;
  result = GetCurrentProcessId();
  *v0 = result;
  return result;
}
```
这个就是关键的加密算法了，执行完加密就会跳转到`0x4019F9`，也就是main函数进行check的地方
```c
void __fastcall sub_401A90()
{
  int i; // ebx

  do
  {
    input[41 - (char)i] ^= input[2 * (char)i % 42];
    &#43;&#43;i;
  }
  while ( (char)i &lt;= 41 );
  JUMPOUT(0x4019F9i64);
}
```
那么逻辑分析就明白了, exp:
```python
enc = bytearray.fromhex(&#34;346C6033153B74385E6A5305311C433553584A12393B355E3A21081B44007C266E5D540C0107001F521B&#34;)

for i in range(41, -1, -1):
    enc[41 - i] ^= enc[2 * i % 42]
    
print(enc)
# flag{G00d_jOb_!_7h1s_i5_nOt_0nIy_junkc0d3}
```

### PangBai 泰拉记（2）
vm题，简单调试了一下发现是单字节加密，那么frida启动开始爆破!
可以学习一下这篇文章[基于 Frida 对单字节加密验证程序侧信道爆破](https://bbs.kanxue.com/thread-281796.htm)

不过在启动前先把那个可恶的`getchar() == 10`给patch掉，卡了我半天
![alt text](/images/NewStarCTF2024/image.png)

由于我也是现学的，所以代码写的有点shit请见谅hh

bf.py:
```python
import subprocess
import frida
from string import printable

idx = 0
bad = 0
flag = &#34;&#34;

def on_message(message, data):
    global idx, bad, flag
    if message[&#34;type&#34;] == &#34;send&#34;:
        
        bad = int(message[&#34;payload&#34;])


jscode = open(&#34;hook.js&#34;, &#34;rb&#34;).read().decode()

for index in range(len(flag), 24):
    for i in printable:
        process = subprocess.Popen(
            &#34;vm.exe&#34;,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        tmp_flag = (flag &#43; i).ljust(23, &#34;A&#34;) &#43; &#34;}&#34;

        session = frida.attach(&#34;vm.exe&#34;)
        script = session.create_script(jscode)
        script.on(&#34;message&#34;, on_message)
        script.load()

        process.stdin.write(tmp_flag)
        process.stdin.flush()

        output, error = process.communicate()
        
        if bad &gt; idx:
            flag &#43;= i
            idx = bad
            print(flag)
            break
        
        process.terminate()
```
hook.js:
```javascript
var arr = [40, 121, 23, 4, 12, 115, 38, 54, 80, 57, 126, 36, 81, 23, 68, 37, 6, 112, 77, 64, 121, 53, 115, 33];
function main() {
    var base = Module.findBaseAddress(&#34;vm.exe&#34;)

    Interceptor.attach(base.add(0x17EB), {

        onEnter: function (args) {
            var rbp = this.context.rbp;
            var s = rbp.sub(0x20).add(128);
            var hexdump = Memory.readByteArray(s, 24);
            var b = new Uint8Array(hexdump);
            var exit_ = new NativeFunction(base.add(0xE540), &#39;void&#39;, [&#39;int&#39;]);

            for (var i = 0; i &lt; b.length; i&#43;&#43;) {
                if (b[i] != arr[i]) {
                    send(i);
                    var a = 0;
                    for (var i = 0; i &lt; 9999; i&#43;&#43;) {
                        a &#43;= 1;
                    }
                    exit_(0);
                }
            }
        }

    });
}
setImmediate(main);
```
代码好像写的不太好，最后爆出来`flag{W0w_y0u_$01v3_VM!`，缺一位猜一下是`!`，再补个大括号

flag: `flag{W0w_y0u_$01v3_VM!!}`

### PangBai 泰拉记（3）
ios逆向，没得设备，静态分析硬猜吧，老样子，先找关键字符串交叉引用跟过去
![alt text](/images/NewStarCTF2024/image-1.png)


往下翻，发现一个疑似按钮的事件回调函数
![alt text](/images/NewStarCTF2024/image-2.png)

一眼就看到个rc4

![alt text](/images/NewStarCTF2024/image-3.png)

下面还有个`sub_10001C8D8`是base64

再往下找到了AES-ECB，然后又进行了base64

![alt text](/images/NewStarCTF2024/image-4.png)

那么key和密文在哪里呢!?，在`__cstring`段看见了俩玩意，盲猜就是了

![alt text](/images/NewStarCTF2024/image-5.png)

逻辑大致就猜完了，厨子解一下就好了
![alt text](/images/NewStarCTF2024/image-6.png)

`flag{Sw1ft_$0_funny!}`

### Ohn_flutter!!!
flutter逆向，直接用blutter工具，生成ida脚本用于恢复`libapp.so`的符号

这题其实不难，题目里给的文字提示说的就很好

![alt text](/images/NewStarCTF2024/image-8.png)

`6&#43;52/n`一眼xxtea的特征,然后修改`blutter_frida.js`的函数地址来hook函数

看了一下blutter生成的dart文件，在`drink::_encryptUint32List`中发现了xxtea的特征, `delta=0x9e3779b9`
![alt text](/images/NewStarCTF2024/image-10.png)

那就hook一下`ohn_flutter$drink_drink___encryptUint32List`
![alt text](/images/NewStarCTF2024/image-7.png)

然后就拿到了xxtea的key，转字符串就是`ohn_flutterkkkkk`
![alt text](/images/NewStarCTF2024/image-9.png)

接着随便翻翻又发现了有aes加密，key和iv传入了`Encrypted::ctor_fromUtf8`
![alt text](/images/NewStarCTF2024/image-11.png)

愣着干啥捏，hook他呗，key: `12345678901234561234567890123456`, iv: `1234567890123456`
![alt text](/images/NewStarCTF2024/image-12.png)

但是还有个问题，密文哪去了？

 `ohn_flutter_EditView_MyEditTextState::check_2d50c0`看着是check密文的地方，但是尝试hook了没得到密文，只能用ida调试一下拿了

下断点，随便敲点东西，断下来
![alt text](/images/NewStarCTF2024/image-13.png)
双击v10,跳过去，在下面就能看到密文了
![alt text](/images/NewStarCTF2024/image-14.png)

然后用cyberchef处理一下数据，中间注意还有俩base64
![alt text](/images/NewStarCTF2024/image-15.png)

exp:
```c
#include &lt;stdio.h&gt;

// xxtea
void xxtea(unsigned int* v, int n, unsigned int* key) {
    // n: array v size
    unsigned int delta = 0x9e3779b9;
    unsigned int y, z, sum;
    unsigned int rounds, e;
    if (n &gt; 1) { // encrypt
        rounds = 6 &#43; 52/n;
        sum = 0;
        z = v[n - 1];
        do {
            sum &#43;= delta;
            e = (sum &gt;&gt; 2) &amp; 3;
            for (int p = 0; p &lt; n - 1; p&#43;&#43;) {
                y = v[p &#43; 1];
                v[p] &#43;= (((z &gt;&gt; 5 ^ y &lt;&lt; 2) &#43; (y &gt;&gt; 3 ^ z &lt;&lt; 4)) ^ ((sum ^ y) &#43; (key[(p &amp; 3) ^ e] ^ z)));
                z = v[p];
            }
            y = v[0];
            v[n - 1] &#43;= (((z &gt;&gt; 5 ^ y &lt;&lt; 2) &#43; (y &gt;&gt; 3 ^ z &lt;&lt; 4)) ^ ((sum ^ y) &#43; (key[((n - 1) &amp; 3) ^ e] ^ z)));
            z = v[n - 1];
        } while (--rounds);
    } else if (n &lt; -1) { //decrypt
        n = -n;
        rounds = 6 &#43; 52/n;
        sum = rounds * delta;
        y = v[0];
        do {
            e = (sum &gt;&gt; 2) &amp; 3;
            for (int p = n - 1; p &gt; 0; p--) {
                z = v[p - 1];
                v[p] -= (((z &gt;&gt; 5 ^ y &lt;&lt; 2) &#43; (y &gt;&gt; 3 ^ z &lt;&lt; 4)) ^ ((sum ^ y) &#43; (key[(p &amp; 3) ^ e] ^ z)));
                y = v[p];
            }
            z = v[n - 1];
            v[0] -= (((z &gt;&gt; 5 ^ y &lt;&lt; 2) &#43; (y &gt;&gt; 3 ^ z &lt;&lt; 4)) ^ ((sum ^ y) &#43; (key[e] ^ z)));
            y = v[0];
            sum -= delta;
        } while (--rounds);
    }
}

int main() {
    char data[] = &#34;\xbf\xd2\x48\x02\x24\x2c\xd9\x72\x41\x97\x8f\x4c\xc8\x3a\x38\x74\x43\x1a\x73\xa4\x6f\x48\xbc\x72\xf9\x82\x9c\x8f\xa3\x9d\xbe\x97\x10\x07\x7a\x6d&#34;;
    int len = 36;
    unsigned int* key = (unsigned int*) &#34;ohn_flutterkkkkk&#34;;
    xxtea((unsigned int*) data, -len / 4, key);
    puts(data);
    return 0;
}
// flag{U_@r4_F1u774r_r4_m@ster}
```

---

> Author: yuro  
> URL: /posts/7e3381e/  

