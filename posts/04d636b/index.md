# WKCTF2024

WKCTF2024 Reverse wp
&lt;!--more--&gt;
# 前言
只出了两题，剩下那题是quickjs，不知道是版本问题还是打乱了opcode什么的，总之skill issue了，唉太菜了
# Reverse[2/3]
## so_easy
简单的安卓题，加密逻辑在so里面，建议看`lib\arm64-v8a\libeasy.so`，比其他几个清晰

跟`beginctf2024-出题人的密码是什么`的算法一样，做过的应该能看出来是魔改crc64，exp拿过来改个轮数和key就行了
```python
key = 0x71234EA7D92996F5

def decrypt(value, key):
    for _ in range(255):
        if value &amp; 1:
            value = (value ^ key) &gt;&gt; 1
            value |= 0x8000000000000000
        else:
            value = value &gt;&gt; 1
    return value

enc = [0x540A95F0C1BA81AE, 0xF8844E52E24A0314, 0x9FD988F98143EC9, 0x3FC00F01B405AD5E]

flag = b&#39;&#39;
for i in range(4):
    flag &#43;= decrypt(enc[i], key).to_bytes(8, &#39;little&#39;)

print(flag.decode())
```
## quite_easy
ida打开就看到个flag，火速提交，结果不对，意料之中哈哈

尝试在main函数开头打断点，结果跑飞了，说明main函数之面肯定哪里藏了脏东西

### TlsCallback
瞄一下导出函数就看到了`TlsCallback_0_0`，里面有调用俩函数，都有花指令，简单去除一下

`sub_401195`里面是一个反调试，直接nop即可；`sub_4014A6`里是一个IAT hook，hook了strcmp，挂钩到`sub_401573`

### main
回到main函数看看，strcmp的参数分别为输入内容和一个字符串，传入钩子函数中`sub_401573`
```c
if ( !strcmp(input, &#34;flag{ed1d665e6516a37ab09f0b7a40}&#34;) )
  {
    v4 = sub_EB1389(std::wcout, (wchar_t *)L&#34;right&#34;);
    std::wostream::operator&lt;&lt;(v4, sub_EB15FA);
  }
```

### 加密逻辑
有经验的话一眼就能看出来是一堆stl函数，可以自己编译一个exe，然后bindiff恢复符号，我这里就简单恢复了一下

首先置随机数种子，输入长度是32，所以随机数种子就是`32 &#43; 89`了，然后生成一个长度16的随机数表

再往下就是加密逻辑，需要先解出前16个字节的数据，才能解后面16个字节的数据

加密完成后再还原hook，strcmp与密文比较

这里给出两种解法，爆破 和 直接解
```c
int __cdecl sub_EBA5A0(char *input, BYTE *s)
{
  int input_size; // eax
  char v3; // al
  int v4; // esi
  int v5; // esi
  char v6; // di
  _BYTE *v7; // eax
  int v8; // esi
  int v9; // esi
  char v10; // di
  _BYTE *v11; // eax
  const char *data; // eax
  _BYTE *v14; // [esp&#43;10h] [ebp-158h]
  int v15; // [esp&#43;18h] [ebp-150h]
  int m; // [esp&#43;E4h] [ebp-84h]
  int k; // [esp&#43;F0h] [ebp-78h]
  int j; // [esp&#43;FCh] [ebp-6Ch]
  int i; // [esp&#43;108h] [ebp-60h]
  char v20[36]; // [esp&#43;114h] [ebp-54h] BYREF
  char s_input[32]; // [esp&#43;138h] [ebp-30h] BYREF
  int v22; // [esp&#43;164h] [ebp-4h]

  j___CheckForDebuggerJustMyCode(&amp;unk_ECA036);
  sub_EB111D(input);
  v22 = 1;
  sub_EB111D((char *)&amp;Str);
  input_size = std::string::size(s_input);
  srand(input_size &#43; 89);
  for ( i = 0; i &lt; 16; &#43;&#43;i )
  {
    v3 = rand();
    std::string::append(v3);
  }
  if ( std::string::size(s_input) != 48 )
    exit(99);
  for ( j = 0; j &lt; 16; &#43;&#43;j )
  {
    v4 = *(char *)std::string::operator[](j);
    v5 = *(char *)std::string::operator[](j &#43; 32) ^ v4;
    v6 = *(_BYTE *)std::string::operator[](j);
    v7 = (_BYTE *)std::string::operator[](j &#43; 32);
    std::string::append(~(*v7 &amp; v6) &amp; v5);
  }
  for ( k = 16; k &lt; 32; &#43;&#43;k )
  {
    v8 = *(char *)std::string::operator[](k);
    v9 = *(char *)std::string::operator[](k - 16) ^ v8;
    v10 = *(_BYTE *)std::string::operator[](k);
    v11 = (_BYTE *)std::string::operator[](k - 16);
    std::string::append(~(*v11 &amp; v10) &amp; v9);
  }
  for ( m = 0; m &lt; 32; &#43;&#43;m )
  {
    v14 = (_BYTE *)std::string::operator[](m);
    *v14 -= s[m];
  }
  restore_strcmp();
  data = (const char *)std::string::c_str(v20);
  v15 = strcmp(data, enc_data);
  LOBYTE(v22) = 0;
  sub_EB1357(v20);
  v22 = -1;
  sub_EB1357(s_input);
  return v15;
}
```

### 解题
#### 解法1 - 爆破
看到一堆位运算就头疼，赛时我也是选择了直接爆破，没啥好讲究的，逻辑抄过来直接爆呗
```python
enc = bytearray.fromhex(&#34;80D36FFF1503988CB45B96C059AC18DF2DCE3FFBC4EDD8D2A82DF8239F2225CE&#34;)
s = &#34;flag{ed1d665e6516a37ab09f0b7a40}&#34;
rand_data = bytearray.fromhex(&#34;b1 74 93 32 d6 13 cc 85 20 a8 f4 96 8a d2 7d 26&#34;)

part1 = &#34;&#34;
for i in range(16):
    for j in range(32, 128):
        v5 = rand_data[i] ^ j
        v6 = j
        v7 = rand_data[i]
        tmp = ~(v7 &amp; v6) &amp; v5
        if ((tmp - ord(s[i])) &amp; 0xff == enc[i]):
            print(tmp, v5, v6, v7, j)
            part1 &#43;= chr(j)


flag = part1
for i in range(16):
    for j in range(32, 128):
        v5 = ord(part1[i]) ^ j
        v6 = j
        v7 = ord(part1[i])
        tmp = ~(v7 &amp; v6) &amp; v5
        if ((tmp - ord(s[16 &#43; i])) &amp; 0xff == enc[16 &#43; i]):
            flag &#43;= chr(j)
            
print(flag)
```

#### 解法2 - 表达式化简求解
将那一坨位运算合并一下得到`result = ~(data[i] &amp; s[i]) &amp; (data[i] ^ s[i])`

所以我们需要在已知`data[i]`和`result`的情况下求解s[i]

先将表达式化简，需要一点点逻辑代数的知识
{{&lt; raw &gt;}}
$$
\begin{aligned}
result &amp;= \sim(data[i] \&amp; s[i]) \&amp; (data[i] \oplus s[i]) \\
&amp;= (\sim data[i] \mid \sim s[i]) \&amp; (data[i] \oplus s[i]) \\
&amp;= (\sim data[i] \&amp; (data[i] \oplus s[i])) \mid (\sim s[i] \&amp; (data[i] \oplus s[i])) \\
&amp;= (\sim data[i] \&amp; data[i]) \oplus (\sim data[i] \&amp; s[i]) \mid (\sim s[i] \&amp; data[i]) \oplus (\sim s[i] \&amp; s[i]) \\
&amp;= (\sim data[i] \&amp; s[i]) \mid (\sim s[i] \&amp; data[i]) \\
&amp;= data[i] \oplus s[i]
\end{aligned}
$$
{{&lt; /raw &gt;}}



可以得知加密算法其实相当于一个异或而已，直接解就行了
```c
#include &lt;stdio.h&gt;
#include &lt;stdlib.h&gt;

unsigned char enc_data[32] = {
    0x80, 0xD3, 0x6F, 0xFF, 0x15, 0x03, 0x98, 0x8C, 0xB4, 0x5B, 0x96, 0xC0, 0x59, 0xAC, 0x18, 0xDF, 
    0x2D, 0xCE, 0x3F, 0xFB, 0xC4, 0xED, 0xD8, 0xD2, 0xA8, 0x2D, 0xF8, 0x23, 0x9F, 0x22, 0x25, 0xCE
};

char s[] = &#34;flag{ed1d665e6516a37ab09f0b7a40}&#34;;

int main() {
    srand(32 &#43; 89);
    unsigned char key[16];
    unsigned char flag[32];

    for (size_t i = 0; i &lt; 16; &#43;&#43;i )
    {
        unsigned char rnd = rand();
        key[i] = rnd;
    }

    for (size_t i = 0; i &lt; 16; i&#43;&#43;)
    {
        flag[i] = (enc_data[i] &#43; s[i]) ^ key[i];
    }

    for (size_t i = 0; i &lt; 16; i&#43;&#43;)
    {
        flag[16 &#43; i] = (enc_data[16 &#43; i] &#43; s[16 &#43; i]) ^ flag[i];
    }

    for (size_t i = 0; i &lt; 32; i&#43;&#43;)
    {
        printf(&#34;%c&#34;, flag[i]);
    }
}
```


---

> Author: yuro  
> URL: /posts/04d636b/  

