# 2024春秋杯网络安全联赛夏季赛

2024春秋杯网络安全联赛夏季赛 Reverse wp
&lt;!--more--&gt;
# 前言
时隔半年，去年冬季赛只会签到的笨蛋也是在今年夏季赛ak了，这里记录一下wp
# Reverse[3/3]
## snack
{{&lt; admonition tip &#34;题目描述&#34;&gt;}}
题目内容：

你也想玩蛇吗？

[附件下载](https://pan.baidu.com/s/1RLwANqez2FIqgt1vndgvxw) 提取码（GAME）[备用下载](https://share.weiyun.com/2bXJxSrd)
{{&lt; /admonition &gt;}}
简单的签到题，pyinstaller打包的程序，先`pyinstxtractor.py`解包，注意要用python3.8版本

然后`pycdc`反编译`snake.pyc`，把解密代码扣下来跑一遍就好了
```python
xor_key = &#39;V3rY_v3Ry_Ez&#39;

def initialize(key):
    key_length = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j &#43; S[i] &#43; key[i % key_length]) % 256
        S[i], S[j] = (S[j], S[i])
    return S

def generate_key_stream(S, length):
    i = 0
    j = 0
    key_stream = []
    for _ in range(length):
        i = (i &#43; 1) % 256
        j = (j &#43; S[i]) % 256
        S[i], S[j] = (S[j], S[i])
        key_stream.append(S[(S[i] &#43; S[j]) % 256])
    return key_stream

def decrypt(data, key):
    S = initialize(key)
    key_stream = generate_key_stream(S, len(data))
    decrypted_data = bytes([i ^ data[i] ^ key_stream[i] for i in range(len(data))])
    return decrypted_data

key_bytes = bytes([ord(char) for char in xor_key])
data = [101, 97, 39, 125, 218, 172, 205, 3, 235, 195, 72, 125, 89, 130, 103, 213, 120, 227, 193, 67, 174, 71, 162, 248, 244, 12, 238, 92, 160, 203, 185, 155]
decrypted_data = decrypt(bytes(data), key_bytes)
print(decrypted_data.decode())
# flag{KMLTz3lT_MePUDa7A_P5LpzCBT}
```
## HardSignin
{{&lt; admonition tip &#34;题目描述&#34;&gt;}}
题目内容：

这是一道困难的签到题

[附件下载](https://pan.baidu.com/s/1S82W-BXwmYfwx5rvRfRWQQ) 提取码（GAME）[备用下载](https://share.weiyun.com/KG59ep2F)
{{&lt; /admonition &gt;}}

也不是很困难，就只是修改了upx特征，套了一堆反调试花指令加密算法，耐心分析就好了

### 0x00 upx脱壳
用010 Editor，将0x1E0，0x208，0x3E0三个位置的VMP修改回UPX，然后`upx -d`即可脱壳

### 0x01 去除花指令
ida打开分析，发现前面有一大片红，三个Tls回调函数中有花指令，需要去除一下

将`0x00401042`，`0x00401134`，`0x00401042` 三个地址的单个字节改成90(nop)即可

### 0x02 分析Tls回调函数
因为Tls回调函数早于main函数执行，所以我们需要先去分析他
#### TlsCallback_0
`TlsCallback_0`中存在一个`IsDebuggerPresent`反调试，nop掉即可

下面就是一个SMC，将main函数前170个字节每位异或0x66来解密

然后初始化随机数种子`0x114514`
```c
void __stdcall TlsCallback_0(int a1, int a2, int a3)
{
  SIZE_T i; // [esp&#43;50h] [ebp-10h]
  DWORD flOldProtect; // [esp&#43;54h] [ebp-Ch] BYREF
  SIZE_T dwSize; // [esp&#43;58h] [ebp-8h]
  LPVOID lpAddress; // [esp&#43;5Ch] [ebp-4h]

  if ( a2 == 1 )
  {
    if ( IsDebuggerPresent() )
      exit(0);
    lpAddress = main;
    dwSize = 170;
    flOldProtect = 0;
    VirtualProtect(main, 0xAAu, 0x40u, &amp;flOldProtect);
    for ( i = 0; i &lt; dwSize; &#43;&#43;i )
      *((_BYTE *)lpAddress &#43; i) ^= 0x66u;
    srand(0x114514u);
  }
}
```
#### TlsCallback_1
在`TlsCallback_1`中也是存在一个`CheckRemoteDebuggerPresent`反调试，一样直接nop掉即可

下面是在打乱base64码表

注意最后又初始化随机数种子为`0x1919810`
```c
void __stdcall TlsCallback_1(int a1, int a2, int a3)
{
  HANDLE CurrentProcess; // eax
  int v4; // eax
  int i; // [esp&#43;50h] [ebp-10h]
  int v6; // [esp&#43;58h] [ebp-8h]
  BOOL pbDebuggerPresent; // [esp&#43;5Ch] [ebp-4h] BYREF

  pbDebuggerPresent = 0;
  if ( a2 == 1 )
  {
    CurrentProcess = GetCurrentProcess();
    CheckRemoteDebuggerPresent(CurrentProcess, &amp;pbDebuggerPresent);
    if ( pbDebuggerPresent )
      exit(0);
    for ( i = 0; i &lt; 100; &#43;&#43;i )
    {
      v6 = rand() % 64;
      v4 = rand() % 64;
      swap(&amp;base64_table[v6], &amp;base64_table[v4]);
    }
    srand(0x1919810u);
  }
}
```
#### TlsCallback_2
这里前面还是一个反调试，同理

下面则是在初始化rc4和xtea的key，在后面会分析到的
```c
int __stdcall TlsCallback_2(int a1, int a2, int a3)
{
  int result; // eax
  HANDLE CurrentProcess; // eax
  int i; // [esp&#43;50h] [ebp-18h]
  NTSTATUS (__stdcall *NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG); // [esp&#43;58h] [ebp-10h]
  HMODULE hModule; // [esp&#43;5Ch] [ebp-Ch]
  int v8; // [esp&#43;64h] [ebp-4h] BYREF

  v8 = 0;
  result = a2;
  if ( a2 == 1 )
  {
    hModule = LoadLibraryA(&#34;Ntdll.dll&#34;);
    NtQueryInformationProcess = (NTSTATUS (__stdcall *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(hModule, &#34;NtQueryInformationProcess&#34;);
    CurrentProcess = GetCurrentProcess();
    NtQueryInformationProcess(CurrentProcess, ProcessDebugPort, &amp;v8, 4, 0);
    if ( v8 )
      exit(0);
    for ( i = 0; ; &#43;&#43;i )
    {
      result = i;
      if ( i &gt;= size )
        break;
      rc4_key[i] = rand() % 255;
      xtea_key[i] = rand() % 255;
    }
  }
  return result;
}
```


#### TlsCallback_3
不知道有什么用，好像并不影响做题，略过吧哈哈
```c
int __stdcall TlsCallback_3(int a1, int a2, int a3)
{
  int result; // eax
  HANDLE CurrentThread; // eax
  FARPROC ZwSetInformationThread; // [esp&#43;50h] [ebp-8h]
  HMODULE hModule; // [esp&#43;54h] [ebp-4h]

  result = a2;
  if ( a2 == 1 )
  {
    hModule = GetModuleHandleA(&#34;Ntdll&#34;);
    ZwSetInformationThread = GetProcAddress(hModule, &#34;ZwSetInformationThread&#34;);
    CurrentThread = GetCurrentThread();
    return ((int (__stdcall *)(HANDLE, int, _DWORD, _DWORD))ZwSetInformationThread)(CurrentThread, 17, 0, 0);
  }
  return result;
}
```
### 0x03 分析main函数和check
动态执行完SMC的解密代码，即可看到main函数的逻辑
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signed int size; // [esp&#43;4Ch] [ebp-6Ch]
  char input[100]; // [esp&#43;50h] [ebp-68h] BYREF

  memset(input, 0, sizeof(input));
  printf((char *)0xF93180);
  scanf((char *)0xF93198, input);
  size = strlen(input);
  if (check(input, size) )
    printf((char *)0xF9319C);
  else
    printf((char *)0xF931B0);
  MEMORY[0xF930B8](0xF931C4);
  return 0;
}
```
分析一下check函数，先将输入内容进行base64编码，注意这里的base64在Tls回调函数中已被打乱

然后rc4加密，最后xtea加密，这里的key都在`TlsCallback_2`中初始化
```c
BOOL __cdecl check(BYTE *input, int a2)
{
  BYTE *data; // [esp&#43;50h] [ebp-4h]

  data = base64(input, a2);
  rc4_crypt(data, 4 * (a2 / 3), rc4_key, size);
  xtea(rounds, (DWORD *)data, &amp;key);
  return memcmp(data, enc_data, Size) == 0;
}

void __cdecl rc4_init(BYTE *a1, int a2)
{
  int k; // [esp&#43;4Ch] [ebp-114h]
  int v3; // [esp&#43;50h] [ebp-110h]
  int j; // [esp&#43;54h] [ebp-10Ch]
  BYTE v5[256]; // [esp&#43;58h] [ebp-108h] BYREF
  int i; // [esp&#43;158h] [ebp-8h]

  for ( i = 0; i &lt; 256; &#43;&#43;i )
    s_box[i] = i;
  memset(v5, 0, sizeof(v5));
  for ( j = 0; j &lt; 256; &#43;&#43;j )
    v5[j] = a1[j % a2];
  v3 = 0;
  for ( k = 0; k &lt; 256; &#43;&#43;k )
  {
    v3 = (v5[k] &#43; v3 &#43; s_box[k]) % 256;
    swap(&amp;s_box[k], &amp;s_box[v3]);
  }
}

void __cdecl rc4_crypt(BYTE *data, int ssize, BYTE *key, int size)
{
  int i; // [esp&#43;4Ch] [ebp-14h]
  int v5; // [esp&#43;54h] [ebp-Ch]
  int v6; // [esp&#43;58h] [ebp-8h]

  v6 = 0;
  v5 = 0;
  rc4_init(key, size);
  for ( i = 0; i &lt; ssize; &#43;&#43;i )
  {
    v6 = (v6 &#43; 1) % 256;
    v5 = (v5 &#43; s_box[v6]) % 256;
    swap(&amp;s_box[v6], &amp;s_box[v5]);
    data[i] ^= s_box[(s_box[v5] &#43; s_box[v6]) % 256];
  }
}

void __cdecl xtea(unsigned int rounds, DWORD *data, DWORD *key)
{
  unsigned int j; // [esp&#43;4Ch] [ebp-18h]
  unsigned int sum; // [esp&#43;54h] [ebp-10h]
  DWORD v1; // [esp&#43;58h] [ebp-Ch]
  DWORD v0; // [esp&#43;5Ch] [ebp-8h]
  int i; // [esp&#43;60h] [ebp-4h]

  for ( i = 0; i &lt; 16; i &#43;= 2 )
  {
    v0 = data[i];
    v1 = data[i &#43; 1];
    sum = 0;
    for ( j = 0; j &lt; rounds; &#43;&#43;j )
    {
      v0 &#43;= (key[sum &amp; 3] &#43; sum) ^ (v1 &#43; ((v1 &gt;&gt; 5) ^ (16 * v1)));
      sum -= 0x61C88647;
      v1 &#43;= (key[(sum &gt;&gt; 11) &amp; 3] &#43; sum) ^ (v0 &#43; ((v0 &gt;&gt; 5) ^ (16 * v0)));
    }
    data[i] = v0;
    data[i &#43; 1] = v1;
  }
}
```
### 0x04 exp
把代码扣下来，逆着逻辑解密即可
```c
#include &lt;stdio.h&gt;
#include &lt;stdint.h&gt;
#include &lt;string.h&gt;

#define BYTE unsigned char

unsigned int enc_data[16] = {
    0xB4FD1B59, 0xD9BEB86B, 0xD677D3B3, 0x185F65F0, 0x533A9DA0, 0x267B4A6D, 0x4E9C3A74, 0xD8194320,
    0xB595ED72, 0x5622059C, 0x91117ACB, 0x0CBC7A9F, 0xCE6D694A, 0x29ABB43D, 0x3262FA61, 0xB64CECB4
};

BYTE s_box[256];

void __cdecl swap(BYTE *a1, BYTE *a2)
{
  BYTE v2; // [esp&#43;4Fh] [ebp-1h]

  v2 = *a1;
  *a1 = *a2;
  *a2 = v2;
}

void __cdecl rc4_init(BYTE *a1, int a2)
{
  int k;        // [esp&#43;4Ch] [ebp-114h]
  int v3;       // [esp&#43;50h] [ebp-110h]
  int j;        // [esp&#43;54h] [ebp-10Ch]
  BYTE v5[256]; // [esp&#43;58h] [ebp-108h] BYREF
  int i;        // [esp&#43;158h] [ebp-8h]

  for (i = 0; i &lt; 256; &#43;&#43;i)
    s_box[i] = i;
  memset(v5, 0, sizeof(v5));
  for (j = 0; j &lt; 256; &#43;&#43;j)
    v5[j] = a1[j % a2];
  v3 = 0;
  for (k = 0; k &lt; 256; &#43;&#43;k)
  {
    v3 = (v5[k] &#43; v3 &#43; s_box[k]) % 256;
    swap(&amp;s_box[k], &amp;s_box[v3]);
  }
}

void __cdecl rc4_crypt(BYTE *data, int ssize, BYTE *key, int size)
{
  int i;  // [esp&#43;4Ch] [ebp-14h]
  int v5; // [esp&#43;54h] [ebp-Ch]
  int v6; // [esp&#43;58h] [ebp-8h]

  v6 = 0;
  v5 = 0;
  rc4_init(key, size);
  for (i = 0; i &lt; ssize; &#43;&#43;i)
  {
    v6 = (v6 &#43; 1) % 256;
    v5 = (v5 &#43; s_box[v6]) % 256;
    swap(&amp;s_box[v6], &amp;s_box[v5]);
    data[i] ^= s_box[(s_box[v5] &#43; s_box[v6]) % 256];
  }
}

void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t key[4])
{
  unsigned int i;
  uint32_t v0 = v[0], v1 = v[1], delta = 0x9E3779B9, sum = delta * num_rounds;
  for (i = 0; i &lt; num_rounds; i&#43;&#43;)
  {
    v1 -= (((v0 &lt;&lt; 4) ^ (v0 &gt;&gt; 5)) &#43; v0) ^ (sum &#43; key[(sum &gt;&gt; 11) &amp; 3]);
    sum -= delta;
    v0 -= (((v1 &lt;&lt; 4) ^ (v1 &gt;&gt; 5)) &#43; v1) ^ (sum &#43; key[sum &amp; 3]);
  }
  v[0] = v0;
  v[1] = v1;
}

BYTE base_table[] = &#34;ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789&#43;/&#34;;

int main()
{
  unsigned char rc4_key[16];
  unsigned char key[16];

  srand(0x114514u);
  for (size_t i = 0; i &lt; 100; &#43;&#43;i)
  {
    int v6 = rand() % 64;
    int v4 = rand() % 64;
    swap(&amp;base_table[v6], &amp;base_table[v4]);
  }

  printf(&#34;base_table: %s\n&#34;, base_table);
  srand(0x1919810u);

  for (size_t i = 0; i &lt; 16; &#43;&#43;i)
  {
    rc4_key[i] = rand() % 255;
    key[i] = rand() % 255;
  }

  for (size_t i = 0; i &lt; 16; i &#43;= 2)
  {
    decipher(0x64, enc_data &#43; i, (uint32_t *)key);
  }

  rc4_crypt((BYTE *)enc_data, 4 * (64 / 3), rc4_key, 16);

  for (size_t i = 0; i &lt; 64; i&#43;&#43;)
  {
    printf(&#34;%c&#34;, *((BYTE *)enc_data &#43; i));
  }
}
/*
base_table: 4yZRiNP8LoK/GSA5ElWkUjXtJCz7bMYcuFfpm6&#43;hV0rxeHIdwv32QOTnqg1BDsa9
C&#43;vFCnHRGPghbmyQMXvFMRNd7fNCG8jcU&#43;jcbnjRJTj2GTCOGUvgtOS0CTge7fNs
*/
```
最后得到了打乱后的表和base64编码后的flag，用CyberChef自定义码表解码一下就好了

flag: `flag{C0ngr@tulat1on!Y0u_Re_suCces3fu1Ly_Signln!}`
## BEDTEA
{{&lt; admonition tip &#34;题目描述&#34;&gt;}}
题目内容：

来一杯睡前tea

[附件下载](https://pan.baidu.com/s/1iT4aSOaAReattT3cTzuMeA) 提取码（GAME）[备用下载](https://share.weiyun.com/gW8XBb6f)
{{&lt; /admonition &gt;}}
这题主要难点还是在于SSE指令吧，中间还夹杂着一些算法和数据结构，不过通过动调还是很容易分析出逻辑的

### 0x01 反调试
程序中有两处反调试
第一处是 `IsDebuggerPresent`，如果检测到在调试状态，则赋值为1，否则为3,

这处反调试决定了后面斐波那契数列的起始值，影响tea的key
```c
fib_start = !IsDebuggerPresent() ? 3 : 1;
```

还有一处是时间反调试，如果你在这中间断了很久，超过了判定时间范围，就会认为你在调试他
```cpp
begin_time = std::chrono::_V2::system_clock::now(v3);
...
if ( std::chrono::_V2::system_clock::now(v7) - begin_time &lt;= 10000999 )
{
    ...
}
else  
{
    ... // 检测到被调试则执行else分支
}
```

### 0x02 加密算法分析
#### 斐波那契数列计算key
程序首先会将输入分为三部分，用tea算法加密

并且key由计算斐波那契数列得出，三组的key都不一样
```c

void main()
{
  ...
  fib_start = !IsDebuggerPresent() ? 3 : 1;     // 检测是否被调试，没有则为3，决定了斐波那契数列的起始值，影响tea的key
  tea((unsigned int *)&amp;input);
  tea((unsigned int *)&amp;input1);
  tea((unsigned int *)&amp;input2);
  ...
}
void __fastcall tea(unsigned int *input)
{
  int v1; // ebp
  int *v2; // r12
  int v3; // r13d
  int v4; // ebx
  int v5; // r9d
  int v6; // edi
  int v7; // r11d
  int v8; // esi
  int v9; // eax
  int v10; // r8d
  int v11; // edx
  int v12; // eax
  unsigned int data1; // edx
  int sum; // r9d
  unsigned int data0; // r8d

  v1 = fib_start;
  v2 = &amp;key0;
  *(__m128i *)&amp;key0 = _mm_load_si128((const __m128i *)&amp;xmmword_405050);
  v3 = fib_start &#43; 4;
  do                                            // 计算斐波那契数列
  {
    v4 = v1;
    if ( v1 &lt;= 0 )
    {
      v12 = 1;
    }
    else
    {
      v5 = 0;
      v6 = 0;
      v7 = 1;
      v8 = 1;
      v9 = 1;
      do
      {
        if ( (v4 &amp; 1) != 0 )
        {
          v10 = v6;
          v6 = v7 * v8 &#43; v5 * v6;
          v8 = v7 * v10 &#43; v9 * v8;
        }
        v11 = v7 * v7;
        v7 *= v5 &#43; v9;
        v5 = v11 &#43; v5 * v5;
        v4 &gt;&gt;= 1;
        v9 = v9 * v9 &#43; v11;
      }
      while ( v4 );
      v12 = v8;
    }
    &#43;&#43;v1;
    *v2&#43;&#43; = v12;
  }
  while ( v1 != v3 );
  fib_start = v1;
  data1 = input[1];
  sum = 0;
  data0 = *input;
  do
  {
    sum -= 0x61CBB648;
    data0 &#43;= (sum &#43; data1) ^ (key1 &#43; (data1 &gt;&gt; 4)) ^ (key0 &#43; 32 * data1);
    data1 &#43;= (sum &#43; data0) ^ (key3 &#43; (data0 &gt;&gt; 4)) ^ (key2 &#43; 32 * data0);
  }
  while ( sum != 0x987E55D0 );
  *input = data0;
  input[1] = data1;
}
```

正常在没有被检测到调试的情况下，数列起始值应该是3，那么就可以得到三组key的值了

```c
unsigned int key1[4] = {
    3, 5, 8, 13
};
unsigned int key2[4] = {
    21, 34, 55, 89
};
unsigned int key3[4] = {
    144, 233, 377, 610
};
```
#### TEA
一个魔改的tea,修改了delta，rounds和移位等常量，应该一眼就能看出来

```c
void decrypt(uint32_t *v, uint32_t *k)
{
    uint32_t v0 = v[0], v1 = v[1], i;
    uint32_t delta = -0x61cbb648;
    uint32_t sum = delta * 22;
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    for (i = 0; i &lt; 22; i&#43;&#43;)
    {
        v1 -= ((v0 &lt;&lt; 5) &#43; k2) ^ (v0 &#43; sum) ^ ((v0 &gt;&gt; 4) &#43; k3);
        v0 -= ((v1 &lt;&lt; 5) &#43; k0) ^ (v1 &#43; sum) ^ ((v1 &gt;&gt; 4) &#43; k1);
        sum -= delta;
    }
    v[0] = v0; v[1] = v1;
}
```

#### 二叉树和后序遍历
没学过数据结构，看了半天发现是二叉树后就去粗略学了一下，

恢复了一下符号，先是将输入构建了一个二叉树，然后后序遍历，保存在一个全局变量里

说实话，不懂数据结构也没关系，因为他这做法只是相当于把数组逆序了一下，动调一下就能看出来...
```c
struct TreeNode
{
  __int16 value;
  TreeNode *left;
  TreeNode *right;
};

void main()
{
  ...
  si128 = _mm_load_si128((const __m128i *)&amp;input);
  currIndex = 0;
  p_input = si128;
  tree = buildBinaryTree((BYTE *)&amp;p_input, &amp;currIndex, 24);
  if ( tree )
    postOrderTraversal(tree);
  ...
}

TreeNode *__fastcall buildBinaryTree(BYTE *inputArray, int *currentIndex, int arraySize)
{
  TreeNode *v3; // rbx
  __int64 index; // rax
  __int16 v8; // r12
  TreeNode *v9; // rax

  v3 = 0i64;
  index = *currentIndex;
  if ( (int)index &lt; arraySize )
  {
    *currentIndex = index &#43; 1;
    v8 = inputArray[index];
    v9 = (TreeNode *)operator new(0x18ui64);
    *(_OWORD *)&amp;v9-&gt;left = 0i64;
    v3 = v9;
    v9-&gt;value = v8;
    v9-&gt;left = buildBinaryTree(inputArray, currentIndex, arraySize);
    v3-&gt;right = buildBinaryTree(inputArray, currentIndex, arraySize);
  }
  return v3;
}

void __fastcall postOrderTraversal(TreeNode *a1)
{
  TreeNode *left; // rcx
  TreeNode *right; // rcx
  __int64 index; // rax
  __int16 value; // cx

  left = a1-&gt;left;
  if ( left )
    postOrderTraversal(left);
  right = a1-&gt;right;
  if ( right )
    postOrderTraversal(right);
  index = g_index;
  value = a1-&gt;value;
  &#43;&#43;g_index;
  *((_WORD *)&amp;my_data &#43; index) = value;
}

```

#### 异或
可能看着比较抽象的就是中间那一片奇奇怪怪的指令了，不过一眼看上去其实也就只是一个异或而已

还是一样，直接动调观察数据变化，发现这部分内容就是将数据每一位异或0x33
```c
if ( std::chrono::_V2::system_clock::now(v7) - begin_time &lt;= 10000999 )// 时间反调试
  {
    xor_key = _mm_load_si128((const __m128i *)&amp;xmmword_405070);
    xmmword_408070 = (__int128)_mm_xor_si128(_mm_load_si128((const __m128i *)&amp;xmmword_408070), xor_key);
    xmmword_408080 = (__int128)_mm_xor_si128(_mm_load_si128((const __m128i *)&amp;xmmword_408080), xor_key);
    xmmword_408090 = (__int128)_mm_xor_si128(_mm_load_si128((const __m128i *)&amp;xmmword_408090), xor_key);
    xmmword_4080A0 = (__int128)_mm_xor_si128(_mm_load_si128((const __m128i *)&amp;xmmword_4080A0), xor_key);
    xmmword_4080B0 = (__int128)_mm_xor_si128(_mm_load_si128((const __m128i *)&amp;xmmword_4080B0), xor_key);
    xmmword_4080C0 = (__int128)_mm_xor_si128(_mm_load_si128((const __m128i *)&amp;xmmword_4080C0), xor_key);
    xmmword_4080D0 = (__int128)_mm_xor_si128(_mm_load_si128((const __m128i *)&amp;xmmword_4080D0), xor_key);
    xmmword_4080E0 = (__int128)_mm_xor_si128(_mm_load_si128((const __m128i *)&amp;xmmword_4080E0), xor_key);
    v9 = _mm_load_si128((const __m128i *)&amp;xmmword_408110);
    xmmword_4080F0 = (__int128)_mm_xor_si128(_mm_load_si128((const __m128i *)&amp;xmmword_4080F0), xor_key);
    v10 = _mm_xor_si128(_mm_load_si128((const __m128i *)&amp;xmmword_408100), xor_key);
    qword_408120 ^= 0x33003300330033ui64;
  }
xmmword_408100 = (__int128)v10;
xmmword_408110 = (__int128)_mm_xor_si128(v9, xor_key);
my_data = (__int128)_mm_xor_si128(xor_key, (__m128i)my_data);
```
### 0x03 exp
```c
#include &lt;stdio.h&gt;
#include &lt;stdint.h&gt;

void decrypt(uint32_t *v, uint32_t *k)
{
    uint32_t v0 = v[0], v1 = v[1], i;
    uint32_t delta = -0x61cbb648;
    uint32_t sum = delta * 22;
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    for (i = 0; i &lt; 22; i&#43;&#43;)
    {
        v1 -= ((v0 &lt;&lt; 5) &#43; k2) ^ (v0 &#43; sum) ^ ((v0 &gt;&gt; 4) &#43; k3);
        v0 -= ((v1 &lt;&lt; 5) &#43; k0) ^ (v1 &#43; sum) ^ ((v1 &gt;&gt; 4) &#43; k1);
        sum -= delta;
    }
    v[0] = v0;
    v[1] = v1;
}

unsigned int key1[4] = {
    3, 5, 8, 13
};
unsigned int key2[4] = {
    21, 34, 55, 89
};
unsigned int key3[4] = {
    144, 233, 377, 610
};

unsigned char enc_data[] = {
    0x76, 0x71, 0x9d, 0xe7, 0x70, 0x77, 0x3f, 0xa3,
    0x02, 0xf1, 0x8d, 0xc9, 0x02, 0xc6, 0xa2, 0x4b,
    0xba, 0x19, 0x56, 0x05, 0xf2, 0x89, 0x5e, 0xe0
};

int main()
{
    // 异或0x33
    for (int i = 0; i &lt; 24; i&#43;&#43;) {
        enc_data[i] ^= 0x33;
    }

    // 逆序
    for (int i = 0; i &lt; 24 / 2; i&#43;&#43;) {
        unsigned char temp = enc_data[i];
        enc_data[i] = enc_data[24 - 1 - i];
        enc_data[24 - 1 - i] = temp;
    }

    // TEA解密
    decrypt((unsigned int *)enc_data, key1);
    decrypt((unsigned int *)enc_data &#43; 2, key2);
    decrypt((unsigned int *)enc_data &#43; 4, key3);

    printf(&#34;%s&#34;, enc_data);
    // flag{y0u_reallyl1ke_te@}
}
```

---

> Author: yuro  
> URL: /posts/73f38a7/  

