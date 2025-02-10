# VNCTF2025 Writeup

VNCTF2025 Writeup
&lt;!--more--&gt;
## 碎碎念
去年摸个一血就跑路了，今年总得摸个贴纸吧哈哈

## Misc
### VN_Lang
题目给了源码，读源码可知，flag是直接硬编码在程序中的，然后加载一个自定义的字体显示出来。那么直接strings大法就ok了
```bash
$ strings VN_lang_074712b442f25c5c9915effbafe7e9fc.exe | grep VNCTF
VNCTF{Hb976Vj4HZT4q9MuDrJMDOK9SDp8OqXhkZuIOnBW6IOuO}
```

### aimind
&gt; 环境好像坏了，这里口述一下

本来是不会的，但是hint给的实在太多了，于是研究了一下

尝试欺骗AI，发现没有任何效果，经过一番奇思妙想后发现可以用`file:///`协议去读任意文件，存在ssrf漏洞。加上hint说内网有一个redis，猜一下就是利用ssrf打redis了，但是读了半天redis配置文件没读到，就猜他是没密码的吧，照着这篇文章打了一下 [SSRF结合Redis未授权的打法](https://www.cnblogs.com/mysticbinary/p/18297386) ，payload拿过来可以直接用，不过需要注意的是他靶机重启的时候ip貌似会变，hint给的`172.18.0.3`，我最后打的是`172.18.0.2`，读一下`etc/hosts`就能看出来，最后弹个shell出来就可以直接`cat flag`了。

## Reverse
### Hook Fish

分析加密流程`encrypt-&gt;encode-check`

从`http://47.121.211.23/hook_fish.dex`远程下载了dex然后加载

```java
package fish.hook_fish;
import java.lang.Object;
import java.lang.String;
import java.lang.StringBuilder;
import java.util.HashMap;
import java.lang.Character;

public class hook_fish	// class@000003 from hook_fish.dex
{
    private HashMap fish_dcode;
    private HashMap fish_ecode;
    private String strr;

    public void hook_fish(){
       super();
       this.strr = &#34;jjjliijijjjjjijiiiiijijiijjiijijjjiiiiijjjjliiijijjjjljjiilijijiiiiiljiijjiiliiiiiiiiiiiljiijijiliiiijjijijjijijijijiilijiijiiiiiijiljijiilijijiiiijjljjjljiliiijjjijiiiljijjijiiiiiiijjliiiljjijiiiliiiiiiljjiijiijiijijijjiijjiijjjijjjljiliiijijiiiijjliijiijiiliiliiiiiiljiijjiiliiijjjliiijjljjiijiiiijiijjiijijjjiiliiliiijiijijijiijijiiijjjiijjijiiiljiijiijilji&#34;;
       this.encode_map();
       this.decode_map();
    }
    public boolean check(String p0){
       if (p0.equals(this.strr)) {
          return true;
       }
       return false;
    }
    public String decode(String p0){
       StringBuilder str = &#34;&#34;;
       int i = 0;
       int i1 = 0;
       while (true) {
          int i2 = p0.length() / 5;
          if (i1 &lt; i2) {
             int i3 = i &#43; 5;
             str = str.append(this.fish_dcode.get(p0.substring(i, i3)));
             i1 = i1 &#43; 1;
             i = i3;
          }else {
             break ;
          }
       }
       return str;
    }
    public void decode_map(){
       HashMap hashMap = new HashMap();
       this.fish_dcode = hashMap;
       hashMap.put(&#34;iiijj&#34;, Character.valueOf(&#39;a&#39;));
       this.fish_dcode.put(&#34;jjjii&#34;, Character.valueOf(&#39;b&#39;));
       this.fish_dcode.put(&#34;jijij&#34;, Character.valueOf(&#39;c&#39;));
       this.fish_dcode.put(&#34;jjijj&#34;, Character.valueOf(&#39;d&#39;));
       this.fish_dcode.put(&#34;jjjjj&#34;, Character.valueOf(&#39;e&#39;));
       this.fish_dcode.put(&#34;ijjjj&#34;, Character.valueOf(&#39;f&#39;));
       this.fish_dcode.put(&#34;jjjji&#34;, Character.valueOf(&#39;g&#39;));
       this.fish_dcode.put(&#34;iijii&#34;, Character.valueOf(&#39;h&#39;));
       this.fish_dcode.put(&#34;ijiji&#34;, Character.valueOf(&#39;i&#39;));
       this.fish_dcode.put(&#34;iiiji&#34;, Character.valueOf(&#39;j&#39;));
       this.fish_dcode.put(&#34;jjjij&#34;, Character.valueOf(&#39;k&#39;));
       this.fish_dcode.put(&#34;jijji&#34;, Character.valueOf(&#39;l&#39;));
       this.fish_dcode.put(&#34;ijiij&#34;, Character.valueOf(&#39;m&#39;));
       this.fish_dcode.put(&#34;iijji&#34;, Character.valueOf(&#39;n&#39;));
       this.fish_dcode.put(&#34;ijjij&#34;, Character.valueOf(&#39;o&#39;));
       this.fish_dcode.put(&#34;jiiji&#34;, Character.valueOf(&#39;p&#39;));
       this.fish_dcode.put(&#34;ijijj&#34;, Character.valueOf(&#39;q&#39;));
       this.fish_dcode.put(&#34;jijii&#34;, Character.valueOf(&#39;r&#39;));
       this.fish_dcode.put(&#34;iiiii&#34;, Character.valueOf(&#39;s&#39;));
       this.fish_dcode.put(&#34;jjiij&#34;, Character.valueOf(&#39;t&#39;));
       this.fish_dcode.put(&#34;ijjji&#34;, Character.valueOf(&#39;u&#39;));
       this.fish_dcode.put(&#34;jiiij&#34;, Character.valueOf(&#39;v&#39;));
       this.fish_dcode.put(&#34;iiiij&#34;, Character.valueOf(&#39;w&#39;));
       this.fish_dcode.put(&#34;iijij&#34;, Character.valueOf(&#39;x&#39;));
       this.fish_dcode.put(&#34;jjiji&#34;, Character.valueOf(&#39;y&#39;));
       this.fish_dcode.put(&#34;jijjj&#34;, Character.valueOf(&#39;z&#39;));
       this.fish_dcode.put(&#34;iijjl&#34;, Character.valueOf(&#39;1&#39;));
       this.fish_dcode.put(&#34;iiilj&#34;, Character.valueOf(&#39;2&#39;));
       this.fish_dcode.put(&#34;iliii&#34;, Character.valueOf(&#39;3&#39;));
       this.fish_dcode.put(&#34;jiili&#34;, Character.valueOf(&#39;4&#39;));
       this.fish_dcode.put(&#34;jilji&#34;, Character.valueOf(&#39;5&#39;));
       this.fish_dcode.put(&#34;iliji&#34;, Character.valueOf(&#39;6&#39;));
       this.fish_dcode.put(&#34;jjjlj&#34;, Character.valueOf(&#39;7&#39;));
       this.fish_dcode.put(&#34;ijljj&#34;, Character.valueOf(&#39;8&#39;));
       this.fish_dcode.put(&#34;iljji&#34;, Character.valueOf(&#39;9&#39;));
       this.fish_dcode.put(&#34;jjjli&#34;, Character.valueOf(&#39;0&#39;));
    }
    public String encode(String p0){
       StringBuilder str = &#34;&#34;;
       for (int i = 0; i &lt; p0.length(); i = i &#43; 1) {
          str = str.append(this.fish_ecode.get(Character.valueOf(p0.charAt(i))));
       }
       return str;
    }
    public void encode_map(){
       HashMap hashMap = new HashMap();
       this.fish_ecode = hashMap;
       hashMap.put(Character.valueOf(&#39;a&#39;), &#34;iiijj&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;b&#39;), &#34;jjjii&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;c&#39;), &#34;jijij&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;d&#39;), &#34;jjijj&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;e&#39;), &#34;jjjjj&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;f&#39;), &#34;ijjjj&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;g&#39;), &#34;jjjji&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;h&#39;), &#34;iijii&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;i&#39;), &#34;ijiji&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;j&#39;), &#34;iiiji&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;k&#39;), &#34;jjjij&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;l&#39;), &#34;jijji&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;m&#39;), &#34;ijiij&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;n&#39;), &#34;iijji&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;o&#39;), &#34;ijjij&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;p&#39;), &#34;jiiji&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;q&#39;), &#34;ijijj&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;r&#39;), &#34;jijii&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;s&#39;), &#34;iiiii&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;t&#39;), &#34;jjiij&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;u&#39;), &#34;ijjji&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;v&#39;), &#34;jiiij&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;w&#39;), &#34;iiiij&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;x&#39;), &#34;iijij&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;y&#39;), &#34;jjiji&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;z&#39;), &#34;jijjj&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;1&#39;), &#34;iijjl&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;2&#39;), &#34;iiilj&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;3&#39;), &#34;iliii&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;4&#39;), &#34;jiili&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;5&#39;), &#34;jilji&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;6&#39;), &#34;iliji&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;7&#39;), &#34;jjjlj&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;8&#39;), &#34;ijljj&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;9&#39;), &#34;iljji&#34;);
       this.fish_ecode.put(Character.valueOf(&#39;0&#39;), &#34;jjjli&#34;);
    }
}
```

既然给了decode，代码抄下来调用一下就好了
```java
public static void main(String[] args) {
    hook_fish h = new hook_fish();
    
    System.out.println(h.decode(h.strr));
    // 0qksrtuw0x74r2n3s2x3ooi4ps54r173k2os12r32pmqnu73r1h432n301twnq43prruo2h5
}
```
encrypt懒得逆了，测了一下可以直接爆破，那就开爆
```python
from string import printable

def code(a, index):
    if index &gt;= len(a) - 1:
        return
    
    a[index] = chr(ord(a[index]) ^ ord(a[index &#43; 1]))
    a[index &#43; 1] = chr(ord(a[index]) ^ ord(a[index &#43; 1]))
    a[index] = chr(ord(a[index]) ^ ord(a[index &#43; 1]))
    
    code(a, index &#43; 2)

def encrypt(string):
    str1 = bytearray(string.encode())
    for i in range(len(str1)):
        str1[i] = (str1[i] &#43; 68) &amp; 0xFF 
    
    str2 = &#39;&#39;.join([f&#39;{b:02x}&#39; for b in str1])
    
    str3 = list(str2)
    
    code(str3, 0)
    
    for i in range(len(str3)):
        if &#39;a&#39; &lt;= str3[i] &lt;= &#39;f&#39;:
            str3[i] = chr(ord(str3[i]) - ord(&#39;1&#39;) &#43; (i % 4))
        else:
            str3[i] = chr(ord(str3[i]) &#43; ord(&#39;7&#39;) &#43; (i % 10))
    
    result = &#39;&#39;.join(str3)
    return result

enc = &#34;0qksrtuw0x74r2n3s2x3ooi4ps54r173k2os12r32pmqnu73r1h432n301twnq43prruo2h5&#34;

flag = list(&#34;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&#34;)

t = 0
while t &lt; 36:
    for i in printable:
        flag[t] = i
        e = encrypt(&#39;&#39;.join(flag))
        if enc[(t*2):(t*2)&#43;2] == e[(t*2):(t*2)&#43;2]:
            print(&#34;&#34;.join(flag))
            t &#43;= 1
            break
# VNCTF{u_re4l1y_kn0w_H0Ok_my_f1Sh!1l}
```

### Fuko&#39;s starfish
exe里没什么有用的东西，直接看`starfish.dll`，有一堆反调试，但只要我不调试他就反不到我

游戏胜利后调了用了一个函数，里面就一个AES解密，将一些byte_xxxxx异或0x17作为key，找交叉引用跟到了一个ThreadProc里，看到rand第一反应就去找srand的交叉引用了，果不其然在下面有一个花指令，将他nop掉就能看到正确的生成key逻辑了

```c
__int64 __fastcall ThreadProc(LPVOID lpThreadParameter)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD &#34;&#43;&#34; TO EXPAND]

  v1 = rand();
  byte_7FFE8793E1E0 = v1 &#43; v1 / 255;
  v2 = rand();
  byte_7FFE8793E1F0 = v2 &#43; v2 / 255;
  v3 = rand();
  byte_7FFE8793E1F2 = v3 &#43; v3 / 255;
  v4 = rand();
  byte_7FFE8793E200 = v4 &#43; v4 / 255;
  v5 = rand();
  byte_7FFE8793E204 = v5 &#43; v5 / 255;
  v6 = rand();
  byte_7FFE8793E210 = v6 &#43; v6 / 255;
  v7 = rand();
  byte_7FFE8793E950 = v7 &#43; v7 / 255;
  v8 = rand();
  byte_7FFE8793E220 = v8 &#43; v8 / 255;
  v9 = rand();
  byte_7FFE8793E228 = v9 &#43; v9 / 255;
  v10 = rand();
  byte_7FFE8793E230 = v10 &#43; v10 / 255;
  v11 = rand();
  byte_7FFE8793E232 = v11 &#43; v11 / 255;
  v12 = rand();
  byte_7FFE8793E240 = v12 &#43; v12 / 255;
  v13 = rand();
  byte_7FFE8793E244 = v13 &#43; v13 / 255;
  v14 = rand();
  byte_7FFE8793E960 = v14 &#43; v14 / 255;
  v15 = rand();
  byte_7FFE8793E962 = v15 &#43; v15 / 255;
  v16 = rand();
  byte_7FFE8793E970 = v16 &#43; v16 / 255;
  srand(114514u);
  v17 = rand();
  byte_7FFE8793E1E0 = v17 &#43; v17 / 255;
  v18 = rand();
  byte_7FFE8793E1F0 = v18 &#43; v18 / 255;
  v19 = rand();
  byte_7FFE8793E1F2 = v19 &#43; v19 / 255;
  v20 = rand();
  byte_7FFE8793E200 = v20 &#43; v20 / 255;
  v21 = rand();
  byte_7FFE8793E204 = v21 &#43; v21 / 255;
  v22 = rand();
  byte_7FFE8793E210 = v22 &#43; v22 / 255;
  v23 = rand();
  byte_7FFE8793E950 = v23 &#43; v23 / 255;
  v24 = rand();
  byte_7FFE8793E220 = v24 &#43; v24 / 255;
  v25 = rand();
  byte_7FFE8793E228 = v25 &#43; v25 / 255;
  v26 = rand();
  byte_7FFE8793E230 = v26 &#43; v26 / 255;
  v27 = rand();
  byte_7FFE8793E232 = v27 &#43; v27 / 255;
  v28 = rand();
  byte_7FFE8793E240 = v28 &#43; v28 / 255;
  v29 = rand();
  byte_7FFE8793E244 = v29 &#43; v29 / 255;
  v30 = rand();
  byte_7FFE8793E960 = v30 &#43; v30 / 255;
  v31 = rand();
  byte_7FFE8793E962 = v31 &#43; v31 / 255;
  v32 = rand();
  byte_7FFE8793E970 = v32 &#43; v32 / 255;
  return 0LL;
}
```
那么直接抄下来输出生成的key就行喽，代码太长？无所谓AI会帮我全部补全
```c
#include &lt;windows.h&gt;
#include &lt;stdio.h&gt;
#include &lt;stdlib.h&gt;

int v17;
int v18;
int v19;
int v20;
int v21;
int v22;
int v23;
int v24;
int v25;
int v26;
int v27;
int v28;
int v29;
int v30;
int v31;
int v32;

unsigned char byte_7FFE8793E1E0;
unsigned char byte_7FFE8793E1F0;
unsigned char byte_7FFE8793E1F2;
unsigned char byte_7FFE8793E200;
unsigned char byte_7FFE8793E204;
unsigned char byte_7FFE8793E210;
unsigned char byte_7FFE8793E950;
unsigned char byte_7FFE8793E220;
unsigned char byte_7FFE8793E228;
unsigned char byte_7FFE8793E230;
unsigned char byte_7FFE8793E232;
unsigned char byte_7FFE8793E240;
unsigned char byte_7FFE8793E244;
unsigned char byte_7FFE8793E960;
unsigned char byte_7FFE8793E962;
unsigned char byte_7FFE8793E970;

int main() {
    srand(114514u);
    v17 = rand();
    byte_7FFE8793E1E0 = v17 &#43; v17 / 255;
    v18 = rand();
    byte_7FFE8793E1F0 = v18 &#43; v18 / 255;
    v19 = rand();
    byte_7FFE8793E1F2 = v19 &#43; v19 / 255;
    v20 = rand();
    byte_7FFE8793E200 = v20 &#43; v20 / 255;
    v21 = rand();
    byte_7FFE8793E204 = v21 &#43; v21 / 255;
    v22 = rand();
    byte_7FFE8793E210 = v22 &#43; v22 / 255;
    v23 = rand();
    byte_7FFE8793E950 = v23 &#43; v23 / 255;
    v24 = rand();
    byte_7FFE8793E220 = v24 &#43; v24 / 255;
    v25 = rand();
    byte_7FFE8793E228 = v25 &#43; v25 / 255;
    v26 = rand();
    byte_7FFE8793E230 = v26 &#43; v26 / 255;
    v27 = rand();
    byte_7FFE8793E232 = v27 &#43; v27 / 255;
    v28 = rand();
    byte_7FFE8793E240 = v28 &#43; v28 / 255;
    v29 = rand();
    byte_7FFE8793E244 = v29 &#43; v29 / 255;
    v30 = rand();
    byte_7FFE8793E960 = v30 &#43; v30 / 255;
    v31 = rand();
    byte_7FFE8793E962 = v31 &#43; v31 / 255;
    v32 = rand();
    byte_7FFE8793E970 = v32 &#43; v32 / 255;

    printf(&#34;%02x&#34;, byte_7FFE8793E1E0 ^ 0x17);
    printf(&#34;%02x&#34;, byte_7FFE8793E1F0 ^ 0x17);
    printf(&#34;%02x&#34;, byte_7FFE8793E1F2 ^ 0x17);
    printf(&#34;%02x&#34;, byte_7FFE8793E200 ^ 0x17);
    printf(&#34;%02x&#34;, byte_7FFE8793E204 ^ 0x17);
    printf(&#34;%02x&#34;, byte_7FFE8793E210 ^ 0x17);
    printf(&#34;%02x&#34;, byte_7FFE8793E950 ^ 0x17);
    printf(&#34;%02x&#34;, byte_7FFE8793E220 ^ 0x17);
    printf(&#34;%02x&#34;, byte_7FFE8793E228 ^ 0x17);
    printf(&#34;%02x&#34;, byte_7FFE8793E230 ^ 0x17);
    printf(&#34;%02x&#34;, byte_7FFE8793E232 ^ 0x17);
    printf(&#34;%02x&#34;, byte_7FFE8793E240 ^ 0x17);
    printf(&#34;%02x&#34;, byte_7FFE8793E244 ^ 0x17);
    printf(&#34;%02x&#34;, byte_7FFE8793E960 ^ 0x17);
    printf(&#34;%02x&#34;, byte_7FFE8793E962 ^ 0x17);
    printf(&#34;%02x&#34;, byte_7FFE8793E970 ^ 0x17);
    // 09e5fdeb683175b6b13b840891eb78d2
}
```
密文是`3D011C190BA090815F672731A89AA47497362167AB2EB4A09418D37D93E646E7`，剩下的Cyberchef梭一下就好了

🚩: `VNCTF{W0w_u_g0t_Fuk0&#39;s_st4rf1sh}`

### kotlindroid
这题挺简单的吧，就一个AES GCM，唯一要注意的是他会把iv附在加密后的数据前面，要手动去除一下
```java
byte[] cipherText = cipher.doFinal(parameterSpec1);
Intrinsics.checkNotNull(cipherText);
byte[] encryptedData = ArraysKt.plus(iv, cipherText); // &lt;---
str = Base64.encode$default(Base64.Default, encryptedData, 0, 0, 6, null);
```

然后拿frida 嘎嘎hook拿参数搓个代码解就完事了
```java
package org.example;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
public class Main {
    private static final String ALGORITHM = &#34;AES/GCM/NoPadding&#34;;
    private static final int TAG_LENGTH_BIT = 128;

    public static byte[] decrypt(String encryptedData, String secretKey, String iv, String aad) throws Exception {
        byte[] encryptedDataBytes = Base64.getDecoder().decode(encryptedData);
        byte[] ivBytes = iv.getBytes();
        byte[] aadBytes = aad.getBytes();
        
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), &#34;AES&#34;);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);

        cipher.updateAAD(aadBytes);

        return cipher.doFinal(encryptedDataBytes);
    }

    public static void main(String[] args) throws Exception {
        String secretKey = &#34;atrikeyssyekirta&#34;;
        String encryptedData = &#34;HMuJKLOW1BqCAi2MxpHYjGjpPq82XXQ/jgx5WYrZ2MV53a9xjQVbRaVdRiXFrSn6EcQPzA==&#34;;
        String iv = &#34;114514&#34;;
        String aad = &#34;mysecretadd&#34;;

        byte[] decryptedData = decrypt(encryptedData, secretKey, iv, aad);
        System.out.println(new String(decryptedData));
        // VNCTF{Y0U_@re_th3_Ma5t3r_0f_C0mp0s3}
    }
}
```

### 抽奖转盘
鸿蒙逆向，没法调试，那就静态硬猜吧

先看`pages/Index`，找到按钮的回调函数
![alt text](/images/VNCTF2025/image.png)

调用so里的MyCry函数加密输入的内容
![alt text](/images/VNCTF2025/image-1.png)

输入的内容先将每个字符加3，然后判断长度是否为40，两个分支的区别无法就是true的话里面是rc4最后多异或个长度，false最后异或固定的0x18，key是`Take_it_easy`，按照常理，肯定是走true这个分支的，最后再将数据base64编码一下
![alt text](/images/VNCTF2025/image-2.png)
![alt text](/images/VNCTF2025/image-3.png)

回到arkts层，`pages/MyPage`里又将数据每位&#43;1然后异或7
![alt text](/images/VNCTF2025/image-4.png)

密文就在下面
![alt text](/images/VNCTF2025/image-5.png)

最后厨子梭一下解密就好了
![alt text](/images/VNCTF2025/image-6.png)

### AndroidLux
Android里运行linux? 很有趣

Android那边没什么重要的东西，就初始化了busybox的环境，然后开了个socket用来通信，看Service可以发现他启动了`/root/env`
```java
package work.pangbai.androidlux.Service$1;
import java.lang.Runnable;
import work.pangbai.androidlux.Service;
import java.lang.Object;
import java.lang.String;
import work.pangbai.androidlux.cmdExer;

class Service$1 implements Runnable	// class@000061 from classes4.dex
{
    final Service this$0;

    void Service$1(Service this$0){
       this.this$0 = this$0;
       super();
    }
    public void run(){
       cmdExer.execute(&#34;gnu_linux_loader -r /data/data/work.pangbai.androidlux/files -0 -w /root -b /dev -b /proc -b /sys /bin/bash -c ./env&#34;, false, true);
    }
}
```

那么文件在哪里呢，题目给了一个env文件，这个其实是tar.gz格式的，直接可以解压，然后火速去分析root目录下的env

有几个花指令，但是IDA很智能，直接帮我们识别出来了，直接nop掉就行了

现在逻辑就很清楚了，传进来然后一个魔改base64加密了一下
![alt text](/images/VNCTF2025/image-7.png)

```c
void __fastcall encodeBase64(BYTE *data, int size, BYTE *out)
{
  int v3; // w0
  int v4; // w1
  int v5; // w1
  int v6; // w0
  int v7; // w1
  int v8; // w0
  _BYTE *d; // [xsp&#43;58h] [xbp&#43;58h]
  int i; // [xsp&#43;68h] [xbp&#43;68h]
  int ii; // [xsp&#43;68h] [xbp&#43;68h]
  int j; // [xsp&#43;6Ch] [xbp&#43;6Ch]

  sqrt((double)25);
  j = 0;
  if ( size % 3 )
    v3 = 4;
  else
    v3 = 0;
  d = malloc(4 * (size / 3) &#43; 1 &#43; v3);
  for ( i = 0; i &lt; size; &#43;&#43;i )
  {
    if ( size - i &lt;= 2 )
    {
      d[j] = base64[data[i] &gt;&gt; 2];
      if ( size - i == 2 )
      {
        v7 = data[i&#43;&#43;] &amp; 3;
        d[j &#43; 1] = base64[v7 | ((int)data[i] &gt;&gt; 2) &amp; 0x3C];
        d[j &#43; 2] = base64[data[i] &amp; 0xF];
      }
      else
      {
        d[j &#43; 1] = base64[data[i] &amp; 3];
        d[j &#43; 2] = &#39;=&#39;;
      }
      v8 = j &#43; 3;
      j &#43;= 4;
      d[v8] = &#39;=&#39;;
    }
    else
    {
      d[j] = base64[data[i] &gt;&gt; 2];
      v4 = data[i] &amp; 3;
      ii = i &#43; 1;
      d[j &#43; 1] = base64[v4 | ((int)data[ii] &gt;&gt; 2) &amp; 60];
      v5 = data[ii] &amp; 15;
      i = ii &#43; 1;
      d[j &#43; 2] = base64[v5 | (16 * (data[i] &gt;&gt; 6))];
      v6 = j &#43; 3;
      j &#43;= 4;
      d[v6] = base64[data[i] &amp; 0x3F];
    }
  }
  d[j] = 0;
  *(_QWORD *)out = d;
}
```

密文: `RPVIRN40R9PU67ue6RUH88Rgs65Bp8td8VQm4SPAT8Kj97QgVG==`
自定义表: `TUVWXYZabcdefghijABCDEF456789GHIJKLMNOPQRSklmnopqrstuvwxyz0123&#43;/`

base64魔改点就在将第二部分的前2个bit和后4个bit互换，第三部分的前4个bit和后2个bit互换，其他不变

但是尝试解码的时候出现了问题，`R`查表得到40，转二进制就是`101000`，第一个字符的最高位是1？这不符合可打印字符的范围，说明这题还有其他地方藏了逻辑

在把这个程序翻了个底朝天也没找到东西后，只能看看是不是这个环境哪里对程序做了修改，掏出我们的everything, 按时间排序一下文件，看看出题人在哪里干了坏事

接着就翻到了`ld.so.preload`文件，加载了`/usr/libexec/libexec.so`

果不其然，在这个so里面hook了`read`和`strcmp`函数
![alt text](/images/VNCTF2025/image-8.png)

那么逻辑已经十分清晰了，exp:
```python

def custom_rot13_decrypt(data: str) -&gt; str:
    dec = []
    for c in data:
        if &#39;A&#39; &lt;= c &lt;= &#39;M&#39; or &#39;a&#39; &lt;= c &lt;= &#39;m&#39;:
            dec.append(chr(ord(c) &#43; 13))
        elif &#39;N&#39; &lt;= c &lt;= &#39;Z&#39; or &#39;n&#39; &lt;= c &lt;= &#39;z&#39;:
            dec.append(chr(ord(c) - 13))
        else:
            dec.append(c)
    return &#39;&#39;.join(dec)

cipher_text = &#34;RPVIRN40R9PU67ue6RUH88Rgs65Bp8td8VQm4SPAT8Kj97Qg&#34;
table = list(&#34;TUVWXYZabcdefghijABCDEF456789GHIJKLMNOPQRSklmnopqrstuvwxyz0123&#43;/&#34;)

eee = custom_rot13_decrypt(cipher_text)


enc = eee.encode()

idx = []

for i in enc:
    idx.append(table.index(chr(i)))

s = []

for i in idx:
    s.append(bin(i)[2:].zfill(6))

for i in range(0, len(s), 4):
    s[i &#43; 1] = s[i &#43; 1][4:] &#43; s[i &#43; 1][:4]
    s[i &#43; 2] = s[i &#43; 2][2:] &#43; s[i &#43; 2][:2]

res = &#34;&#34;
for i in s:
    res &#43;= i

b = [res[i:i&#43;8] for i in range(0, len(res), 8)]

for i in b:
    print(chr(int(i, 2) ^ 1), end=&#34;&#34;)
    
print(&#34;}&#34;)
# VNCTF{Ur_go0d_@ndr0id&amp;l1nux_Reve7ser}
```

---

> Author: yuro  
> URL: /posts/65d31d5a/  

