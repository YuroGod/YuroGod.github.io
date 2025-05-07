# 某端游外挂网络验证的分析与破解

某端游外挂网络验证的分析与破解
&lt;!--more--&gt;
## 前言
去年年底的时候，听说该游戏出现了一个挂号称可以无限刷爱心(游戏货币)，于是从朋友A那里要来了样本，折腾半天干掉了网络验证部分，结果一顿分析完之后发现该功能的实现原理十分不优雅，放国内游戏厂商估计老早ban掉了...这里就把其网络验证部分的分析和破解思路分享出来吧，整个流程还是挺有意思的

## 分析
国际惯例，DIE启动，可以看到加了个SE壳

![](/images/某端游外挂网络验证的分析与破解/image.png)

启动dump一下，丢IDA分析，看代码特征能看出来是易语言写的，还有经典的一堆VMProtect标记，大概是网络验证模块里的代码自带的，代码也没有任何被vm的地方，那就简单了

![](/images/某端游外挂网络验证的分析与破解/image-1.png)

首先要解决第一个问题，因为出了一些意外被作者抓到有人破解了他的大宝贝，所以有一个关键云端文件被清空了，现在直接打开会报一个错误
![](/images/某端游外挂网络验证的分析与破解/image-2.png)

HTTP Debugger抓包看一下，从云端获取了`SSSSSPRO.json`这个文件
![](/images/某端游外挂网络验证的分析与破解/image-3.png)

当时第一次破的时候忘记把文件内容存下来了，所以后面在这里折腾了好一会，去分析代码又太麻烦。这时突然就灵机一动，他既然有PRO，那会不会还有不带PRO的版本呢？

诶试了一下他还真有，格式是一模一样的
![](/images/某端游外挂网络验证的分析与破解/image-4.png)

然后又折腾好一会猜一下对应字段的意思
```json
{
	&#34;SM&#34;: &#34;d54bca47c7d6fa5247dd8f9cadd2ac5e1&#34;, // Software MD5
	&#34;UM&#34;: &#34;b27d69cf88e09e919328b0a2bada77c8&#34;,  // Updater MD5
	&#34;DB&#34;: 1131533037,                          // unknown
	&#34;ZB&#34;: 1,                                   // unknown
	&#34;MRDB&#34;: [                                  // 每日代币数据
        ...
	],
	&#34;clickPic&#34;: &#34;...&#34;,                         // 点击图片跳转的链接
	&#34;notice&#34;: &#34;...&#34;                            // 公告  
}
```

那么本地起个server简单模拟一下数据，然后将程序对应的url替换了就可以了
```python
from flask import Flask, jsonify, make_response

app = Flask(__name__)

@app.route(&#39;/pc/SSSSSPRO.json&#39;, methods=[&#39;GET&#39;])
def init():
    d = jsonify({
        &#34;SM&#34;: &#34;8e8b5927c023c6c04689c94f3b96269b&#34;,
        &#34;UM&#34;: &#34;0974868e7f92234dfab0ccc9d37f2c28&#34;,
        &#34;DB&#34;: 1131533037,
        &#34;ZB&#34;: 1,
        &#34;MRDB&#34;: [
            
        ],
        &#34;clickPic&#34;: &#34;&#34;,
        &#34;notice&#34;: &#34;&#34;
    })
    res = make_response(d)
    res.status_code = 200
    return res
    
    

if __name__ == &#39;__main__&#39;:
    app.run(host=&#39;0.0.0.0&#39;, port=8818, debug=False)
```

为了后面方便，我这里直接选用注入`frida gadget`的方案了，但又懒得写劫持注入，所以写了个loader.exe，`CreateProcess`启动外挂主程序后立刻把`gadget.dll`注入进去

hook.js
```javascript
var url_addr = ptr(&#34;0x0057B54E&#34;)
var url = &#34;http://127.0.0.1:8818/pc/SSSSSPRO.json&#34;

Memory.protect(url_addr, url.length, &#34;rw&#34;);
Memory.writeUtf8String(url_addr, url);
```

gadget.config
```json
{
  &#34;interaction&#34;: {
    &#34;type&#34;: &#34;script&#34;,
    &#34;path&#34;: &#34;hook.js&#34;
  }
}
```

现在双击`loader.exe`启动，就不会再弹那个错误了，剩下的卡密验证部分，当然可以选择逆向找到验证点修改跳转，但那还是太吃操作了，有没有更简单的方法呢？有的兄弟有的

先定位到接口url

![](/images/某端游外挂网络验证的分析与破解/image-5.png)

然后用密探扫一下子域名
![](/images/某端游外挂网络验证的分析与破解/image-6.png)

`https://doc.*.com/`就是目标使用的网络验证的接口文档，里面还给了sign的计算方式和加解密算法，加入文档的QQ群也可以获取到其他语言的SDK，再结合抓包得到的数据其实就可以自己写一个server把他对接过来了
![](/images/某端游外挂网络验证的分析与破解/image-7.png)

但实际写的时候不知道哪里出了问题，一直报数据异常，但又懒的去调试了，所以这里又去换了条路。

`https://web.*.com/`这个就是其网络验证后台登录地址，他是允许任何人去注册的，这不就省去我自己写server的麻烦了
![](/images/某端游外挂网络验证的分析与破解/image-8.png)

注册之后自己新建一个软件，然后生成配置，加密算法默认rc4，
![](/images/某端游外挂网络验证的分析与破解/image-9.png)

然后修改hook.js替换对应配置值就行了
```javascript
var url_addr = ptr(&#34;0x0057B54E&#34;)
var url = &#34;http://127.0.0.1:8818/pc/SSSSSPRO.json&#34;

var app_key_addr = ptr(&#34;0x0057B6FA&#34;)
var app_key = &#34;*&#34;

var rc4_key_addr = ptr(&#34;0x0057B73C&#34;)
// rc4_key = rc4key&#43;客户端签名
var rc4_key = &#34;*123[data]456[key]789&#34;

var key_addr = ptr(&#34;0x0057B714&#34;)
var key = &#34;*&#34;


Memory.protect(url_addr, url.length, &#34;rw&#34;);
Memory.writeUtf8String(url_addr, url);

Memory.protect(app_key_addr, app_key.length, &#34;rw&#34;);
Memory.writeUtf8String(app_key_addr, app_key);

Memory.protect(rc4_key_addr, rc4_key.length, &#34;rw&#34;);
Memory.writeUtf8String(rc4_key_addr, rc4_key);

Memory.protect(key_addr, key.length, &#34;rw&#34;);
Memory.writeUtf8String(key_addr, key);
```

然后给自己生成几个永久卡玩玩
![](/images/某端游外挂网络验证的分析与破解/image-10.png)

至此就破解完毕了

![](/images/某端游外挂网络验证的分析与破解/image-11.png)

## 总结
整个流程下来难度其实不大，没有太多逆向的地方，主要是思维的发散了。还有那两个猜测的点，想不到的话就只能硬干了，如果能把server模拟出来当然是最好的。

---

> Author: yuro  
> URL: /posts/833ca24/  

