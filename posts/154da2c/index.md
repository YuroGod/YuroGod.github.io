# NepCTF2024

NepCTF2024 wp
&lt;!--more--&gt;
# 前言
这几天太忙了，又是练车，又是一堆比赛的，头疼，这次比赛有点遗憾，NepWRT那题脑子糊涂了把flag拼错了痛失900分，没拿到键帽，可惜

因为还有其他比赛同时在打，所以就只做了几个简单题，这里记录一下wp
## Misc
### NepMagic -- CheckIn
直接手玩玩通关就能拿到flag，不过我还是去逆了一下

一个RPGMarker XP做的游戏，github上找个`RGSS Extractor`解包`Game.rgssad`可以拿到游戏资源

导入到自己的工程里，可以直接分析游戏逻辑了，在NPC的Event里可以查看对话，按照游戏正常逻辑拼一下对话里的flag碎片即可

![](/images/NepCTF2024/image1.png)

`NepCTF{50c505f4-2700-11ef-ad49-00155d5e2505}`

### Nemophila
题目给了一个python脚本，里面有很多层约束，手撕一下，最终可以得到`secret_is{Frieren&amp;C_SunR15e&amp;Himme1_eterna1_10ve}`

解压压缩包，有一个png但是看起来不太对，010分析一下，可以看到PNG原本00字节地方跟刚刚得到的key有一部分是一样的，大概率就是异或了

![](/images/NepCTF2024/image2.png)

cyberchef异或解密一下图片，还修改了图片高度，丢到随波逐流里梭一下即可看到下面出现了flag
`NepCTF{1f_I_were_the_on1y_one_i_would_N0T_be_able_to_see_this_Sunrise}`

### 3DNep
010查看文件头，是个glTF模型文件，找个在线网站查看一下模型，翻到最下面可以看到一个像二维码的东西，实际上是汉信码，在线工具解码即可

`NepCTF{6e766b59-23d1-395c26d708a4}`

### NepCamera
分析流量，发现每个包里都能看见jpg的文件头，猜是分组传输图片数据吗，

![](/images/NepCTF2024/image3.png)

搓了一个脚本写出数据
```python
import pyshark

capture = pyshark.FileCapture(r&#39;misc\NepCamera.pcapng&#39;)

data = bytes()
packet_count = 0

for idx, packet in enumerate(capture):
    
    for layer in packet.layers:
        
        if len(layer.field_names) == 4:
            data &#43;= bytes.fromhex(&#34;&#34;.join(layer.iso_data.split(&#39;:&#39;)))[12:]
            
    packet_count &#43;= 1
    
    if packet_count == 3:
        with open(f&#34;misc\\output\\{idx // 3}.jpg&#34;, &#34;wb&#43;&#34;) as fp:
            fp.write(data)
        data = bytes()
        packet_count = 0
```
实际上代码写的很有问题，图片拼的不对，但是其实这里已经能看到flag了，我就没有再修改了

![](/images/NepCTF2024/image4.png)

`flag{Th3_c4mer4_takes_c1ear_pictures}`

## Reverse
### 0ezAndroid
比赛刚开始的时候给了一个hint，说跟pdf的一个cve有关，于是就把目光看到了pdf，然后就看到了一堆js代码
```javascript
var cipher = [0x69, 0x7c, 0x70, 0x75, 0x68, 0x71, 0x7b, 0x73, 0x79, 0x76, 0x7c, 0x7f, 0x75, 0x72, 0x78, 0x70, 0x7a, 0x45, 0x4f, 0xe, 0x4d, 0x41, 0x4b, 0x43, 0x42, 0x46, 0x4c, 0x44, 0x4e, 0x42, 0xc, 0x40, 0x4a, 0x55, 0x5f, 0x13, 0x4e];
flag = &#34;&#34;;
for (i = 0x0; i &lt; cipher.length; i&#43;&#43;) {
  flag &#43;= String.fromCharCode(cipher[i] ^ i &#43; 0xf);
}
console.log(flag);
```
跑一下得到的就是正确的flag，说实话我当时以为这个是fake flag

`flag{enenneenneneen,neneenenen!neen!}`

### Super Neuro : Escape from Flame!
一个unity il2cpp游戏，原本想走正常的il2cpp逆向流程的，但是看到题目要求只要得到1024分就行，就换了个方向，先去用CPP2IL dump了一下

搜一下NepCTF，然后在`FollowNeuro::FixedUpdate`看到了判断，尝试了直接改跳转，但是输出的空flag
```c#
System.Void FixedUpdate() {
	UnityEngine.GameObject neuro = this.Neuro
	UnityEngine.Transform transform = neuro.transform
	UnityEngine.Vector3 position = .position
	System.Single single = position.y
	if (single &gt; this.MostHeight)
	    this.MostHeight = single
	endif
       
	this.Save()
	System.Single mostHeight = this.MostHeight
	ulong local9 = 0
	if (mostHeight &lt;= local9)
           goto INSN_18055FDA1
       endif
	TMPro.TextMeshProUGUI _height = this._height
	System.Single mostHeight2 = this.MostHeight
	System.String string = System.String.Format(&#34;{0:F1}/{1:F1}&#34;, position, position) //(String format, Object arg0, Object arg1)
	_height.text = string
	INSN_18055FDA1:
	if (single &lt;= 1024)
           goto INSN_18055FF02
       endif
	ulong local21 = 0
	local21 &#43;= 1
	System.Byte[] local22 = new System.Byte[local21]
	[instruction error - managed method being called is null]
	System.Runtime.InteropServices.Marshal.Copy()
	ulong local26 = 0
	System.Text.Encoding uTF8 = System.Text.Encoding.UTF8
	System.String string2 = uTF8.GetString(local22) //(Byte[] bytes)
	TMPro.TextMeshProUGUI _finish = this._finish
	System.String string3 = System.String.Concat(&#34;NepCTF{&#34;, string2, &#34;}&#34;) //(String str0, String str1, String str2)
	_finish.text = string3
	INSN_18055FF02:
	Neuro neuroInstance = this.NeuroInstance
	UnityEngine.Rigidbody2D rigidBody = neuroInstance.rigidBody
	UnityEngine.Vector2 velocity = rigidBody.velocity
	UnityEngine.GameObject neuro2 = this.Neuro
	UnityEngine.Transform transform2 = neuro2.transform
	UnityEngine.Vector3 position2 = .position
	System.Single single2 = this.LastPosition.y
	System.Single single3 = position2.z
	mostHeight2 = single
	TMPro.TextMeshProUGUI _velocity = this._velocity
	System.String string4 = System.String.Format(&#34;H:{0}
       V:{1}&#34;, position2, position2) //(String format, Object arg0, Object arg1)
	_velocity.text = string4
	this.LastPosition.z = single3
	return
	throw new System.NullReferenceException()
}
```

最后懒得逆了，直接CE启动，找到`FollowNeuro`的instance

然后将`FollowNeuro-&gt;NeuroInstance-&gt;IsJumping`的值锁0，就实现了连跳，再把跳跃高度锁的高一点，就可以原地左脚踩右脚快速升天了

## Hardware
### 火眼金睛
binwalk跑出来一堆文件，翻一下找到带符号表的那个，strings一下，hint说是有一个奇怪的函数在符号表里面，猜测有没有可能是base64之类的

于是搜了一下`=`，结果还真的搜到了
```txt
JZSXAQ2UIZ5VSMDVL5DTA5C7JMZTG3S
7GFXFGMLHNB2F6MLOL53FQ5ZQOJ
FXGIJBEFPUYM3UE5ZV6RZQL5DHK4
TUNAZXE7I=
```

base32解码得到flag
`NepCTF{Y0u_G0t_K33n_1nS1ght_1n_vXw0rKs!!!_L3t&#39;s_G0_Furth3r}`

---

> Author: yuro  
> URL: /posts/154da2c/  

