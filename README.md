# BypassLoad
**通过远程加载AES + XOR异或加密shellcode的免杀加载器，无过多技术细节。**

| shellcode | 360杀毒    | 火绒 | Defender | 腾讯电脑管家 | VT |
| --------- | -----------| --- | -------  | ------------- |  --  |
| Meterpreter  | √       |   √ |    √      | √           |  13/69  |
| Cobalt Strike| √   |   √ |    √      | √           |   13/69 |

推荐Meterpreter生成shellcode，Cobalt Strike在尝试远程加载的shellcode时可能被360拦截

可自行`加壳`或`修改`程序尝试

**releases程序可能会被杀软hash标记，保证免杀效果请自行编译**

**如果你不知道怎么做，不推荐使用该程序**

## 声明：
1. 文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担！
2. 水平不高，纯萌新刚刚开始研究免杀，面向Github编程借鉴了很多大佬的代码。
3. 目前测试通过360、火绒、腾讯电脑管家、Defender。其他自行测试

## 使用指南

1. 编译BypassLoad和Encrypt
2. 将shellcode写入shellcode.txt然后运行Encrypt.exe进行加密编码（注意需要手动去除换行）
3. 将Encrypt.exe加密编码后的数据上传至服务器
4. 将远程访问链接写入webpath.txt
5. 运行BypassLoad.exe

注意：存在一段if判断内存是否小于4G，进行简单的反沙箱判断。

## 更新
2024年03月11日
  1. 更新2.0 使用.Net内置函数替换原有使用的Windows函数
  
2024年01月29日
  1. 效果优化，更换加载方式
  2. 不再提供releases，请自行编译

2024年01月26日
  1. 效果优化
  2. 请不要将程序放入沙箱，以延长免杀时间

2024年01月24日
  1. 效果优化，现已免杀Defender
  2. 现在基于.NET Framework4.7.2框架
  3. 移除了一段无效代码

<p align="center"">
  <img src="https://github.com/Mangofang/BypassLoad/blob/main/image/%7BCFE2B5D0-BF30-4063-9ADC-6426314F6132%7D.png">
</p>

<p align="center">
  <img src="https://github.com/Mangofang/BypassLoad/blob/main/image/%7BAB76D9F0-6FF6-424c-BA8C-5AC09209FF61%7D.png">
</p>
