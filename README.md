# BypassLoad
**通过远程加载AES + XOR异或加密shellcode的加载器，无过多技术细节。**

| shellcode | 360杀毒    | 火绒 | Defender | 腾讯电脑管家 |
| --------- | -----------| --- | -------  | ----------- | 
| meterpreter  | √       |   √ |          | √           | 
| Cobalt Strike|         |   √ |          | √           |

## 声明：
1. 文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担！
2. 水平不高，纯萌新刚刚开始研究免杀，面向Github编程借鉴了很多大佬的代码。
3. 目前测试通过360、火绒、腾讯电脑管家，暂时无法通过Defender。其他自行测试

## 使用指南

1. 将shellcode写入shellcode.txt然后运行Encrypt.exe进行加密编码
2. 将Encrypt.exe加密编码后的数据上传至服务器
3. 将远程访问链接写入webpath.txt
4. 运行BypassLoad.exe

![IMAGE](/image/logo.png)
