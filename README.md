# BiFang BypassAV 小工具

BiFang c# 编写自动化生成loader，实现加密、混淆、bypass沙箱、多种现有进程注入技术，动态编译生成。目的在于学习现有技术，实现易用的shellcode生成器，以及快速整合新技术到项目中。

## 使用说明

根据图形化界面选择生成即可，现支持net framework 4.0版本。

![image-20211108180652624](https://ddysgogogo.oss-cn-beijing.aliyuncs.com/tb/image-20211108180652624.png)



## 现有功能说明

### 不同方式自动上线

根据不同二进制文件；dns，http自动判断上线；http优先级高于DNS。

### 混淆

支持类名，方法，变量混淆；建议根据需求选择，全选可能报毒。

### 反沙箱检测

#### 进程黑名单

存在以下进程认为是虚拟机,直接退出。

```
 "vmsrvc", "tcpview", "wireshark", "visual basic", "fiddler", "vmware", "vbox", "process explorer", "autoit", "vboxtray", "vmtools", "vmrawdsk", "vmusbmouse", "vmvss", "vmscsi", "vmxnet", "vmx_svga", "vmmemctl", "df5serv", "vboxservice", "vmhgfs", "vmtoolsd"
```

#### MAC地址检测

网卡MAC地址包括以下开头，直接退出。

```
"000569","000C29","001C14","005056","080027"
```

#### 磁盘检测

磁盘大小小于50G，判定为虚拟机，直接退出。

#### 启动启动时间检测

开机运行时间低于1h，判定为虚拟机，直接退出。

#### CPU核心数量与语言检测

CPU逻辑个数小于4个或者操作系统语言不是中文，判定为虚拟机，直接退出。

#### 时间加速检测

运行时间存在加速，判定为虚拟机，直接退出。

### bypass技术

1. 进程镂空
2. Dinvoke 调用API
3. 载入第二个NTDLL绕过HOOK
4. 映射注入 
4. syscall

## 后续功能

支撑net4.0以下版本。

## 参考

**注：无原创新技术，均来自各位师傅项目。**

https://github.com/3xpl01tc0d3r/ProcessInjection

https://github.com/Kara-4search/HellgateLoader_CSharp

https://github.com/Kara-4search/NewNtdllBypassInlineHook_CSharp



