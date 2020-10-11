# GoH3c for Win
基于Golang编写的h3c客户端(for windows),用于链路层EAPoL认证  
测试网络环境: sysu   

## Require
- 基于gopacket提供的链路层数据帧控制,gopacket是pcap的高级wrapper
- windows下需安装winpcap/npcap
  - 如果电脑有抓包软件如wireshark,则已经安装pcap
- linux下需安装libpcap
  - linux也可以通过设置raw_packet的socket访问链路层
- 这份代码涉及了一些windows的syscall,所以兼容linux需要一些小改动

## Usage
- `./goh3c.exe`
- 输入用户名,密码,网卡序号,网卡地址
  - 注意一定要选择`以太网卡`,此后用户数据保存在当前目录的`user.conf`中
- win: 在cmd/powershell中输入`ipconfig /all `查看以太网卡的MAC地址
- linux: bash中输入`ifconfig`
- 关闭进程goh3c: powershell/bash下: `ps | grep goh3c` `kill [pid]`


## Function
- 基本功能已实现
  - 与交换机交互,认证用户
  - 进程退出占有shell,进入守护模式,日志保存在当前路径的log
- windows下网卡会自动dhcp,在交换机通过认证后即可获取到ip
  - 但是注意需要等待windows自动dhcp,平均时间是10s-1min左右

## TODO
- [x] 抓包时延太大
  - 修复为毫秒级
- [x] 加入.conf文件,保存user信息
- [x] daemon模式,进入后台,dup文件描述符
  - 也许可以通过在func init()里面判断环境变量或flag来先执行函数
- [x] 获取网卡MAC,现在必须手动输入
  - 也许可以尝试通过ipv6去net.interfaces()来获取,v6是不需要认证的

## Refactor
- 代码写得很乱,没有设计低耦合,权作为练习链路层收发数据帧的练习,有时间再重构