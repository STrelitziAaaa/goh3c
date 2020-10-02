# GoH3c for Win
基于Golang编写的h3c客户端(for windows),用于链路层EAPoL认证  
测试网络环境: sysu   

## Require
- 基于gopacket提供的链路层数据帧控制,gopacket是pcap的高级wrapper
- windows下需安装winpcap/npcap
  - 如果电脑有抓包软件如wireshark,则已经安装pcap
- linux下需安装libpcap
  - linux也可以通过设置raw_packet的socket访问链路层

## Usage
- `./goh3c.exe`
- 输入用户名,密码,网卡序号,网卡地址
  - 注意一定要选择`以太网卡`,此后用户数据保存在当前目录的`user.conf`中
- win: 在cmd/powershell中输入`ipconfig /all `查看以太网卡的MAC地址
- linux: bash中输入`ifconfig`

## Function
- 基本功能已实现
  - 即: 与交换机握手认证
- windows下网卡会自动dhcp,在交换机通过认证后即可获取到ip
  - 但是注意需要等待windows自动dhcp,平均时间是10s-1min左右

## TODO
- [ ] 第一个request包捕获不到,必须等第二个重发的request包
  - 更正: 不是捕获不到,是wireshark捕获到很久以后gopacket才捕获到
- [x] 加入.conf文件,保存user信息
- [ ] daemon模式,进入后台,dup文件描述符
- [ ] 获取网卡MAC,现在必须手动输入

## Refactor
- 代码写得很乱,权作为练习链路层收发数据帧的练习,有时间再重构