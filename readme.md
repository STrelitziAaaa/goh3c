# GoH3c for Win
基于Golang编写的h3c客户端(for windows),用于链路层EAPoL认证  
测试环境: sysu   

## Require
- windows不提供直接操作链路层的socket,必须使用winpcap或npcap

## Usage
- `./goh3c.exe`
- 输入用户名,密码,网卡序号,网卡地址
  - 注意一定要选择`以太网卡`
- 在cmd/powershell中输入`ipconfig /all `查看以太网卡的MAC地址

## function
- 基本功能已实现
  - 即: 与交换机握手认证
- windows下网卡会自动dhcp,在交换机通过认证后即可获取到ip

## TODO
- 第一个request包捕获不到,必须等第二个重发的request包,可能是刷新频率不够?
- 加入.conf文件,保存user信息
- daemon模式,进入后台,dup文件描述符
- 获取网卡MAC,现在必须手动输入