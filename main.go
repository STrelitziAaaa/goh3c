package main

import (
	// 自定义包,前缀路径是module名,即go mod init指定的名字
	// "fmt"

	// "fmt"
	"encoding/json"
	"flag"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"a.com/goh3c/eapAuth"
	"a.com/goh3c/eapAuth/util"
	"github.com/google/gopacket/pcap"

	// "a.com/goh3c/eapAuth/util"
	"fmt"
)

var isDebug = flag.Bool("debug", false, "a bool")
var isDaemon = flag.Bool("daemon", false, "daemon")

type user struct {
	Username     string
	Password     string
	Device       *pcap.Interface
	HardwareAddr []byte
}

func NewUser(conf string) user {
	// first check .conf
	if _, err := os.Stat(conf); err != nil {
		name, psw := utilInputUser()
		device := utilInputDevice(true)
		addr := utilGetAddr(device)
		// addr := utilInputAddr()
		u := user{name, psw, device, addr}
		handleErr(u.MarshallWrite(conf))
		return u
	}
	// read from .conf
	// openfile 的perm指的是创建文件时给予文件的权限
	f, err := os.OpenFile(conf, os.O_RDONLY, 0)
	handleErr(err)
	b, err := ioutil.ReadAll(f)
	handleErr(err)
	user := user{}
	json.Unmarshal(b, &user)
	return user
}

func (u user) GetUser() (string, string) {
	return u.Username, u.Password
}

func (u user) GetDevice() *pcap.Interface {
	return u.Device
}

func (u user) GetHardwareAddr() eapAuth.HardwareAddr {
	return eapAuth.HardwareAddr(u.HardwareAddr)
}

func (u user) MarshallWrite(file string) error {
	b, err := json.Marshal(u)
	if err != nil {
		return err
	}
	fd, err := syscall.Open(file, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		return err
	}
	for len(b) != 0 {
		n, err := syscall.Write(fd, b)

		if err == syscall.EINTR {
			continue
		}

		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func handleErr(err error) {
	if err != nil {
		util.LogFatalln(err)
	}
}

func utilInputDevice(show bool) *pcap.Interface {
	// winShowDeviceByNet()
	ifs, err := pcap.FindAllDevs()
	handleErr(err)
	if show {
		for i, if_ := range ifs {
			fmt.Printf("Index:%d , Name:%s , Desciption:%s\n", i, if_.Name, if_.Description)
		}
	}
	fmt.Println("请输入网卡序号(从0开始):")
	var ifi int
	fmt.Scanf("%d\n", &ifi)
	fmt.Printf("你选择了 %s\n", ifs[ifi].Description)
	return &ifs[ifi]
}

func utilGetAddr(ifi *pcap.Interface) []byte {
	for _, v := range ifi.Addresses {
		ip := v.IP.String()
		fmt.Println(ip)
		hAddr := findHardwareAddrByip(ip)
		if hAddr != nil {
			fmt.Println(net.HardwareAddr(hAddr).String())
			return hAddr
		}
	}
	// 如果都找不到,可以试试: getmac这个cmd命令,cmd = "getmac | grep ifi.Name > ./tmp" ,再读取文件
	return nil
}

func findHardwareAddrByip(ip string) []byte {
	ifs, err := net.Interfaces()
	handleErr(err)
	for _, v := range ifs {
		addrs, err := v.Addrs()
		handleErr(err)
		for _, vv := range addrs {
			if strings.Split(vv.String(), "/")[0] == ip {
				return v.HardwareAddr
			}
		}
	}
	return nil
}

func utilInputUser() (usr string, psw string) {
	var err error
	fmt.Println("请输入用户名:")
	_, err = fmt.Scanf("%s\n", &usr)
	handleErr(err)
	fmt.Println("请输入密码:")
	_, err = fmt.Scanf("%s\n", &psw)
	handleErr(err)
	return
}

func utilInputAddr() []byte {
	fmt.Println("请输入网卡地址:(形如C1-B2-F3-84-B5-C6)")
	var rawAddr string
	fmt.Scanf("%s\n", &rawAddr)
	hardwareAddr := utilProcessRawHardwareAddr(rawAddr)
	return hardwareAddr
}

func utilProcessRawHardwareAddr(addr string) (addr_ret eapAuth.HardwareAddr) {
	addr = strings.ReplaceAll(addr, "-", "")
	// fmt.Println(addr)
	for i := 0; i < 12; i += 2 {
		uint8_, _ := strconv.ParseUint(addr[i:i+2], 16, 8)
		// fmt.Printf("->%s %d\n", addr[i:i+2], uint8_)
		addr_ret = append(addr_ret, byte(uint8_))
	}
	// fmt.Printf("0x%x\n", []byte(addr_ret))
	return
}

func main() {
	flag.Parse()
	eapAuth.SetDaemon(*isDaemon)
	eapAuth.SetDebug(*isDebug)
	user := NewUser("./user.conf")
	c := eapAuth.NewClient(user)
	if *isDaemon {
		fmt.Println("in daemon: i will serve 4ever")
		handleErr(syscall.FlushFileBuffers(syscall.Stdout))
		c.StartAuth()
		return
	}
	if ok := c.StartAuth(); ok {
		f, err := os.OpenFile("log", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
		handleErr(err)
		// change to daemon
		cmd := exec.Cmd{
			Path:   os.Args[0],
			Args:   os.Args,
			Env:    os.Environ(),
			Stdout: f,
			Stderr: f,
		}
		cmd.Args = append(cmd.Args, "-daemon")
		cmd.Start()
	} else {
		fmt.Println("Auth Failed")
	}
	c.Close()
}
