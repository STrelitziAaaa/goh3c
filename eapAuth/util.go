package eapAuth

import (
	"fmt"
	"strconv"
	"strings"

	// "log"
	"errors"
	"net"

	// "a.com/goh3c/eapAuth/util"
	"github.com/google/gopacket/pcap"
)

func winShowDeviceByPcap() {
	ifs, err := pcap.FindAllDevs()
	handleErr(err)
	for _, if_ := range ifs {
		fmt.Printf("Name:%s , Desciption:%s\n", if_.Name, if_.Description)
	}
}

func winShowDeviceByNet() {
	ifs, err := net.Interfaces()
	handleErr(err)
	for _, if_ := range ifs {
		fmt.Printf("Name:%s \n", if_.Name)
	}
}

// get input to choose interface
func utilInputDevice(show bool) *pcap.Interface {
	// winShowDeviceByNet()
	ifs, err := pcap.FindAllDevs()
	handleErr(err)
	if show {
		for _, if_ := range ifs {
			fmt.Printf("Name:%s , Desciption:%s\n", if_.Name, if_.Description)
		}
	}
	fmt.Println("请输入网卡序号(从0开始):")
	var ifi int
	fmt.Scanf("%d\n", &ifi)

	return &ifs[ifi]
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

func utilFindDeviceIpv4(device pcap.Interface) string {
	for _, addr := range device.Addresses {
		if ipv4 := addr.IP.To4(); ipv4 != nil {
			return ipv4.String()
		}
	}
	panic("device has no IPv4")
}

// 根据网卡的IPv4地址获取MAC地址
// 有此方法是因为gopacket内部未封装获取MAC地址的方法，所以这里通过找到IPv4地址相同的网卡来寻找MAC地址
func utilFindMacAddrByIp(ip string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		panic(interfaces)
	}

	for _, i := range interfaces {
		addrs, err := i.Addrs()
		if err != nil {
			panic(err)
		}

		for _, addr := range addrs {
			if a, ok := addr.(*net.IPNet); ok {
				if ip == a.IP.String() {
					return i.HardwareAddr.String(), nil
				}
			}
		}
	}
	return "", errors.New(fmt.Sprintf("no device has given ip: %s", ip))
}

func utilProcessRawHardwareAddr(addr string) (addr_ret HardwareAddr) {
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
