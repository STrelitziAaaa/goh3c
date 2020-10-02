package eapAuth

import (
	"fmt"

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
