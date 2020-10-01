package eapAuth

import (
	// "bytes"
	// "bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	// "strconv"
	// "strings"

	// "io"
	// "log"

	// "unsafe"

	"a.com/goh3c/eapAuth/util"

	// "log"
	"github.com/google/gopacket"
	// "github.com/google/gopacket/layers"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket/pcap"
)

var (
	paeMulticastAddr1 = []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}
	// []byte("\x01\x80\xc2\x00\x00\x03") 这种"\x01"的字符串存储方式,表示字符串按二进制存储
	// paeMulticastAddr2 int64 = 0x0180c2000003             // 48 bit
)

func TestAddr() {
	fmt.Println(paeMulticastAddr1)
	// buffer := bytes.NewBuffer([]byte{})
	// binary.Write(buffer, binary.BigEndian, paeMulticastAddr2)
	// fmt.Println(buffer.Bytes()[2:])
}

func TestPackageImport() {
	fmt.Println("hello world")
}

func handleErr(err error) {
	if err != nil {
		util.LogFatalln(err)
	}
}

// EAPoL : eap over lan
// EAPoR : EAP over RADIUS (radius指收费系统)
// 通信拓扑: user -> terminal_device -> auth_server
// 1. 交换机设备中继转发,则user需要使用EAPoR,即user直接与authServer通信
// 2. eap报文在交换机设备处终结

func printDivider() {
	fmt.Println("====================================")
}

const hexDigit = "0123456789abcdef"

// A HardwareAddr represents a physical hardware address.
type HardwareAddr []byte

func (a HardwareAddr) String() string {
	if len(a) == 0 {
		return ""
	}
	buf := make([]byte, 0, len(a)*3-1)
	for i, b := range a {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexDigit[b>>4])
		buf = append(buf, hexDigit[b&0xF])
	}
	return string(buf)
}

type Client struct {
	fd                 int // deprecated
	device             *pcap.Interface
	userName           string
	passWord           string
	MyHardwareAddr     HardwareAddr
	RemoteHardwareAddr HardwareAddr

	ethHdr []byte // 备用

	Handle *pcap.Handle
}

func (c *Client) sendAll(data ...[]byte) {
	// fmt.Println(REMOTE_ADDR)
	// err := util.WriteAll(c.fd, &REMOTE_ADDR, data...)
	// if err != nil {
	// 	err = fmt.Errorf("fd:%d  "+err.Error(), c.fd)
	// 	handleErr(err)
	// }
	buf := bytes.NewBuffer(nil)
	for _, v := range data {
		buf.Write(v)
	}
	handleErr(c.Handle.WritePacketData(buf.Bytes()))
}

// func ShowEthInterface() []net.Interface {
// 	ifs, err := net.Interfaces()
// 	handleErr(err)

// 	// show interfaces
// 	printDivider()
// 	for i, v := range ifs {
// 		fmt.Println(i, v.Name, v.HardwareAddr, "#", v.Flags)
// 	}
// 	printDivider()

// 	return ifs
// }

// var REMOTE_ADDR syscall.SockaddrLinklayer

// 必须加,否则会不对
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
	// return i
}

// return a sockfd that only recv 802.1x frame
func newCustomeSocket(device *net.Interface) (fd int) {
	// WSL 不支持 AF_PACKET
	// WSL2 支持,本程序在wsl2中开发及测试
	// ! 注意需要sudo运行
	// fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(uint16(syscall.ETH_P_PAE))))
	// handleErr(err)
	// mac_s := strings.Split(device.HardwareAddr.String(), ":")
	// var mac [8]uint8
	// for i, v := range mac_s {
	// 	t, err := strconv.ParseInt(v, 16, 16) // 无法parse uint
	// 	if err != nil {
	// 		util.LogFatalln(err)
	// 	}
	// 	mac[i] = uint8(t)
	// }
	// mac := [8]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}
	// REMOTE_ADDR = syscall.SockaddrLinklayer{
	// 	Protocol: htons(syscall.ETH_P_PAE),
	// 	Ifindex:  device.Index,
	// 	Addr:     mac,
	// 	Halen:    6,
	// }
	// localAddr := syscall.SockaddrLinklayer{
	// 	Protocol: syscall.ETH_P_PAE,
	// 	Ifindex:  device.Index,
	// }
	// handleErr(err)
	// handleErr(syscall.Bind(fd, &localAddr))
	// handleErr(syscall.BindToDevice(fd, device.Name))
	// handleErr(syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1))
	return
}

// uplayerType will be syscall.ETH_P_PAE
func getEtherHdr(dst, src []byte, uplayerType uint16) (hdr []byte) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uplayerType)
	hdr = make([]byte, 14)
	util.CopyAll(hdr, dst[:6], src[:6], buf[:2])
	return
}

func getEtherPayload(type_ uint8) (payload []byte) {
	payload = make([]byte, 2)
	payload[0] = byte(EAPOL_VERSION)
	payload[1] = byte(type_)
	return
}

type eapConfig interface {
	GetDevice() (*pcap.Interface, bool)
	GetUser() (string, string, bool)
}

func NewNilClient() *Client {
	return &Client{}
}

func NewClient(config eapConfig) *Client {
	device := (*pcap.Interface)(nil)
	username := ""
	password := ""
	var ok bool

	if config == nil {
		username, password = utilInputUser()
		device = utilInputDevice(true)
	} else {
		if username, password, ok = config.GetUser(); !ok {
			username, password = utilInputUser()
		}
		if device, ok = config.GetDevice(); !ok {
			device = utilInputDevice(true)
		}
	}

	fmt.Printf("你选择了 %s\n", device.Description)

	handle, err := pcap.OpenLive(device.Name, 1564 /*每个数据包读取的最大值*/, false /*是否开启混杂模式*/, 30*time.Second /*读包超时时长*/)
	handleErr(err)

	fd := newCustomeSocket(nil)
	// hardwareAddr, err := HardwareAddr("\x00\x0E\xC6\xD7\x40\x50"), nil
	// \Device\NPF_{2472EB93-D9EB-4E08-8F3A-249B764038F9}
	fmt.Println("请输入网卡地址:(形如C1-B2-F3-84-B5-C6)")
	var rawAddr string
	fmt.Scanf("%s\n", &rawAddr)
	hardwareAddr := utilProcessRawHardwareAddr(rawAddr)
	handleErr(err)
	util.LogInfof("fd:%d , device:%s , MAC:%s , username:%s\n", fd, device.Description, hardwareAddr.String(), username)
	return &Client{fd, device, username, password, hardwareAddr, nil, nil, handle}
}

func (c *Client) Close() {
	defer c.Handle.Close()
}

var TestTargetMac = [6]byte{0xC0, 0xB6, 0xF9, 0x8B, 0xB2, 0xC1}

// EAP over lan start,客户端向设备触发802.1X验证
func (c *Client) eapStart() {
	// 在win上用wireshark抓wsl网卡,可以正常抓到,难道是要padding?
	c.ethHdr = getEtherHdr(paeMulticastAddr1, []byte(c.MyHardwareAddr), uint16(0x888e))
	// ethPayload := getEtherPayload(EAPOL_LOGIN)
	ethPayload := getEAPoL(EAPOL_START, nil)
	util.LogInfof("Ethernet Frame Headr: 0x%x , Payload: 0x%x\n", c.ethHdr, ethPayload)
	c.sendAll(c.ethHdr, ethPayload)
	util.LogInfoln("[EAPoL] Start")
}

var DISCARD_IPV4 bool

func (c *Client) HandleEther(pkt []byte) (payload interface{}, err error) {
	if len(pkt) <= 14 {
		return nil, errors.New("handleEther: Null Payload")
	}
	dst := pkt[:6]
	src := pkt[6:12]
	c.RemoteHardwareAddr = HardwareAddr(src)
	if n := copy(c.ethHdr, src); n != 6 {
		util.LogFatalln("Copy Error")
	}

	uplayerType := binary.BigEndian.Uint16(pkt[12:])
	util.LogInfof("[ETHERNET] dst:0x%x src:0x%x type:0x%x", dst, src, uplayerType)
	// myMac := []byte(c.MyHardwareAddr)
	// if !util.CompareMac(dst, myMac) {
	// 	err = fmt.Errorf("handleEther: Unmatched dst: expected:0x%x , got:0x%x", myMac, dst)
	// 	DISCARD_PACKET = true
	// 	return
	// }
	payload = pkt[14:]
	// if uplayerType != 0x888e {
	// 	DISCARD_PACKET = true
	// 	err = fmt.Errorf("handleEther: Unmatched uplayerType: expected:0x%x , got:0x%x", 0x888e, uplayerType)
	// 	if uplayerType == 0x800 {
	// 		if DISCARD_IPV4 {
	// 			return nil, nil
	// 		}
	// 		DISCARD_IPV4 = true
	// 		err = fmt.Errorf(err.Error() + " 0x800:ipv4")
	// 	}
	// 	return
	// }
	util.LogInfof("[LUCKY] matched Type: 0x%x 802.1X Auth", uplayerType)
	return
}

func (c *Client) HandleEAPoL(pkt []byte) (payload interface{}, err error) {
	// EAPOL Header
	// EAPOL Version, EAPOL Type and Payload Len
	hdr := struct {
		Version uint8
		Type    uint8
		Len     uint16
	}{}
	handleErr(binary.Read(bytes.NewReader(pkt), binary.BigEndian, &hdr))
	util.LogDebugf("HandleEAPoL: version:0x%x type:0x%x len:0x%x\n", hdr.Version, hdr.Type, hdr.Len)

	// hdrLen := unsafe.Sizeof(hdr)
	hdrLen := 4
	payload = pkt[hdrLen : hdrLen+int(hdr.Len)]
	if hdr.Type != EAPOL_EAPPACKET {
		msg := fmt.Sprintf("ERR: Unknown Packet Type: expected:0x%x , get:0x%x", EAPOL_EAPPACKET, hdr.Type)
		err = errors.New(msg)
		return
	}

	if len(payload.([]byte)) == 0 {
		err = errors.New("HandleEAPoL: Null Payload")
	}
	return
}

func (c *Client) HandleEAP(pkt []byte) (payload interface{}, err error) {
	hdr := struct {
		Code uint8  // req/resp/success/fail
		Id   uint8  // id is just a kind of seq_num ,we dont need to incre it,just repeat it when response,the server will incre it
		Len  uint16 // include hdr, so typicaly, this len will equal to len in EAPoL hdr
	}{}
	handleErr(binary.Read(bytes.NewReader(pkt), binary.BigEndian, &hdr))
	payload = pkt[4:hdr.Len]
	switch hdr.Code {
	case EAP_CODE_SUCCESS:
		util.LogInfoln("[SUCCESS] Auth Passed")
		util.LogInfoln("[Waiting] Dhcp Discover")
		// Now we need dhcp
		// for win , it will send dhcp automatically
		// Now we need change process to daemon
	case EAP_CODE_FAILURE:
		util.LogInfoln("[FAIL] EAP FAILURE")
		syscall.Exit(-1)
	case EAP_CODE_REQUEST:
		util.LogInfoln("[RECV] EAP_CODE_REQUEST")
		reqType := int(payload.([]byte)[0])
		payload = payload.([]byte)[1:]
		switch reqType {
		case EAP_TYPE_ID:
			// send username
			// used in the auth and heartbeat

			// first change ether header
			util.LogInfoln("---- EAP_TYPE_ID")
			pld := bytes.NewBuffer(nil)
			handleErr(util.BufferWriteAll(pld, []byte(VERSION_INFO), []byte(c.userName)))
			c.sendAll(c.ethHdr, getEAPoL(EAPOL_EAPPACKET, getEAP(EAP_CODE_RESPONSE, hdr.Id, EAP_TYPE_ID, pld.Bytes())))
			util.LogInfoln("---- SEND OK")

		// this is not used in windows
		// case EAP_TYPE_PSW:
		// 	pld := bytes.NewBuffer(nil)
		// 	// binary.Write(pld, binary.BigEndian, uint8(len(c.passWord)))
		// 	// binary.Write(pld, binary.BigEndian, c.passWord)
		// 	// binary.Write(pld, binary.BigEndian, c.userName)
		// 	util.BufferWriteAll(pld, uint8(len(c.passWord)), c.passWord, c.userName)
		// 	c.sendAll(c.ethHdr, getEAPoL(EAPOL_EAPPACKET, getEAP(EAP_CODE_RESPONSE, hdr.Id, EAP_TYPE_PSW, pld.Bytes())))
		// 	break

		case EAP_TYPE_MD5:
			util.LogInfoln("---- EAP_TYPE_MD5")
			len_ := payload.([]byte)[0] // len=16,后面有16字节的md5_data,作为密钥加密
			key := payload.([]byte)[1 : len_+1]
			var chap []byte
			psw := [16]uint8{}
			copy(psw[:], []uint8(c.passWord)) // 目的是固定长度,尾部用0填充
			for i := range psw {
				chap = append(chap, psw[i]^key[i]) // 按位异或
			}

			pld := bytes.NewBuffer(nil)
			// binary.Write(pld, binary.BigEndian, uint8(len(chap))) // eap.md5.value_size = 16 (fixed)
			// binary.Write(pld, binary.BigEndian, chap)             // eap.md5.value
			// binary.Write(pld, binary.BigEndian, []byte(c.userName))       // eap.md5.extra_data
			err := util.BufferWriteAll(pld, uint8(len(chap)), chap, []byte(c.userName))
			handleErr(err)
			c.sendAll(c.ethHdr, getEAPoL(EAPOL_EAPPACKET, getEAP(EAP_CODE_RESPONSE, hdr.Id, EAP_TYPE_MD5, pld.Bytes())))
			util.LogInfoln("---- SEND OK")
		}
	case EAP_CODE_RESPONSE:
		util.LogInfoln("---- EAP_CODE_RESPONSE")
		// we cant recv response, we just recv request and send response
		util.LogInfoln("[Warning]: Receive Response EAP")
	case EAP_CODE_UNKNOWN:
		util.LogInfoln("---- EAP_CODE_UNKNOWN")
		// do nothin
		util.LogWarnf("Received Unknown EAP")
	}

	return
}

func getEAPoL(t uint8, payload []byte) []byte {
	buf := bytes.NewBuffer(nil)
	err := util.BufferWriteAll(buf, EAPOL_VERSION, t, uint16(len(payload)), payload)
	handleErr(err)
	return buf.Bytes()
}

// code:response/request   id:seq_num  t:type:EAP_TYPE_ID
func getEAP(code uint8, id uint8, t uint8, payload []byte) []byte {
	buf := bytes.NewBuffer(nil)
	err := util.BufferWriteAll(buf, code, id, uint16(len(payload)+5), t, payload)
	handleErr(err)
	fmt.Printf("getEAP header: 0x%x\n", buf.Bytes()[:5])
	fmt.Printf("getEAP payload: 0x%x\n", buf.Bytes()[5:])
	return buf.Bytes()
}

func (c *Client) Start() {
	p := NewPktParser()
	p.AddHandleFunc(c.HandleEther).AddHandleFunc(c.HandleEAPoL).AddHandleFunc(c.HandleEAP)
	var filter string = "ether dst " + c.MyHardwareAddr.String() + " && ether proto 0x888e"
	handleErr(c.Handle.SetBPFFilter(filter))

	pktSrc := gopacket.NewPacketSource(c.Handle, c.Handle.LinkType())
	c.eapStart()
	for {
		util.LogInfoln("[WAIT] ready to recv")
		for v := range pktSrc.Packets() {
			p.Handle(v.Data())
		}
	}
}

// func (c *Client) Test() {
// 	c.handlePayload([]byte{0x12, 0x34, 0x56, 0x78})
// }

// test ok
func TestRespIdentity(netid string) []byte {
	return append([]byte(VERSION_INFO), []byte(netid)...)
}

// test ok
func TestRespMd5(psw string) []byte {
	key := []uint8("\x74\x35\x4c\x54\x67\x4a\x35\x74\x06\x08\x57\x40\x74\xca\x3b\x23")
	var chap []uint8
	psw_ := [16]uint8{}
	copy(psw_[:], []byte(psw)) // 目的是固定长度,尾部用0填充
	for i := range psw_ {
		chap = append(chap, (psw_[i])^key[i]) // 按位异或
	}
	return chap
}

// func TestWriteFd(c *Client) {
// 	n, err := syscall.Write(c.fd, []byte{0x12, 0x43})
// 	if err != nil {
// 		util.LogDebugf("n:%d, errInfo:%s", n, err.Error())
// 		syscall.Exit(-1)
// 	}
// }

// func TestHtons() {
// 	fmt.Printf("htons uint16 %x\n", int(htons(uint16(syscall.ETH_P_PAE))))
// 	fmt.Printf("raw uint16 %x\n", uint16(syscall.ETH_P_PAE))
// 	fmt.Printf("raw %x\n", (syscall.ETH_P_PAE))
// 	fmt.Printf("htons %x\n", int(htons((syscall.ETH_P_PAE))))
// }

func SetDebug(debug bool) {
	Debug = debug
	util.Debug = debug
	util.LogInfof("[DEBUG] Set OK : %v", debug)
}
