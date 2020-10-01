package main

import (
	// 自定义包,前缀路径是module名,即go mod init指定的名字
	// "fmt"

	// "fmt"
	"a.com/goh3c/eapAuth"
	"flag"
	"github.com/google/gopacket/pcap"
	"log"
	// "a.com/goh3c/eapAuth/util"
	// "fmt"
)

var debug = flag.Bool("debug", false, "a bool")

type user struct {
	username string
	password string
	device   int
}

func (u user) GetUser() (string, string, bool) {
	ok := true
	if u.username == "" {
		ok = false
	}
	return u.username, u.password, ok
}

func (u user) GetDevice() (*pcap.Interface, bool) {
	if u.device == -1 {
		return nil, false
	}

	ifs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	return &ifs[u.device], true
}

func main() {
	flag.Parse()
	eapAuth.SetDebug(*debug)

	user := user{"", "", -1}
	c := eapAuth.NewClient(user)
	c.Start()
	c.Close()
}
