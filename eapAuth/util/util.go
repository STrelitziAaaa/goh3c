package util

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"runtime"
	"strings"
	// "syscall"
)

var Debug bool
var Info bool

func init() {
	Debug = false
	Info = true
}

func BufferAll(data ...[]byte) []byte {
	buf := bytes.NewBuffer(nil)
	for _, v := range data {
		buf.Write(v)
	}
	return buf.Bytes()
}

func CopyAll(dst []byte, src ...[]byte) int {
	n_written := 0
	for _, v := range src {
		for len(v) > 0 {
			n := copy(dst[n_written:], v)
			v = v[n:]
			n_written += n
		}
	}
	return n_written
}

// default use bigendian
func BufferWriteAll(w io.Writer, data ...interface{}) error {
	for _, v := range data {
		switch t := v.(type) {
		case string:
			v = []byte(t)
		}

		err := binary.Write(w, binary.BigEndian, v)
		if err != nil {
			return err
		}
	}
	return nil
}

func LogInfoln(info interface{}) {
	if Info {
		log.Println("[INFO]", info)
	}
}

func LogInfof(fmt string, v ...interface{}) {
	if Info {
		log.Printf("[INFO] "+fmt, v...)
	}
}

func LogDebugln(info interface{}) {
	if !Debug {
		return
	}
	getLasElem := func(s []string) string {
		return s[len(s)-1]
	}

	if pc, file, line, ok := runtime.Caller(1); ok {
		funcName := runtime.FuncForPC(pc).Name()
		log.Printf("[DEBUG] %s:%d@%s() ---> %v\n", getLasElem(strings.Split(file, "/")), line, getLasElem(strings.Split(funcName, "/")), info)
	}
}

func LogDebugf(fmt_ string, v ...interface{}) {
	if !Debug {
		return
	}
	getLasElem := func(s []string) string {
		return s[len(s)-1]
	}
	if pc, file, line, ok := runtime.Caller(1); ok {
		funcName := runtime.FuncForPC(pc).Name()
		prefix := fmt.Sprintf("[DEBUG] %s:%d@%s() ---> ", getLasElem(strings.Split(file, "/")), line, getLasElem(strings.Split(funcName, "/")))
		log.Printf(prefix+fmt_, v...)
	}
}

// only used in handleErr
func LogFatalln(info interface{}) {
	getLasElem := func(s []string) string {
		return s[len(s)-1]
	}
	if pc, file, line, ok := runtime.Caller(2); ok {
		funcName := runtime.FuncForPC(pc).Name()
		log.Fatalf("[ERROR] %s:%d@%s() ---> %v\n", getLasElem(strings.Split(file, "/")), line, getLasElem(strings.Split(funcName, "/")), info)
	}
}

func LogWarnf(fmt string, v ...interface{}) {
	log.Printf(fmt, v...)
}

func CompareMac(a []byte, b []byte) bool {
	// fmt.Printf("compare: 0x%x   0x%x", a, b)
	for i := 0; i < 6; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	// fmt.Println("pass")
	return true
}
