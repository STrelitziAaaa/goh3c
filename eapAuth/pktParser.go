package eapAuth

import (
	"log"
	"syscall"

)

// 必须返回payload,而不是hdrLen,因为可能需要对包截断,当然由于是基于UDP协议的,这里不需要截断
type handleFunc func(pkt []byte) (payload interface{}, err error)

type pktParser struct {
	handleFuncs []handleFunc
}

func NewPktParser() *pktParser {
	return &pktParser{nil}
}

// func (p *pktParser) SetDefaultHandler() *pktParser {
// 	p.handleFuncs = append(p.handleFuncs, handleEAPoL)
// 	return p
// }

func (p *pktParser) AddHandleFunc(f ...handleFunc) *pktParser {
	p.handleFuncs = append(p.handleFuncs, f...)
	return p
}

func (p *pktParser) DiscardIfErr() *pktParser {
	p.handleFuncs = append(p.handleFuncs, nil)
	return p
}

var DISCARD_PACKET bool

func (p *pktParser) Handle(pkt []byte) interface{} {
	DISCARD_PACKET = false
	payload := interface{}(pkt)
	var err error
	for _, f := range p.handleFuncs {
		payload, err = f(payload.([]byte))
		if err != nil {
			log.Println(err)
			if DISCARD_PACKET {
				return nil
			}
			syscall.Exit(-1)
		}
		if payload == nil {
			return nil
		}
	}
	return payload
}
