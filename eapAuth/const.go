package eapAuth

import ()

const (
	EAPOL_VERSION   uint8 = 1
	EAPOL_EAPPACKET uint8 = 0 // 用于认证过程中的type

	EAPOL_START  uint8 = 1 // 用于开始认证的type
	EAPOL_LOGOFF uint8 = 2
)

const (
	EAP_CODE_REQUEST  = 1
	EAP_CODE_RESPONSE = 2
	EAP_CODE_SUCCESS  = 3
	EAP_CODE_FAILURE  = 4
	EAP_CODE_UNKNOWN  = 10
)

const (
	EAP_TYPE_ID  = 1
	EAP_TYPE_MD5 = 4
	EAP_TYPE_PSW = 7
)

//
const (
	// VERSION_INFO  = "\x06\x07bjQ7SE8BZ3MqHhs3clMregcDY3Y=\x20\x20"  // 如果此字段确为version字段,则这个可能是较旧版本的h3c version
	VERSION_INFO string = ("\x15\x04\xac\x12\x2a\xae\x06\x07\x62\x7a\x4d\x4d\x48\x52\x67\x47\x5a\x6e\x51\x74\x48\x78\x78\x69\x49\x56\x51\x71\x66\x58\x77\x4e\x52\x72\x59\x3d\x20\x20")
)

var (
	Debug bool
)

func init() {
	Debug = false
}
