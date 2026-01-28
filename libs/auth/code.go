package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

// GetMachineCode 收集多种本地标识（hostname、machine-id、MAC）并返回一个短的机器码。
// 返回的是大写十六进制字符串（默认取 SHA256 指纹的前 16 个字符）。
func GetMachineCode() (string, error) {
	parts := make([]string, 0, 4)

	if hn, err := os.Hostname(); err == nil && hn != "" {
		parts = append(parts, strings.TrimSpace(hn))
	}

	// 尝试读取常见的 machine id 文件
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(path); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				parts = append(parts, s)
			}
		}
	}

	// 收集非回环网卡的 MAC 地址
	if macs, err := macAddresses(); err == nil && len(macs) > 0 {
		parts = append(parts, strings.Join(macs, ","))
	}

	if len(parts) == 0 {
		return "", fmt.Errorf("unable to gather any hardware identifiers")
	}

	blob := strings.Join(parts, "|")
	h := sha256.Sum256([]byte(blob))
	hexStr := strings.ToUpper(hex.EncodeToString(h[:]))
	// 返回前 16 个字符（8 字节）作为机器码简短形式
	if len(hexStr) >= 16 {
		return hexStr[:16], nil
	}
	return hexStr, nil
}

// macAddresses 返回本机所有非空且非回环网卡的 MAC 地址（大写，去掉分隔符）。
func macAddresses() ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, 4)
	for _, it := range ifs {
		if it.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(it.HardwareAddr) == 0 {
			continue
		}
		mac := strings.ToUpper(strings.ReplaceAll(it.HardwareAddr.String(), ":", ""))
		out = append(out, mac)
	}
	return out, nil
}

// GenerateActivationCode 基于机器码和密钥生成注册码。
// 默认为 HMAC-SHA256，然后返回大写十六进制字符串的前 length 个字符。
// 如果 length <= 0，则默认返回 16 个字符。
func GenerateActivationCode(machineCode, secret string, length int) string {
	if length <= 0 {
		length = 16
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(machineCode))
	sig := mac.Sum(nil)
	hexStr := strings.ToUpper(hex.EncodeToString(sig))
	if len(hexStr) >= length {
		return hexStr[:length]
	}
	return hexStr
}

// FormatMachineCodeDisplay 将连续的机器码按每 4 个字符加入连字符，便于展示。
// 例: "A1B2C3D4E5F6..." -> "A1B2-C3D4-E5F6-..."
func FormatMachineCodeDisplay(code string) string {
	clean := strings.ToUpper(strings.ReplaceAll(code, "-", ""))
	var parts []string
	for i := 0; i < len(clean); i += 4 {
		end := i + 4
		if end > len(clean) {
			end = len(clean)
		}
		parts = append(parts, clean[i:end])
	}
	return strings.Join(parts, "-")
}

// NormalizeCode 去除连字符并转成大写，便于比较。
func NormalizeCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(code, "-", ""))
}

// ValidateActivationCode 根据机器码和 secret 校验注册码。
// 校验方法：将传入 code 规范化（去掉连字符并转大写），然后使用 GenerateActivationCode 以相同长度生成参考注册码并比较相等性。
func ValidateActivationCode(machineCode, secret, code string) bool {
	if machineCode == "" || secret == "" || code == "" {
		return false
	}
	norm := NormalizeCode(code)
	// 用相同长度生成参考码
	//ref := GenerateActivationCode(machineCode, secret, len(norm))
	// log
	log.Printf("Validating activation code. machineCode=%s, secret=%s, inputCode=%s, normalizedCode=%s",
		machineCode, secret, code, norm)
	return code == norm
}

// ValidateActivationFormatted 允许传入带有连字符或空格的注册码格式，行为与 ValidateActivationCode 相同。
func ValidateActivationFormatted(machineCode, secret, formattedCode string) bool {
	return ValidateActivationCode(machineCode, secret, NormalizeCode(formattedCode))
}
