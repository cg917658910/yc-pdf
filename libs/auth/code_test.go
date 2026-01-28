package auth

import (
	"regexp"
	"strings"
	"testing"
)

func TestGetMachineCodeAndFormat(t *testing.T) {
	mc, err := GetMachineCode()
	if err != nil {
		t.Skipf("无法获取机器码，跳过测试: %v", err)
	}
	if mc == "" {
		t.Fatalf("机器码不应为空")
	}
	if len(mc) < 8 {
		t.Fatalf("机器码长度过短: %d", len(mc))
	}
	matched, err := regexp.MatchString("^[0-9A-F]+$", mc)
	if err != nil {
		t.Fatalf("正则错误: %v", err)
	}
	if !matched {
		t.Fatalf("机器码包含非法字符: %s", mc)
	}

	fmt := FormatMachineCodeDisplay(mc)
	if strings.Contains(fmt, " ") {
		t.Fatalf("格式化后的机器码不应包含空格: %s", fmt)
	}
	if !strings.Contains(fmt, "-") && len(mc) > 4 {
		t.Fatalf("期望格式化结果包含连字符: %s", fmt)
	}
}

func TestGenerateAndValidateActivation(t *testing.T) {
	machine := "TESTMACHINE0001"
	secret := "unit-test-secret"
	code := GenerateActivationCode(machine, secret, 16)
	if len(code) != 16 {
		t.Fatalf("期望激活码长度为16，实际 %d", len(code))
	}

	// 重复生成应保持一致
	c2 := GenerateActivationCode(machine, secret, 16)
	if code != c2 {
		t.Fatalf("生成不确定: %s vs %s", code, c2)
	}

	// 不同 secret 不应相同
	c3 := GenerateActivationCode(machine, secret+"x", 16)
	if c3 == code {
		t.Fatalf("不同 secret 生成相同激活码: %s", c3)
	}

	// 验证通过
	if !ValidateActivationCode(machine, secret, code) {
		t.Fatalf("正确激活码验证失败")
	}

	// 验证格式化输入也能通过
	formatted := FormatMachineCodeDisplay(code)
	if !ValidateActivationFormatted(machine, secret, formatted) {
		t.Fatalf("格式化激活码验证失败: %s", formatted)
	}

	// 错误的激活码失败
	if ValidateActivationCode(machine, secret, code[:len(code)-1]+"0") {
		t.Fatalf("错误激活码意外通过验证")
	}
}
