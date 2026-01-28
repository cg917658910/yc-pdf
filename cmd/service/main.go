package main

import (
	"fmt"
	"os"

	"github.com/cg917658910/yc-pdf/libs/auth"
	"github.com/joho/godotenv"
)

func main() {
	// 尝试从项目根目录加载 .env 文件（如果存在），忽略错误
	_ = godotenv.Load()

	if len(os.Args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: genact MACHINE_CODE")
		os.Exit(2)
	}
	machine := os.Args[1]

	secret := os.Getenv("ACTIVATION_SECRET")
	if secret == "" {
		secret = "yc-pdf-trial-secret"
	}

	act := auth.GenerateActivationCode(machine, secret, 16)
	fmt.Println(act)
}
