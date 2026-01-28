package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	api "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/encrypt", encryptHandler)

	addr := ":8088"
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html>
<html lang="zh-cn">
<head>
  <meta charset="UTF-8" />
  <title>PDF 加密</title>
</head>
<body>
  <h1>PDF 加密</h1>
  <form action="/encrypt" method="post" enctype="multipart/form-data">
    <div>
      <label>选择 PDF 文件: <input type="file" name="file" accept="application/pdf" required></label>
    </div>
    <div>
      <label>用户口令(user password): <input type="password" name="upw" required></label>
    </div>
    <div>
      <label>所有者口令(owner password，可选): <input type="password" name="opw"></label>
    </div>
    <div>
      <label>加密方式:
        <select name="mode">
          <option value="rc4">RC4 40bit</option>
          <option value="rc4-128">RC4 128bit</option>
          <option value="aes">AES 128bit</option>
          <option value="aes-256" selected>AES 256bit</option>
        </select>
      </label>
    </div>
    <div>
      <label>允许打印: <input type="checkbox" name="print" checked></label>
    </div>
    <div>
      <label>允许复制: <input type="checkbox" name="copy" checked></label>
    </div>
    <div>
      <label>过期日期(YYYY-MM-DD): <input type="date" name="expiry" required></label>
    </div>
    <div>
      <button type="submit">加密并下载</button>
    </div>
  </form>
</body>
</html>`)
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "解析表单失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "读取上传文件失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	upw := r.FormValue("upw")
	if upw == "" {
		http.Error(w, "用户口令必填", http.StatusBadRequest)
		return
	}
	opw := r.FormValue("opw")
	expiryStr := r.FormValue("expiry")
	if expiryStr == "" {
		http.Error(w, "过期日期必填", http.StatusBadRequest)
		return
	}

	expiryDate, err := time.Parse("2006-01-02", expiryStr)
	if err != nil {
		http.Error(w, "日期格式错误(YYYY-MM-DD): "+err.Error(), http.StatusBadRequest)
		return
	}
	expiryDeadline := expiryDate.Add(24 * time.Hour).UTC()
	if expiryDeadline.Before(time.Now().UTC()) {
		http.Error(w, "过期日期必须在未来", http.StatusBadRequest)
		return
	}

	conf := model.NewAESConfiguration(upw, opw, 256)

	// 将上传文件先写入临时文件
	inTmp, err := os.CreateTemp("", "in-*.pdf")
	if err != nil {
		http.Error(w, "创建临时文件失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(inTmp.Name())
	defer inTmp.Close()

	if _, err := io.Copy(inTmp, file); err != nil {
		http.Error(w, "写入临时文件失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := inTmp.Close(); err != nil {
		http.Error(w, "关闭临时文件失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := embedExpiryJavaScript(inTmp.Name(), expiryDeadline, expiryStr); err != nil {
		http.Error(w, "写入有效期脚本失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	outTmp, err := os.CreateTemp("", "out-*.pdf")
	if err != nil {
		http.Error(w, "创建输出临时文件失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(outTmp.Name())
	defer outTmp.Close()
	log.Printf("conf: %+v", conf)
	// 调用 pdfcpu EncryptFile
	if err := api.EncryptFile(inTmp.Name(), outTmp.Name(), conf); err != nil {
		http.Error(w, "加密失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 把加密后的文件返回给浏览器
	if err := outTmp.Close(); err != nil {
		http.Error(w, "关闭输出文件失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	encFile, err := os.Open(outTmp.Name())
	if err != nil {
		http.Error(w, "读取加密文件失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer encFile.Close()

	w.Header().Set("Content-Type", "application/pdf")
	base := filepath.Base(header.Filename)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"encrypted_%s\"", base))

	if _, err := io.Copy(w, encFile); err != nil {
		log.Printf("写响应失败: %v", err)
	}
}

func embedExpiryJavaScript(pdfPath string, deadline time.Time, expiryLabel string) error {
	ctx, err := api.ReadContextFile(pdfPath)
	if err != nil {
		return fmt.Errorf("读取PDF失败: %w", err)
	}

	rootDict, err := ctx.Catalog()
	if err != nil {
		return fmt.Errorf("读取PDF目录失败: %w", err)
	}

	script := buildExpiryScript(deadline, expiryLabel)
	actionDict := types.Dict(map[string]types.Object{
		"S":  types.Name("JavaScript"),
		"JS": types.StringLiteral(script),
	})
	rootDict.Insert("OpenAction", actionDict)

	req := types.Dict(map[string]types.Object{
		"Type": types.Name("Requirement"),
		"S":    types.Name("EnableJavaScripts"),
	})
	rootDict.Insert("Requirements", types.Array{req})

	if err := api.WriteContextFile(ctx, pdfPath); err != nil {
		return fmt.Errorf("写入PDF失败: %w", err)
	}
	return nil
}

func buildExpiryScript(deadline time.Time, label string) string {
	d := deadline.UTC().Format(time.RFC3339)
	return fmt.Sprintf(`var expiryDeadline = new Date("%s");
var now = new Date();
if (now.getTime() >= expiryDeadline.getTime()) {
  app.alert("本文档已过期（截止 %s）。");
  try { this.closeDoc(true); } catch (e) {}
}`, d, label)
}
