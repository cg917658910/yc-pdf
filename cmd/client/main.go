package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cg917658910/yc-pdf/libs/auth"

	api "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

const activationSecret = "yc-pdf-trial-secret"

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

	machineCode, err := generateMachineCode()
	if err != nil {
		http.Error(w, "生成机器码失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
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
      <label>用户口令(user password): <input type="password" name="upw" value="123456" required></label>
    </div>
    <div>
      <label>所有者口令(owner password，可选): <input type="password" value="123456" name="opw"></label>
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
      <label>版本类型:
        <select name="license">
          <option value="trial" selected>试用版</option>
          <option value="commercial">商用版</option>
        </select>
      </label>
    </div>
    <div>
      <label>机器码:
        <input type="text" value="%[1]s" readonly style="width:260px" />
      </label>
      <small>请将机器码发送给客服获取激活码</small>
    </div>
    <div>
      <label>激活码(试用版必填):
        <input type="text" name="activation" placeholder="请输入激活码" style="width:260px" />
      </label>
    </div>
    <div>
      <label>过期时间(YYYY-MM-DD HH:MM): <input type="datetime-local" name="expiry" step="60" required></label>
    </div>
    <div>
      <button type="submit">加密并下载</button>
    </div>
  </form>
</body>
</html>`, machineCode)
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
	license := strings.TrimSpace(r.FormValue("license"))
	if license == "" {
		license = "trial"
	}
	if license == "trial" {
		mCode, err := generateMachineCode()
		if err != nil {
			http.Error(w, "生成机器码失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		activation := strings.TrimSpace(r.FormValue("activation"))
		if !validateActivationCode(mCode, activation) {
			http.Error(w, "试用版需要有效激活码，请联系管理员。", http.StatusForbidden)
			return
		}
	}
	expiryStr := strings.TrimSpace(r.FormValue("expiry"))
	if expiryStr == "" {
		http.Error(w, "过期日期必填", http.StatusBadRequest)
		return
	}

	expiryTime, err := parseExpiry(expiryStr)
	if err != nil {
		http.Error(w, "时间格式错误(YYYY-MM-DD HH:MM): "+err.Error(), http.StatusBadRequest)
		return
	}
	expiryDeadline := expiryTime.UTC()
	if expiryDeadline.Before(time.Now().UTC()) {
		http.Error(w, "过期日期必须在未来", http.StatusBadRequest)
		return
	}
	expiryLabel := expiryTime.Format("2006-01-02 15:04")

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

	if err := embedCombinedJavaScript(inTmp.Name(), expiryDeadline, expiryLabel); err != nil {
		http.Error(w, "写入脚本失败: "+err.Error(), http.StatusInternalServerError)
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

func embedCombinedJavaScript(pdfPath string, deadline time.Time, expiryLabel string) error {
	ctx, err := api.ReadContextFile(pdfPath)
	if err != nil {
		return fmt.Errorf("读取PDF失败: %w", err)
	}

	rootDict, err := ctx.Catalog()
	if err != nil {
		return fmt.Errorf("读取PDF目录失败: %w", err)
	}

	// 将查看器检查脚本和过期脚本合并为一个 OpenAction，保证两个脚本都会执行
	script := buildViewerCheckScript() + "\n" + buildExpiryScript(deadline, expiryLabel)
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

func buildViewerCheckScript() string {
	// 脚本在打开时运行，检测 app.viewerType / app.viewerDisplayName
	return `try {
  var ok = false;
  var viewer = (app.viewerType || '').toString().toLowerCase();
  var disp = (app.viewerDisplayName || '').toString().toLowerCase();

  if (viewer.indexOf('reader') !== -1 || viewer.indexOf('acrobat') !== -1) ok = true;
  if (viewer.indexOf('foxit') !== -1 || disp.indexOf('foxit') !== -1) ok = true;
  if (viewer.indexOf('pdf-xchange') !== -1 || disp.indexOf('pdf-xchange') !== -1 || disp.indexOf('pdfxchange') !== -1) ok = true;

  if (!ok) {
    app.alert('显示错误！请使用Adobe Reader、PDF-XChange或福昕PDF阅读器打开当前文档！', 3);
    try { this.closeDoc(true); } catch (e) {}
  }
} catch (e) {}
`
}

func buildExpiryScript(deadline time.Time, label string) string {
	d := deadline.UTC().Format(time.RFC3339)
	return fmt.Sprintf(`var expiryDeadline = new Date("%s");
var now = new Date();
if (now.getTime() >= expiryDeadline.getTime()) {
  try { app.alert("您查看的文档已过期！", 3); } catch (e) {}
  try {
    for (var i = 0; i < this.numPages; i++) {
      var r = this.getPageBox("Crop", i);
      try {
        var annots = this.getAnnots({nPage: i});
        if (annots) {
          for (var j = annots.length - 1; j >= 0; j--) {
            try { this.removeAnnot(annots[j]); } catch (e) {}
          }
        }
      } catch (e) {}
      try {
        this.addAnnot({
          page: i,
          type: "FreeText",
          rect: [r[0], r[1], r[2], r[3]],
          contents: "您查看的文档已过期！",
          textFont: "Helv",
          textSize: 36,
          alignment: 1,
          fillColor: color.white,
          textColor: color.red,
          opacity: 1
        });
      } catch (e) {}
    }
  } catch (e) {}
}
`, d, label)
}

func parseExpiry(input string) (time.Time, error) {
	normalized := strings.TrimSpace(input)
	if normalized == "" {
		return time.Time{}, fmt.Errorf("空时间")
	}
	if strings.Contains(normalized, " ") {
		normalized = strings.Replace(normalized, " ", "T", 1)
	}
	layouts := []string{
		"2006-01-02T15:04",
		"2006-01-02T15:04:05",
		time.RFC3339,
	}
	for _, layout := range layouts {
		if t, err := time.ParseInLocation(layout, normalized, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("无法解析时间: %s", input)
}

func generateMachineCode() (string, error) {
	return auth.GetMachineCode()
}

func validateActivationCode(machineCode, activation string) bool {
	if machineCode == "" || activation == "" {
		return false
	}
	ok := auth.ValidateActivationFormatted(machineCode, activationSecret, strings.TrimSpace(activation))
	log.Printf("machineCode: %s, activation: %s, valid: %v", machineCode, activation, ok)
	return ok
}
