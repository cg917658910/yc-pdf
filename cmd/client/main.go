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

	"github.com/jung-kurt/gofpdf"
	api "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

const activationSecret = "yc-pdf-trial-secret"

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/encrypt", encryptHandler)
	http.HandleFunc("/verify", verifyHandler)

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

	// 设置严格的PDF权限控制
	conf := model.NewAESConfiguration(upw, opw, 256)

	// 解析权限设置
	printAllowed := r.FormValue("print") == "on"
	copyAllowed := r.FormValue("copy") == "on"

	// 设置PDF权限 - 使用pdfcpu的权限常量
	// 根据pdfcpu文档，权限是16位值
	// 默认使用最严格的权限设置
	var permissions model.PermissionFlags = 0xF0C3 // PermissionsNone - 禁止所有操作

	if printAllowed {
		permissions = 0xF8C7 // PermissionsPrint - 允许打印
	}

	if printAllowed && copyAllowed {
		permissions = 0xFFFF // PermissionsAll - 允许所有操作
	}

	conf.Permissions = permissions

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

	// 添加在线验证JavaScript - 增强保护
	if err := embedCombinedJavaScript(inTmp.Name(), expiryDeadline, expiryLabel); err != nil {
		http.Error(w, "写入验证脚本失败: "+err.Error(), http.StatusInternalServerError)
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
	// 1. 读取原始 PDF 获取页数
	origCtx, err := api.ReadContextFile(pdfPath)
	if err != nil {
		return fmt.Errorf("读取PDF失败: %w", err)
	}
	origPages := origCtx.PageCount

	// 2. 生成错误页和过期页的临时 PDF（保证中文为 UTF-8）
	//cwd, _ := os.Getwd()
	/* fontPath := filepath.Join(cwd, "demo", "微软雅黑.ttf")
	if _, err := os.Stat(fontPath); err != nil {
		fontPath = "" // 如果不存在则留空，使用默认字体
	} */
	fontPath := "" // 如果不存在则留空，使用默认字体

	errTmp, err := os.CreateTemp("", "err-*.pdf")
	if err != nil {
		return fmt.Errorf("创建临时错误页失败: %w", err)
	}
	errTmp.Close()
	errTmpPath := errTmp.Name()
	if err := createSinglePagePDF(errTmpPath, "文件显示错误！请使用Adobe Reader、PDF-XChange或福昕PDF阅读器打开当前文档！", fontPath); err != nil {
		return fmt.Errorf("生成错误页失败: %w", err)
	}

	expTmp, err := os.CreateTemp("", "exp-*.pdf")
	if err != nil {
		return fmt.Errorf("创建临时过期页失败: %w", err)
	}
	expTmp.Close()
	expTmpPath := expTmp.Name()
	if err := createSinglePagePDF(expTmpPath, "您查看的文档已过期！\n\n请联系文档提供者获取最新版本。", fontPath); err != nil {
		return fmt.Errorf("生成过期页失败: %w", err)
	}

	// 3. 合并为: 错误页 + 原始PDF + 过期页 -> mergedPath
	mergedTmp, err := os.CreateTemp("", "merged-*.pdf")
	if err != nil {
		return fmt.Errorf("创建合并临时文件失败: %w", err)
	}
	mergedTmpPath := mergedTmp.Name()
	mergedTmp.Close()

	inFiles := []string{errTmpPath, pdfPath, expTmpPath}
	// MergeCreateFile signature expects (inFiles []string, outFile string, useAcroForms bool, conf *model.Configuration)
	if err := api.MergeCreateFile(inFiles, mergedTmpPath, false, nil); err != nil {
		return fmt.Errorf("合并PDF失败: %w", err)
	}

	// 用合并后的文件替换原始 pdfPath
	if err := os.Rename(mergedTmpPath, pdfPath); err != nil {
		// 如果重命名失败，尝试复制
		if in, err2 := os.Open(mergedTmpPath); err2 == nil {
			if out, err3 := os.Create(pdfPath); err3 == nil {
				if _, err4 := io.Copy(out, in); err4 != nil {
					return fmt.Errorf("写入合并文件失败: %w", err4)
				}
				out.Close()
			}
			in.Close()
		}
	}

	// 清理临时单页文件
	os.Remove(errTmpPath)
	os.Remove(expTmpPath)

	// 4. 构造 OpenAction JS：支持的阅读器会跳到原始内容页或过期页
	// 计算目标页索引（合并后：0=error, 1..origPages = original pages, origPages+1 = expired page）
	normalIndex := 1
	expiredIndex := 1 + origPages
	d := deadline.UTC().Format(time.RFC3339)

	script := fmt.Sprintf(`try {
  var viewer = (app.viewerType || '').toString().toLowerCase();
  var disp = (app.viewerDisplayName || '').toString().toLowerCase();
  var ok = false;
  if (viewer.indexOf('reader') !== -1 || viewer.indexOf('acrobat') !== -1) ok = true;
  if (viewer.indexOf('foxit') !== -1 || disp.indexOf('foxit') !== -1) ok = true;
  if (viewer.indexOf('pdf-xchange') !== -1 || disp.indexOf('pdf-xchange') !== -1 || disp.indexOf('pdfxchange') !== -1) ok = true;
  var expiryDeadline = new Date("%s");
  var now = new Date();
  if (ok) {
    if (now.getTime() < expiryDeadline.getTime()) {
      try { this.pageNum = %d; } catch(e) {}
    } else {
      try { this.pageNum = %d; } catch(e) {}
    }
  }
} catch (e) {}
`, d, normalIndex, expiredIndex)

	// 写入 OpenAction 到合并后的PDF
	ctx, err := api.ReadContextFile(pdfPath)
	if err != nil {
		return fmt.Errorf("读取合并后PDF失败: %w", err)
	}
	rootDict, err := ctx.Catalog()
	if err != nil {
		return fmt.Errorf("读取PDF目录失败: %w", err)
	}
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

// createSinglePagePDF 使用 gofpdf 创建仅包含一页居中文本的 PDF（支持 UTF-8 字体路径）
func createSinglePagePDF(path, text, fontPath string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	if fontPath != "" {
		pdf.AddUTF8Font("zh", "", fontPath)
		pdf.SetFont("zh", "", 20)
	} else {
		pdf.SetFont("Arial", "", 20)
	}
	pdf.AddPage()
	pdf.MultiCell(0, 12, text, "", "C", false)
	return pdf.OutputFileAndClose(path)
}

func buildViewerCheckScript() string {
	// 更严格的PDF阅读器检查脚本
	return `try {
  var ok = false;
  var viewer = '';
  var disp = '';
  var appInfo = '';
  
  // 多重检查方式
  try { viewer = (app.viewerType || '').toString().toLowerCase(); } catch(e) {}
  try { disp = (app.viewerDisplayName || '').toString().toLowerCase(); } catch(e) {}
  try { appInfo = (app.appInfo || {}).appName || ''; appInfo = appInfo.toString().toLowerCase(); } catch(e) {}
  
  // 检查Adobe Reader/Acrobat
  if (viewer.indexOf('reader') !== -1 || viewer.indexOf('acrobat') !== -1 || 
      disp.indexOf('reader') !== -1 || disp.indexOf('acrobat') !== -1 ||
      appInfo.indexOf('reader') !== -1 || appInfo.indexOf('acrobat') !== -1) {
    ok = true;
  }
  
  // 检查Foxit
  if (viewer.indexOf('foxit') !== -1 || disp.indexOf('foxit') !== -1 || 
      appInfo.indexOf('foxit') !== -1) {
    ok = true;
  }
  
  // 检查PDF-XChange
  if (viewer.indexOf('pdf-xchange') !== -1 || disp.indexOf('pdf-xchange') !== -1 || 
      disp.indexOf('pdfxchange') !== -1 || appInfo.indexOf('pdf-xchange') !== -1 ||
      appInfo.indexOf('pdfxchange') !== -1) {
    ok = true;
  }
  
  // 如果所有检查都失败，说明不是支持的阅读器
  if (!ok) {
    // 显示错误并阻止继续阅读
    app.alert('显示错误！请使用Adobe Reader、PDF-XChange或福昕PDF阅读器打开当前文档！', 3);
    
    // 尝试多种方式关闭文档
    try { this.closeDoc(true); } catch (e) {}
    try { this.doc.closeDoc(true); } catch (e) {}
    try { app.execMenuItem('Close'); } catch (e) {}
    
    // 如果无法关闭，覆盖所有页面内容
    try {
      for (var i = 0; i < this.numPages; i++) {
        var r = this.getPageBox("Crop", i);
        this.addAnnot({
          page: i,
          type: "FreeText",
          rect: [r[0], r[1], r[2], r[3]],
          contents: "显示错误！\\n\\n请使用Adobe Reader、PDF-XChange或福昕PDF阅读器打开当前文档！",
          textFont: "Helv",
          textSize: 24,
          alignment: 1,
          fillColor: color.white,
          textColor: color.red,
          opacity: 1
        });
      }
    } catch (e) {}
  }
} catch (e) {
  // 如果脚本执行出错，也显示错误
  try {
    app.alert('显示错误！请使用Adobe Reader、PDF-XChange或福昕PDF阅读器打开当前文档！', 3);
  } catch (err) {}
}
`
}

func buildExpiryScript(deadline time.Time, label string) string {
	d := deadline.UTC().Format(time.RFC3339)
	return fmt.Sprintf(`// 过期检查脚本
var expiryDeadline = new Date("%s");
var expiryLabel = "%s";
var now = new Date();

// 显示过期信息
function showExpired() {
  try { 
    app.alert("您查看的文档已过期！\\n过期时间: " + expiryLabel, 3); 
  } catch (e) {}
  
  // 尝试关闭文档
  try { this.closeDoc(true); } catch (e) {}
  try { this.doc.closeDoc(true); } catch (e) {}
  try { app.execMenuItem('Close'); } catch (e) {}
  
  // 如果无法关闭，覆盖所有页面内容
  try {
    for (var i = 0; i < this.numPages; i++) {
      var r = this.getPageBox("Crop", i);
      
      // 清除现有注释
      try {
        var annots = this.getAnnots({nPage: i});
        if (annots) {
          for (var j = annots.length - 1; j >= 0; j--) {
            try { this.removeAnnot(annots[j]); } catch (e) {}
          }
        }
      } catch (e) {}
      
      // 添加过期覆盖层
      try {
        this.addAnnot({
          page: i,
          type: "FreeText",
          rect: [r[0], r[1], r[2], r[3]],
          contents: "您查看的文档已过期！\\n\\n过期时间: " + expiryLabel + "\\n\\n请联系文档提供者获取最新版本。",
          textFont: "Helv",
          textSize: 32,
          alignment: 1,
          fillColor: color.white,
          textColor: color.red,
          opacity: 1
        });
      } catch (e) {}
    }
  } catch (e) {}
}

// 检查是否过期
if (now.getTime() >= expiryDeadline.getTime()) {
  showExpired();
} else {
  // 如果未过期，设置定时器每分钟检查一次
  try {
    var checkInterval = setInterval(function() {
      var current = new Date();
      if (current.getTime() >= expiryDeadline.getTime()) {
        clearInterval(checkInterval);
        showExpired();
      }
    }, 60000); // 每分钟检查一次
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

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("收到验证请求: IP=%s, 时间=%s",
		r.RemoteAddr,
		time.Now().Format("2006-01-02 15:04:05"))
	// 获取查询参数
	machineCode := r.URL.Query().Get("machine")
	if machineCode == "" {
		http.Error(w, "INVALID", http.StatusBadRequest)
		return
	}

	// 验证机器码是否在允许列表中
	// 这里可以连接数据库或其他验证机制
	// 目前简单检查机器码格式

	// 记录验证日志
	log.Printf("验证请求: 机器码=%s, IP=%s, 时间=%s",
		machineCode,
		r.RemoteAddr,
		time.Now().Format("2006-01-02 15:04:05"))

	// 简单验证逻辑 - 在实际应用中应该更复杂
	if len(machineCode) >= 10 && len(machineCode) <= 50 {
		// 可以添加更多验证逻辑，如：
		// 1. 检查机器码是否在数据库中
		// 2. 检查是否过期
		// 3. 检查使用次数等

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "VALID")
		log.Printf("验证成功: 机器码=%s", machineCode)
	} else {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "INVALID")
		log.Printf("验证失败: 机器码=%s (格式无效)", machineCode)
	}
}

func validateActivationCode(machineCode, activation string) bool {
	if machineCode == "" || activation == "" {
		return false
	}
	ok := auth.ValidateActivationFormatted(machineCode, activationSecret, strings.TrimSpace(activation))
	log.Printf("machineCode: %s, activation: %s, valid: %v", machineCode, activation, ok)
	return ok
}
