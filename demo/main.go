package main

import (
	"fmt"
	"os"
	"time"

	"github.com/jung-kurt/gofpdf"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

func main() {
	out := "expire_demo.pdf"
	tmp := "tmp.pdf"

	// 使用 gofpdf 创建一个三页 PDF，第一页为非推荐阅读器提示（中文），
	// 第二页为正常内容，第三页为过期内容。
	pdf := gofpdf.New("P", "mm", "A4", "")

	// 尝试加载系统中的中文字体以避免乱码
	fontPath := findChineseFont()
	if fontPath != "" {
		//pdf.AddUTF8Font("zh", "", fontPath)
		//pdf.SetFont("zh", "", 20)
	} else {
		// 没找到中文字体则使用默认字体（可能导致中文显示不全）
		pdf.SetFont("Arial", "B", 20)
	}
	pdf.SetFont("Arial", "B", 20)
	// 第1页：非推荐阅读器提示（中文） - 默认打开页
	pdf.AddPage()
	pdf.MultiCell(0, 12, "文件显示错误！请使用Adobe Reader、PDF-XChange或福昕PDF阅读器打开当前文档！", "", "C", false)

	// 第2页：正常内容
	pdf.AddPage()
	pdf.SetFont("", "", 24)
	pdf.CellFormat(0, 20, "NORMAL CONTENT", "", 1, "C", false, 0, "")

	// 第3页：过期内容
	pdf.AddPage()
	pdf.SetFont("", "", 24)
	pdf.CellFormat(0, 20, "EXPIRED CONTENT", "", 1, "C", false, 0, "")

	if err := pdf.OutputFileAndClose(tmp); err != nil {
		panic(err)
	}

	// 构造 JavaScript：只有支持并启用 JS 的阅读器会执行，跳转到第2页或第3页；不支持/不启用 JS 的阅读器会停留在第1页（错误提示）
	expiry := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expiryJS := fmt.Sprintf(`var expiry = new Date("%s");
var now = new Date();
if (now < expiry) { this.pageNum = 1; } else { this.pageNum = 2; }`, expiry.Format(time.RFC3339))

	// viewer 检查：若为 Adobe/Acrobat、Foxit、PDF-XChange 则执行过期逻辑
	viewerCheck := `try {
  var viewer = (app.viewerType || '').toString().toLowerCase();
  var disp = (app.viewerDisplayName || '').toString().toLowerCase();
  var ok = false;
  if (viewer.indexOf('reader') !== -1 || viewer.indexOf('acrobat') !== -1) ok = true;
  if (viewer.indexOf('foxit') !== -1 || disp.indexOf('foxit') !== -1) ok = true;
  if (viewer.indexOf('pdf-xchange') !== -1 || disp.indexOf('pdf-xchange') !== -1 || disp.indexOf('pdfxchange') !== -1) ok = true;
  if (ok) {
` + expiryJS + `
  }
} catch (e) {}
`

	// 注入 OpenAction JavaScript 并写出最终 PDF
	if err := embedJavaScript(tmp, out, viewerCheck); err != nil {
		panic(err)
	}

	_ = os.Remove(tmp)
	fmt.Println("PDF generated:", out)
}

func embedJavaScript(inPath, outPath, js string) error {
	ctx, err := api.ReadContextFile(inPath)
	if err != nil {
		return err
	}

	rootDict, err := ctx.Catalog()
	if err != nil {
		return err
	}

	actionDict := types.Dict(map[string]types.Object{
		"S":  types.Name("JavaScript"),
		"JS": types.StringLiteral(js),
	})
	rootDict.Insert("OpenAction", actionDict)

	req := types.Dict(map[string]types.Object{
		"Type": types.Name("Requirement"),
		"S":    types.Name("EnableJavaScripts"),
	})
	rootDict.Insert("Requirements", types.Array{req})

	return api.WriteContextFile(ctx, outPath)
}

// findChineseFont 尝试返回系统中常见的中文字体路径，若找不到返回空字符串
func findChineseFont() string {
	candidates := []string{
		"./微软雅黑.ttf",
		"/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
		"/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttf",
		"/usr/share/fonts/truetype/arphic/ukai.ttf",
		"/usr/share/fonts/truetype/arphic/uming.ttf",
		"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "./wryh.ttf"
}
