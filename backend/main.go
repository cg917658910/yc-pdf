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

	// 使用 gofpdf 创建一个两页 PDF
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 24)
	pdf.CellFormat(0, 20, "NORMAL CONTENT", "", 1, "C", false, 0, "")

	pdf.AddPage()
	pdf.SetFont("Arial", "B", 24)
	pdf.CellFormat(0, 20, "EXPIRED CONTENT", "", 1, "C", false, 0, "")

	if err := pdf.OutputFileAndClose(tmp); err != nil {
		panic(err)
	}

	// 构造 JavaScript（加入 alert 便于调试查看器是否执行 JS）
	expiry := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	js := fmt.Sprintf(`var expiry = new Date("%s");
var now = new Date();
var vtype = (app.viewerType||app.viewerDisplayName||'').toString();
try { app.alert('JS executed in viewer: ' + vtype + '\nnow: ' + now.toISOString()); } catch(e) {}
if (now < expiry) { this.pageNum = 0; } else { this.pageNum = 1; }`, expiry.Format(time.RFC3339))

	// 注入 OpenAction JavaScript 并写出最终 PDF
	if err := embedJavaScript(tmp, out, js); err != nil {
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
