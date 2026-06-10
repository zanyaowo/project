# 專題報告（LaTeX）

## 檔案
- `main.tex` — 報告主檔（章節內容＋參考文獻都在這裡）
- `figures/` — 圖片放這裡（PDF / PNG）

> 參考文獻直接寫在 `main.tex` 底部的 `thebibliography` 區塊（中英混排已手動排好），
> 不使用 BibTeX，因此沒有 `.bib` 檔。

## 在 Overleaf 編譯（重要）
1. 把 `report/` 整個資料夾打包上傳，或在 Overleaf 新建專案後上傳這些檔案。
2. **Menu → Settings → Compiler 選 `XeLaTeX`**（不可用 pdfLaTeX，`ctex` 中文套件需要 XeLaTeX）。
3. 主檔設為 `main.tex`，按 Recompile。
4. 中文字型用 `ctex` 內建的 fandol，Overleaf 已內建，無需上傳字型。

## 插入圖片
把圖檔放進 `figures/`，在 `main.tex` 取消對應 `\includegraphics` 那行的註解即可。

## 引用文獻
在正文用 `\cite{liu2008isolation}`，文獻定義在 `references.bib`。
