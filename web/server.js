const express = require('express');
const fs = require('fs');
const path = require('path');
const csv = require('csv-parser');
const app = express();
const port = 3000;

// 設定靜態檔案，讓前端可以訪問 public 資料夾內的 HTML, JS
app.use(express.static('public'));

// API 接口：讀取並傳輸 CSV 格式的報警數據
app.get('/api/alerts', (req, res) => {
    const csvPath = path.join(__dirname, 'output-data', 'alerts_if.csv');
    const alerts = [];

    // 使用 csv-parser 讀取 CSV 檔案並轉換為 JSON 陣列
    fs.createReadStream(csvPath)
        .on('error', (err) => {
            // 如果檔案不存在，回傳空陣列
            res.json(alerts); 
        })
        .pipe(csv())
        .on('data', (row) => {
            alerts.push(row);
        })
        .on('end', () => {
            // 成功後將 JSON 數據傳送到前端
            res.json(alerts);
        });
});

// 啟動伺服器
app.listen(port, () => {
    console.log(`展示伺服器已啟動：http://localhost:${port}`);
});