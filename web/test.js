// 1. 引入 Express 模組
const express = require('express');
const app = express();
// 設定伺服器監聽的 Port (建議使用 3000 或 8080)
const port = 3000; 

// 2. 定義一個路由 (Route)
// 當使用者訪問根路徑 (/) 時，執行這個回調函數
app.get('/', (req, res) => {
  // 傳送簡單的文字作為回應
  res.send('專題伺服器已啟動！歡迎使用 Node.js 進行展示。');
});

// 3. 啟動伺服器並監聽指定的 Port
app.listen(port, () => {
  // 伺服器成功啟動後，在終端機顯示訊息
  console.log(`Node.js Server 正在運作中：http://localhost:${port}`);
});