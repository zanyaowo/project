// server.js
const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

// 設置靜態檔案路徑：將 'public' 資料夾設定為網頁的根目錄
app.use(express.static(path.join(__dirname, 'public')));

// ----------------------------------------------------
// API 路由 1: 獲取靜態分析報告 (模型最終效能指標)
// ----------------------------------------------------
app.get('/api/static-report', (req, res) => {
    const filePath = path.join(__dirname, 'static_report.json');
    
    fs.readFile(filePath, (err, data) => {
        if (err) {
            console.error('Error reading static report:', err);
            // 由於 Python 報告可能還沒生成，這裡返回一個友好的錯誤提示
            return res.status(500).json({ error: '無法讀取靜態報告檔案，請確認 Python 腳本已運行並生成 static_report.json' });
        }
        
        try {
            const report = JSON.parse(data);
            res.json(report);
        } catch (parseError) {
            console.error('Error parsing static report JSON:', parseError);
            res.status(500).json({ error: '靜態報告 JSON 格式錯誤' });
        }
    });
});


// ----------------------------------------------------
// API 路由 2: 獲取即時模擬數據 (即時趨勢圖所需數據)
// ----------------------------------------------------
app.get('/api/real-time-stream', (req, res) => {
    const filePath = path.join(__dirname, 'real_time_stream.json');

    fs.readFile(filePath, (err, data) => {
        if (err) {
            console.error('Error reading real-time stream:', err);
            return res.status(500).json({ error: '無法讀取即時數據檔案，請確認 Python 腳本已運行並生成 real_time_stream.json' });
        }
        
        try {
            const stream = JSON.parse(data);
            // 實務上會從數據庫或實時連線獲取，這裡模擬返回全部數據
            res.json(stream); 
        } catch (parseError) {
            console.error('Error parsing real-time stream JSON:', parseError);
            res.status(500).json({ error: '即時數據 JSON 格式錯誤' });
        }
    });
});


// 啟動伺服器
app.listen(PORT, () => {
    console.log(`✅ 伺服器運行在: http://localhost:${PORT}`);
    console.log(`🌐 儀表板入口: http://localhost:${PORT}/index.html`);
    console.log(`API 測試點: http://localhost:${PORT}/api/static-report`);
});