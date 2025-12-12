async function loadAlerts() {
    const tableBody = document.getElementById('table-body');
    const summaryDiv = document.getElementById('alert-summary');
    
    try {
        // 呼叫 Node.js 後端提供的 API
        const response = await fetch('/api/alerts');
        const alerts = await response.json();

        if (alerts.length === 0) {
            summaryDiv.textContent = '未偵測到任何異常或結果檔案尚未生成。';
            return;
        }

        summaryDiv.textContent = `總共偵測到 ${alerts.length} 筆異常連線。`;
        
        // 渲染數據到表格
        alerts.forEach(alert => {
            const row = tableBody.insertRow();
            
            // 由於 anomaly_score 越大越可疑，我們取小数点后几位，方便展示
            const score = parseFloat(alert.anomaly_score).toFixed(4); 
            
            row.insertCell().textContent = alert.ts;
            row.insertCell().textContent = alert.src;
            row.insertCell().textContent = alert.dst;
            row.insertCell().textContent = score;
            row.insertCell().textContent = alert.bytes_sum; 
        });

    } catch (error) {
        console.error('API 錯誤:', error);
        summaryDiv.textContent = '載入數據時發生錯誤，請檢查伺服器狀態。';
    }
}

loadAlerts();