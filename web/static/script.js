document.addEventListener('DOMContentLoaded', function() {
    console.log("Dashboard script loaded.");
    
    // 1. 啟動：載入上方統計卡片 (來自 report.json)
    fetchStaticReport();
    
    // 2. 啟動：載入下方異常報警表格 (來自 alerts_if.csv)
    loadAlerts();
});

// ==========================================
// 功能 1: 獲取靜態統計報告 (更新上方卡片)
// ==========================================
function fetchStaticReport() {
    fetch('/api/static-report')
        .then(response => {
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return response.json();
        })
        .then(data => {
            console.log("接收到靜態報告:", data);
            updateMetricCards(data);
        })
        .catch(error => {
            console.error('獲取報告失敗:', error);
            // 如果失敗，顯示錯誤訊息
            const ppsElem = document.getElementById('pps-display');
            if(ppsElem) ppsElem.textContent = "連線失敗";
        });
}

function updateMetricCards(data) {
    const metrics = data.metrics;

    // 1. 即時數據 (Real-time)
    if (document.getElementById('pps-display')) 
        document.getElementById('pps-display').textContent = metrics.total_connections || 0;
        
    if (document.getElementById('latency-display')) 
        document.getElementById('latency-display').textContent = metrics.total_alerts || 0;

    // 模型類型
    if (document.getElementById('training-time-display')) 
        document.getElementById('training-time-display').textContent = metrics.model_type || "N/A";

    // 2. 離線驗證數據 (Offline Validation) - 讀取新欄位
    // 檢查是否有 validation 數據
    if (metrics.validation) {
        if (document.getElementById('accuracy-display')) 
            document.getElementById('accuracy-display').textContent = (metrics.validation.accuracy * 100).toFixed(1) + "%";
            
        if (document.getElementById('recall-display')) 
            document.getElementById('recall-display').textContent = (metrics.validation.recall * 100).toFixed(1) + "%";
            
        if (document.getElementById('f1-display')) 
            document.getElementById('f1-display').textContent = metrics.validation.f1_score.toFixed(3);
    } else {
        // 如果沒有數據，顯示 "-"
        if (document.getElementById('accuracy-display')) document.getElementById('accuracy-display').textContent = "-";
        if (document.getElementById('recall-display')) document.getElementById('recall-display').textContent = "-";
        if (document.getElementById('f1-display')) document.getElementById('f1-display').textContent = "-";
    }
}

// ==========================================
// 功能 2: 獲取異常連線清單 (更新下方表格)
// ==========================================
async function loadAlerts() {
    const tableBody = document.getElementById('table-body');
    const summaryDiv = document.getElementById('alert-summary');
    
    // 檢查 HTML 元素是否存在，避免報錯
    if (!tableBody || !summaryDiv) return;

    try {
        // 呼叫 Node.js 後端提供的 API
        const response = await fetch('/api/alerts');
        const alerts = await response.json();

        if (alerts.length === 0) {
            summaryDiv.textContent = '未偵測到任何異常或結果檔案尚未生成。';
            return;
        }

        summaryDiv.textContent = `總共偵測到 ${alerts.length} 筆異常連線。`;
        
        // 清空表格舊資料
        tableBody.innerHTML = '';

        // 渲染數據到表格
        alerts.forEach(alert => {
            const row = tableBody.insertRow();
            
            // 處理小數點位數
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