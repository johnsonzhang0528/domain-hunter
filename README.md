# 🔍 Domain Hunter

**全自動過期域名篩選與分析工具** — Automated Expired Domain Evaluation Pipeline

自動完成以下所有步驟，從 CSV 匯入到最終報告一鍵搞定：

1. **ExpiredDomains CSV 匯入** — 解析匯出檔案，自動辨識欄位
2. **Wayback Machine 歷史分析** — 抓取快照 → 分類內容 → 偵測垃圾/成人/賭博
3. **反向連結品質檢查** — CommonCrawl + OpenPageRank → 垃圾連結比例
4. **DNS / WHOIS 查詢** — 可用性、年齡、Parking 偵測
5. **安全性檢測** — URLhaus / Google Safe Browsing / VirusTotal 黑名單
6. **綜合評分** — 加權算法 → 100 分制 → BUY / MAYBE / REJECT 判定
7. **報告生成** — HTML (暗色主題互動式) + CSV + JSON

---

## 🚀 快速開始

### 安裝

```bash
cd domain-hunter
pip install -e .
```

### 設定 API Keys (選填，不設也能用)

```bash
cp .env.example .env
# 編輯 .env 填入你的 API key
```

| API | 用途 | 免費額度 |
|-----|------|----------|
| OpenPageRank | PageRank 查詢 | 100 次/天 |
| Google Safe Browsing | 惡意網站檢測 | 10,000 次/天 |
| VirusTotal | 病毒/惡意軟體掃描 | 4 次/分鐘 |

> **不設任何 key 也可以正常使用！** Wayback Machine、CommonCrawl、URLhaus、DNS、WHOIS 全部免費。

---

## 📖 使用方式

### 1️⃣ 從 ExpiredDomains CSV 分析

到 [ExpiredDomains.net](https://www.expireddomains.net/) 下載 CSV 後：

```bash
domain-hunter analyze downloaded_domains.csv
```

### 2️⃣ 直接分析指定域名

```bash
domain-hunter check example.com gotravelwise.com myblog.org
```

### 3️⃣ 從文字檔批次分析

建立 `domains.txt`（每行一個域名）：

```
example.com
myblog.org
oldsite.net
```

```bash
domain-hunter batch domains.txt
```

### 選項

```
-o, --output DIR    報告輸出目錄 (預設: ./output/)
-f, --format FMT    輸出格式: html, csv, json, all (可多選)
-w, --workers N     並行分析數量 (預設: 5)
-v, --verbose       顯示詳細日誌
```

---

## 📊 評分系統

| 項目 | 權重 | 分數依據 |
|------|------|----------|
| Wayback 歷史 | 30% | 內容乾淨度、無垃圾/賭博/成人 |
| 反向連結品質 | 25% | 垃圾連結比例、錨文本品質 |
| 安全性 | 15% | 黑名單檢查 |
| 利基相關度 | 15% | 內容與目標利基匹配 |
| 域名年齡 | 10% | 越老越好 |
| DNS 可用性 | 5% | 是否可直接註冊 |

### 判定標準

- **BUY** (≥ 75分): 歷史乾淨、連結優質、安全可靠
- **MAYBE** (50-74分): 有些疑慮但可進一步評估
- **REJECT** (< 50分): 有重大問題，不建議購買

### 硬性否決條件（不論總分）

- ❌ 歷史內容含賭博/成人/仿冒
- ❌ 垃圾反連比例 > 50%
- ❌ 被安全黑名單標記

---

## 🔧 垃圾偵測

### 內容分類器偵測項目

| 類別 | 偵測關鍵詞 |
|------|-----------|
| 🎰 gambling | casino, poker, betting, slots, roulette... |
| 🔞 adult | porn, xxx, escort, nude... |
| 💊 pharma | viagra, cialis, buy pills... |
| 🦠 malware | crack, keygen, warez, nulled... |
| 🔗 pbn_spam | "just another wordpress site", lorem ipsum... |
| 🏗️ link_farm | buy backlinks, link building service... |
| 🅿️ parked | "domain for sale", sedoparking, bodis... |

### 可疑 TLD (反連來源)

`.xyz`, `.top`, `.click`, `.loan`, `.icu`, `.buzz`, `.monster`, `.cfd` 等

---

## 📂 專案結構

```
domain-hunter/
├── src/domain_hunter/
│   ├── cli.py              # CLI 入口
│   ├── pipeline.py         # 管線控制器
│   ├── models.py           # 資料模型
│   ├── config.py           # 設定與常數
│   ├── importers/
│   │   └── csv_importer.py # CSV 解析
│   ├── analyzers/
│   │   ├── wayback.py      # Wayback Machine 分析
│   │   ├── backlinks.py    # 反連品質分析
│   │   ├── dns_check.py    # DNS 查詢
│   │   ├── whois_check.py  # WHOIS 查詢
│   │   ├── safety.py       # 安全檢查
│   │   └── content_classifier.py  # 內容分類器
│   ├── scoring/
│   │   └── scorer.py       # 評分引擎
│   └── reports/
│       ├── generator.py    # 報告生成器
│       └── templates/
│           └── report.html # HTML 報告模板
├── output/                 # 報告輸出目錄
├── .env.example            # API Key 範本
├── requirements.txt
└── pyproject.toml
```

---

## 🌐 資料來源

| 服務 | API 類型 | 費用 | 用途 |
|------|---------|------|------|
| Wayback Machine CDX | REST | 免費 | 歷史快照索引與內容 |
| CommonCrawl Index | REST | 免費 | 發現反向連結 |
| OpenPageRank | REST | 免費 100/天 | PageRank 評分 |
| URLhaus (abuse.ch) | REST | 免費 | 惡意網址檢查 |
| Google Safe Browsing | REST | 免費 (需 key) | 惡意網站檢查 |
| VirusTotal | REST | 免費 4/分 (需 key) | 病毒掃描 |
| WHOIS | 系統呼叫 | 免費 | 域名註冊資訊 |
| DNS | 系統呼叫 | 免費 | DNS 解析 |

---

## License

MIT
