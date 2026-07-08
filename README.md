# OpenPhish Threat Intelligence Synchronization

## 專案概述

本專案建立自動化 Threat Intelligence Synchronization 流程，定期同步 OpenPhish 公開釣魚威脅情資（Phishing Threat Feed），並保存歷史情資快照（Historical Snapshot），以提供後續 IOC 分析、威脅追蹤及偵測規則驗證使用。

## 功能特色

- 自動同步 OpenPhish Public Threat Feed
- 定期建立 IOC 歷史快照
- 透過 Git 進行情資版本管理與追蹤
- 支援排程同步與手動觸發
- 提供 Threat Hunting 與 Detection Engineering 資料來源

## 架構流程

```
OpenPhish Public Feed
          │
          ▼
GitHub Actions Workflow
          │
          ▼
Threat Intelligence Synchronization
          │
          ▼
Historical IOC Archive
          │
          ▼
Analysis / Detection Rule Validation
```

## 資料來源

OpenPhish Public Feed

```
https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
```

## 執行排程

| 類型 | 說明 |
|---|---|
| Scheduled Sync | 每 12 小時自動同步 |
| Manual Trigger | 支援 GitHub Actions 手動執行 |

## 資料保存

每次同步會建立時間戳記快照（Historical Snapshot），並依照月份分類保存：

```
data/
├── YYYY-MM/
│   ├── feed_YYYYMMDD_HHMMSS.txt
│   └── ...
```

範例：

```
data/
└── 2026-07/
    ├── feed_20260708_080000.txt
    ├── feed_20260708_200000.txt
    └── ...
```

## 使用情境

- Phishing IOC 蒐集與管理
- Threat Intelligence 資料保存
- Threat Hunting 分析
- Detection Rule 測試與驗證
- Security Monitoring 資料來源

## Technology

- GitHub Actions
- Git
- OpenPhish Public Feed
