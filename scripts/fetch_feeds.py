"""
從 OpenPhish + URLhaus 抓取釣魚網址，去重後累積進歷史檔。
每次執行只會把「新出現」的網址寫入 data/new_this_run.txt，
供後續 ASN 分析腳本使用（避免重複查詢已分析過的網址）。
"""

import csv
import os
import sys
from datetime import datetime, timezone

import requests

HISTORY_FILE = "data/urls_history.csv"       # 累積的完整歷史（url, source, first_seen）
NEW_THIS_RUN_FILE = "data/new_this_run.txt"  # 這次新增的網址，給 analyze 腳本用

OPENPHISH_URL = "https://openphish.com/feed.txt"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def fetch_openphish():
    urls = set()
    try:
        resp = requests.get(OPENPHISH_URL, timeout=30)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if line:
                urls.add((line, "openphish"))
        print(f"OpenPhish: 抓到 {len(urls)} 筆")
    except Exception as e:
        print(f"OpenPhish 抓取失敗: {e}", file=sys.stderr)
    return urls


def fetch_urlhaus():
    urls = set()
    try:
        resp = requests.get(URLHAUS_URL, timeout=30)
        resp.raise_for_status()
        lines = [l for l in resp.text.splitlines() if l and not l.startswith("#")]
        reader = csv.reader(lines)
        for row in reader:
            # 欄位: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
            if len(row) >= 3:
                url = row[2].strip('"').strip()
                if url:
                    urls.add((url, "urlhaus"))
        print(f"URLhaus: 抓到 {len(urls)} 筆")
    except Exception as e:
        print(f"URLhaus 抓取失敗: {e}", file=sys.stderr)
    return urls


def load_history():
    seen = set()
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                seen.add(row["url"])
    return seen


def main():
    os.makedirs("data", exist_ok=True)

    combined = set()
    combined |= fetch_openphish()
    combined |= fetch_urlhaus()

    if not combined:
        print("兩個來源都抓取失敗，中止。", file=sys.stderr)
        sys.exit(1)

    already_seen = load_history()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    new_rows = []
    new_urls_for_analysis = []
    # 同一個 url 可能同時來自兩個來源，合併來源標籤
    url_sources = {}
    for url, source in combined:
        url_sources.setdefault(url, set()).add(source)

    for url, sources in url_sources.items():
        if url not in already_seen:
            new_rows.append({
                "url": url,
                "source": "|".join(sorted(sources)),
                "first_seen": now,
            })
            new_urls_for_analysis.append(url)

    # 寫回歷史檔（append，不覆蓋）
    file_exists = os.path.exists(HISTORY_FILE)
    with open(HISTORY_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "source", "first_seen"])
        if not file_exists:
            writer.writeheader()
        writer.writerows(new_rows)

    # 寫這次新增的網址，給 analyze_asn.py 用
    with open(NEW_THIS_RUN_FILE, "w", encoding="utf-8") as f:
        for url in new_urls_for_analysis:
            f.write(url + "\n")

    print(f"\n本次抓取合計 {len(url_sources)} 筆（去重後）")
    print(f"新增 {len(new_rows)} 筆寫入歷史檔 {HISTORY_FILE}")
    print(f"待分析網址寫入 {NEW_THIS_RUN_FILE}")


if __name__ == "__main__":
    main()
