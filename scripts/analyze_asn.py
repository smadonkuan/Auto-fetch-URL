"""
讀取 data/new_this_run.txt（本次新增的網址），解析 IP/ASN + WHOIS 註冊資訊，
並把結果 append 進 data/analysis_history.csv（累積歷史，不覆蓋）。

新增欄位：
- domain_created: 網域註冊日期（WHOIS，查不到則空白）
- domain_age_days: 網域註冊至今天數
- is_new_domain: 是否為新註冊網域（<7 天），True/False

同一個網域如果之前已經查過 WHOIS，會直接沿用快取結果，
不會重複打 WHOIS（省時間也避免被限速）。
"""

import csv
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

try:
    import whois as whois_lib
except ImportError:
    whois_lib = None

INPUT_FILE = "data/new_this_run.txt"
OUTPUT_FILE = "data/analysis_history.csv"

FIELDNAMES = [
    "url", "domain", "ip", "asn", "isp", "org",
    "country", "region", "city",
    "domain_created", "domain_age_days", "is_new_domain",
    "analyzed_at",
]

NEW_DOMAIN_THRESHOLD_DAYS = 7

# ip-api.com 免費版限制約 45 次/分鐘，保守一點設 1.5 秒間隔
IPAPI_THROTTLE_SECONDS = 1.5
# WHOIS 伺服器限速更嚴格，且不同 TLD 各自為政，保守一點設 3 秒間隔
WHOIS_THROTTLE_SECONDS = 3


def extract_domain(url):
    url = url.strip()
    if not url:
        return None
    if not re.match(r'^https?://', url):
        url = 'http://' + url
    parsed = urlparse(url)
    return parsed.hostname


def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def get_asn_info(ip, retries=2):
    for attempt in range(retries + 1):
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,regionName,city,isp,org,as,query"},
                timeout=10,
            )
            data = resp.json()
            if data.get("status") == "success":
                return data
            return {}
        except Exception as e:
            if attempt < retries:
                time.sleep(2)
                continue
            print(f"ASN 查詢失敗 {ip}: {e}", file=sys.stderr)
    return {}


def get_domain_whois(domain):
    """回傳 (domain_created_str, age_days, is_new_domain)，查不到時回傳 (None, None, None)"""
    if whois_lib is None:
        return None, None, None
    try:
        w = whois_lib.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0] if created else None
        if created is None:
            return None, None, None
        if isinstance(created, str):
            # 少數情況 WHOIS 回傳字串而非 datetime，盡量做基本解析
            created = datetime.strptime(created[:10], "%Y-%m-%d")
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - created).days
        is_new = age_days < NEW_DOMAIN_THRESHOLD_DAYS
        return created.strftime("%Y-%m-%d"), age_days, is_new
    except Exception as e:
        print(f"WHOIS 查詢失敗 {domain}: {e}", file=sys.stderr)
        return None, None, None


def load_whois_cache():
    """從既有歷史檔載入 domain -> (created, age_days, is_new) 快取，避免重查已知網域"""
    cache = {}
    if not os.path.exists(OUTPUT_FILE):
        return cache
    with open(OUTPUT_FILE, "r", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            domain = row.get("domain")
            created = row.get("domain_created")
            if domain and created and domain not in cache:
                cache[domain] = (
                    created,
                    row.get("domain_age_days"),
                    row.get("is_new_domain"),
                )
    return cache


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"{INPUT_FILE} 不存在，可能這次沒有新網址，跳過分析。")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]

    if not urls:
        print("沒有新網址需要分析。")
        return

    if whois_lib is None:
        print("警告：未安裝 python-whois，將跳過網域註冊日期查詢。", file=sys.stderr)

    os.makedirs("data", exist_ok=True)
    file_exists = os.path.exists(OUTPUT_FILE)
    whois_cache = load_whois_cache()

    with open(OUTPUT_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        if not file_exists:
            writer.writeheader()

        for i, url in enumerate(urls):
            domain = extract_domain(url)
            if not domain:
                continue

            ip = resolve_ip(domain)
            info = get_asn_info(ip) if ip else {}

            if domain in whois_cache:
                created, age_days, is_new = whois_cache[domain]
            else:
                created, age_days, is_new = get_domain_whois(domain)
                whois_cache[domain] = (created, age_days, is_new)
                time.sleep(WHOIS_THROTTLE_SECONDS)  # 只有真的查了才需要節流

            row = {
                "url": url,
                "domain": domain,
                "ip": ip or "解析失敗",
                "asn": info.get("as", ""),
                "isp": info.get("isp", ""),
                "org": info.get("org", ""),
                "country": info.get("country", ""),
                "region": info.get("regionName", ""),
                "city": info.get("city", ""),
                "domain_created": created or "",
                "domain_age_days": age_days if age_days is not None else "",
                "is_new_domain": is_new if is_new is not None else "",
                "analyzed_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            }
            writer.writerow(row)

            flag = " 🚨新註冊網域" if is_new else ""
            print(f"[{i+1}/{len(urls)}] {domain} -> {ip} -> {info.get('as', '(無ASN資料)')} "
                  f"| 註冊日:{created or '(無資料)'}{flag}")

            if ip:  # 只有真的打了 ip-api 才需要節流
                time.sleep(IPAPI_THROTTLE_SECONDS)

    print(f"\n完成，共分析 {len(urls)} 筆，累積結果於 {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
