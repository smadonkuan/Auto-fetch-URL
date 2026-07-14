"""
讀取 data/analysis_history.csv，統計出 ASN / 國家 / 新網域 / IP與ASN反查歷史等資訊，
並把結果寫回 README.md 中 <!-- DASHBOARD:START --> ~ <!-- DASHBOARD:END --> 之間。
"""

import csv
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone

ANALYSIS_FILE = "data/analysis_history.csv"
HISTORY_FILE = "data/urls_history.csv"
README_FILE = "README.md"

START_MARK = "<!-- DASHBOARD:START -->"
END_MARK = "<!-- DASHBOARD:END -->"

TOP_N = 10


def load_rows(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def build_table(counter, headers, top_n=TOP_N):
    lines = [f"| {headers[0]} | {headers[1]} |", "|---|---|"]
    if not counter:
        lines.append("| (尚無資料) | - |")
        return "\n".join(lines)
    for name, count in counter.most_common(top_n):
        name = name if name else "(未知)"
        lines.append(f"| {name} | {count} |")
    return "\n".join(lines)


def build_first_seen_table(rows, key_field, top_n=TOP_N):
    """依 key_field（ip 或 asn）分組，算出首次出現時間與命中次數，依命中次數排序"""
    groups = defaultdict(list)
    for r in rows:
        key = r.get(key_field)
        if key and key != "解析失敗":
            groups[key].append(r.get("analyzed_at", ""))

    stats = []
    for key, seen_times in groups.items():
        seen_times_sorted = sorted(t for t in seen_times if t)
        first_seen = seen_times_sorted[0] if seen_times_sorted else "(未知)"
        stats.append((key, len(seen_times), first_seen))

    stats.sort(key=lambda x: x[1], reverse=True)

    label = "ASN" if key_field == "asn" else "IP"
    lines = [f"| {label} | 累積命中次數 | 首次出現時間 |", "|---|---|---|"]
    if not stats:
        lines.append("| (尚無資料) | - | - |")
        return "\n".join(lines)
    for key, count, first_seen in stats[:top_n]:
        lines.append(f"| {key} | {count} | {first_seen} |")
    return "\n".join(lines)


def build_new_domain_table(rows, top_n=TOP_N):
    """挑出 is_new_domain 為 True 的網域，依註冊天數由新到舊排序，同網域只留一筆"""
    seen_domains = {}
    for r in rows:
        if str(r.get("is_new_domain", "")).lower() == "true":
            domain = r.get("domain")
            age = r.get("domain_age_days", "")
            created = r.get("domain_created", "")
            if domain and domain not in seen_domains:
                try:
                    age_val = int(age)
                except (ValueError, TypeError):
                    age_val = 9999
                seen_domains[domain] = (age_val, created, r.get("url", ""))

    items = sorted(seen_domains.items(), key=lambda x: x[1][0])

    lines = ["| 網域 | 註冊日期 | 註冊天數 | 對應網址 |", "|---|---|---|---|"]
    if not items:
        lines.append("| (目前無新註冊網域) | - | - | - |")
        return "\n".join(lines)
    for domain, (age_val, created, url) in items[:top_n]:
        lines.append(f"| {domain} | {created} | {age_val} 天 | {url} |")
    return "\n".join(lines)


def main():
    analysis_rows = load_rows(ANALYSIS_FILE)
    history_rows = load_rows(HISTORY_FILE)

    total_urls = len(history_rows)
    total_analyzed = len(analysis_rows)
    unique_domains = len({r["domain"] for r in analysis_rows if r.get("domain")})
    unique_ips = len({r["ip"] for r in analysis_rows if r.get("ip") and r["ip"] != "解析失敗"})
    unique_asns = len({r["asn"] for r in analysis_rows if r.get("asn")})
    failed_resolve = sum(1 for r in analysis_rows if r.get("ip") == "解析失敗")
    new_domain_count = sum(1 for r in analysis_rows if str(r.get("is_new_domain", "")).lower() == "true")

    asn_counter = Counter(r["asn"] for r in analysis_rows if r.get("asn"))
    country_counter = Counter(r["country"] for r in analysis_rows if r.get("country"))
    org_counter = Counter(r["org"] for r in analysis_rows if r.get("org"))

    asn_table = build_table(asn_counter, ["ASN", "命中次數"])
    country_table = build_table(country_counter, ["國家", "命中次數"])
    org_table = build_table(org_counter, ["Org / 機房", "命中次數"])
    new_domain_table = build_new_domain_table(analysis_rows)
    ip_history_table = build_first_seen_table(analysis_rows, "ip")
    asn_history_table = build_first_seen_table(analysis_rows, "asn")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    dashboard = f"""{START_MARK}
## 📊 釣魚網址情資 Dashboard

> 最後更新：{now}（每小時自動更新，資料來源：OpenPhish + URLhaus）

| 指標 | 數值 |
|---|---|
| 歷史累積網址總數 | {total_urls} |
| 已完成 IP/ASN 分析 | {total_analyzed} |
| 不重複網域數 | {unique_domains} |
| 不重複 IP 數 | {unique_ips} |
| 不重複 ASN 數 | {unique_asns} |
| DNS 解析失敗數 | {failed_resolve} |
| 新註冊網域（&lt;7 天）累積數 | {new_domain_count} |

<details>
<summary>🚨 新註冊網域清單（&lt;7 天，風險較高）</summary>

{new_domain_table}

</details>

<details>
<summary>🔝 Top {TOP_N} ASN（依命中次數，濫用機房排行）</summary>

{asn_table}

</details>

<details>
<summary>🌍 Top {TOP_N} 國家（依命中次數，地理分布）</summary>

{country_table}

</details>

<details>
<summary>🏢 Top {TOP_N} Org / 機房（依命中次數）</summary>

{org_table}

</details>

<details>
<summary>🔁 IP 反查歷史（首次出現時間 + 重複命中次數）</summary>

{ip_history_table}

</details>

<details>
<summary>🔁 ASN 反查歷史（首次出現時間 + 重複命中次數）</summary>

{asn_history_table}

</details>

完整資料請見 [`data/analysis_history.csv`](data/analysis_history.csv)。
{END_MARK}"""

    if not os.path.exists(README_FILE):
        content = f"# 釣魚網址情資追蹤\n\n{dashboard}\n"
    else:
        with open(README_FILE, "r", encoding="utf-8") as f:
            content = f.read()

        if START_MARK in content and END_MARK in content:
            before = content.split(START_MARK)[0]
            after = content.split(END_MARK)[1]
            content = before + dashboard + after
        else:
            content = content.rstrip() + "\n\n" + dashboard + "\n"

    with open(README_FILE, "w", encoding="utf-8") as f:
        f.write(content)

    print("README.md Dashboard 已更新")


if __name__ == "__main__":
    main()
