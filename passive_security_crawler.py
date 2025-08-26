import argparse
import requests
from bs4 import BeautifulSoup
import time
import json
import csv
import tldextract

def crawl(url, max_pages, delay, respect_robots, out_prefix):
    visited = set()
    to_visit = [url]
    results = []

    while to_visit and len(visited) < max_pages:
        current = to_visit.pop(0)
        if current in visited:
            continue

        try:
            print(f"[+] Visiting {current}")
            response = requests.get(current, timeout=10)
            visited.add(current)

            # Extract info
            soup = BeautifulSoup(response.text, "html.parser")
            title = soup.title.string.strip() if soup.title else "No Title"
            results.append({
                "url": current,
                "status": response.status_code,
                "title": title,
                "content_length": len(response.text)
            })

            # Extract links
            for link in soup.find_all("a", href=True):
                href = link['href']
                if href.startswith("http"):
                    domain = tldextract.extract(href).registered_domain
                    if domain == tldextract.extract(url).registered_domain:
                        if href not in visited:
                            to_visit.append(href)

            time.sleep(delay)

        except Exception as e:
            print(f"[-] Error visiting {current}: {e}")

    # Save JSON
    with open(f"{out_prefix}.json", "w", encoding="utf-8") as jf:
        json.dump(results, jf, indent=4)

    # Save CSV
    with open(f"{out_prefix}.csv", "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=["url", "status", "title", "content_length"])
        writer.writeheader()
        writer.writerows(results)

    print(f"[✓] Reports saved as {out_prefix}.json and {out_prefix}.csv")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Passive Security Crawler")
    parser.add_argument("--url", required=True, help="Target website URL to crawl")
    parser.add_argument("--max-pages", type=int, default=50, help="Maximum number of pages to crawl")
    parser.add_argument("--delay", type=int, default=1, help="Delay between requests (seconds)")
    parser.add_argument("--respect-robots", type=bool, default=True, help="Respect robots.txt (not yet implemented)")
    parser.add_argument("--out-prefix", default="report", help="Prefix for output files")

    args = parser.parse_args()

    crawl(
        url=args.url,
        max_pages=args.max_pages,
        delay=args.delay,
        respect_robots=args.respect_robots,
        out_prefix=args.out_prefix
    )
