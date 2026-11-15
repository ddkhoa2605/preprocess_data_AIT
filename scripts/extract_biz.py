"""Trích alert Suricata '.biz TLD' từ <scenario>_wazuh.json ra CSV."""
import json, sys, csv
src, out = sys.argv[1], sys.argv[2]
with open(src, encoding="utf-8") as f, open(out, "w", newline="", encoding="utf-8") as o:
    w = csv.writer(o); w.writerow(["ts","rrname","src_ip","src_port","dest_ip","dest_port","agent_ip","location","dns_type"])
    for line in f:
        if ".biz TLD" not in line: continue
        j = json.loads(line); d = j.get("data", {})
        dns = d.get("dns", {}); q = dns.get("query", [{}])
        w.writerow([d.get("timestamp"), q[0].get("rrname"), d.get("src_ip"), d.get("src_port"), d.get("dest_ip"), d.get("dest_port"),
                    j["agent"].get("ip"), j.get("location"), q[0].get("type")])
