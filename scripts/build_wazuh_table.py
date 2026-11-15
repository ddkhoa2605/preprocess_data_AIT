"""Ghép <scenario>_wazuh.json (gốc) với <scenario>_alerts.txt (nhãn) theo đúng thứ tự dòng mà analyze.py ghi.
Đầu ra: parquet chỉ gồm alert trong _wazuh.json (Wazuh + Suricata do Wazuh thu), không có AMiner.
Dùng: python -I build_wazuh_table.py <wazuh.json> <alerts.txt> <out.parquet>
"""
import json, sys
import pandas as pd

src, csv, out = sys.argv[1:4]
rows = []
with open(src, encoding="utf-8") as f:
    for line in f:
        if "The average number" in line:      # analyze.py cũng bỏ các dòng này
            continue
        j = json.loads(line)
        r, d = j["rule"], j.get("data", {})
        alert = d.get("alert", {})
        rows.append((r.get("id"), r.get("level"), ",".join(r.get("groups", [])), j.get("location"),
                     j["agent"].get("ip"), d.get("flow_id"), d.get("src_ip"), d.get("dest_ip"),
                     alert.get("signature_id"), alert.get("signature"), j.get("full_log", "")[:300]))
js = pd.DataFrame(rows, columns=["rule_id", "level", "groups", "location", "agent_ip", "flow_id",
                                 "src_ip", "dest_ip", "sig_id", "signature", "full_log"])
lab = pd.read_csv(csv, dtype=str, keep_default_na=False)
lab = lab[~lab.name.str.startswith("AMiner")].reset_index(drop=True)
assert len(lab) == len(js), f"lệch số dòng: csv={len(lab)} json={len(js)}"
assert (lab.ip.values == js.agent_ip.values).all(), "agent ip không khớp theo thứ tự"
df = pd.concat([lab, js], axis=1)
df["time"] = df.time.astype(int)
df.to_parquet(out, index=False)
print(out, len(df))
