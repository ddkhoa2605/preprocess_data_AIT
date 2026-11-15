"""Xuất các bảng số liệu (đã kiểm tra lại) cho dashboard. Dùng: python -I scripts/export_viz_data.py"""
import glob
import itertools
import os
import sys

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
from scope_analysis import DUP_LOCATIONS, STEP_ORDER, clusterize, load  # noqa: E402

CSV_DIR = os.path.join(ROOT, "alert-data-set", "alerts_csv", "alerts_csv")
OUT = os.path.join(ROOT, "viz_data")
os.makedirs(OUT, exist_ok=True)
GAP = 1800


def nmap_mask(d):
    return d.full_log.str.contains("nmap", case=False, na=False) | d.signature.fillna("").str.contains("Nmap")


stats, matrix, typeA = [], [], []
for p in sorted(glob.glob(os.path.join(ROOT, "data_raw", "tables", "*.parquet"))):
    s = os.path.basename(p)[:-8]
    full = pd.read_csv(os.path.join(CSV_DIR, f"{s}_alerts.txt"), dtype=str, keep_default_na=False,
                       on_bad_lines="skip")
    full = full[full.time.str.isdigit()]
    raw = load(p)
    d = raw[~raw.location.isin(DUP_LOCATIONS)].copy()

    c = clusterize(d, GAP)
    atk_cl = c[c.ev_atk].cid.nunique()
    nm = nmap_mask(c)
    c2 = c.copy()
    c2.loc[nm, "ev_atk"] = True
    atk_cl_fixed = c2[c2.ev_atk].cid.nunique()
    steps = c[c.ev_atk].groupby("event_label").cid.nunique()

    A = int((d.tm_atk & ~d.ev_atk).sum())
    B = int((~d.tm_atk & d.ev_atk).sum())
    tp = int((d.tm_atk & d.ev_atk).sum())
    nmd = nmap_mask(d)
    stats.append({
        "scenario": s,
        "alerts_all_ids": len(full),
        "removed_aminer": int(full.name.str.startswith("AMiner").sum()),
        "removed_fastlog": int((raw.location == "/var/log/suricata/fast.log").sum()),
        "removed_mailinfo": int((raw.location == "/var/log/mail.info").sum()),
        "alerts_product": len(d),
        "attack_alerts": int(d.ev_atk.sum()),
        "agree_pct": round(100 * (1 - (A + B) / len(d)), 2),
        "type_a": A, "type_b": B,
        "precision_time_pct": round(100 * tp / max(int(d.tm_atk.sum()), 1), 1),
        "recall_time_pct": round(100 * tp / max(int(d.ev_atk.sum()), 1), 1),
        "attack_clusters": atk_cl,
        "attack_clusters_nmap_fixed": atk_cl_fixed,
        "nmap_labeled": int((nmd & d.ev_atk).sum()),
        "nmap_unlabeled": int((nmd & ~d.ev_atk).sum()),
        **{f"step_{k}": int(steps.get(k, 0)) for k in STEP_ORDER},
    })

    if s == "russellmitchell":
        for scope, sub in (("Cả 3 IDS (có AMiner)", full.assign(tm_atk=full.time_label.ne("false_positive"),
                                                                 ev_atk=full.event_label.ne("-"))),
                           ("_wazuh.json, chưa khử trùng", raw),
                           ("_wazuh.json, đã khử trùng", d)):
            matrix.append({"scope": scope,
                           "both_attack": int((sub.tm_atk & sub.ev_atk).sum()),
                           "type_a": int((sub.tm_atk & ~sub.ev_atk).sum()),
                           "type_b": int((~sub.tm_atk & sub.ev_atk).sum()),
                           "both_benign": int((~sub.tm_atk & ~sub.ev_atk).sum())})

    ta = d[d.tm_atk & ~d.ev_atk]
    ta = ta.assign(nmap=nmap_mask(ta))
    g = ta.groupby("name").agg(alerts=("time", "size"), nmap=("nmap", "sum")).reset_index()
    g = g.sort_values("alerts", ascending=False).head(8)
    for _, r in g.iterrows():
        typeA.append({"scenario": s, "rule": r["name"], "alerts": int(r.alerts),
                      "verdict": "Tấn công bị bỏ sót (Nmap)" if r.nmap > 0 else "Nhiễu nền"})

st = pd.DataFrame(stats)
st.to_csv(os.path.join(OUT, "scenario_stats.csv"), index=False)
pd.DataFrame(matrix).to_csv(os.path.join(OUT, "russell_matrix.csv"), index=False)
pd.DataFrame(typeA).to_csv(os.path.join(OUT, "type_a_rules.csv"), index=False)

# Tổ hợp 3 kịch bản test
v0 = st.set_index("scenario").attack_clusters
v1 = st.set_index("scenario").attack_clusters_nmap_fixed
rows = [{"combo": " + ".join(c), "attack_clusters": int(v0[list(c)].sum()),
         "attack_clusters_nmap_fixed": int(v1[list(c)].sum())}
        for c in itertools.combinations(st.scenario, 3)]
pd.DataFrame(rows).sort_values("attack_clusters_nmap_fixed").to_csv(os.path.join(OUT, "test_combos.csv"), index=False)

# Dòng thời gian .biz (chỉ bản eve.json, theo giờ, có cả giờ bằng 0)
SIM = {"harrison": ("2022-02-04", "2022-02-09"), "santos": ("2022-01-14", "2022-01-18")}
hourly = []
for s, (a, b) in SIM.items():
    e = pd.read_csv(os.path.join(ROOT, "data_raw", f"{s}_biz.csv"))
    e = e[e.location.str.contains("eve") & ~e.rrname.fillna("").str.contains("neustar|neuweb")]
    t = pd.to_datetime(e.ts.str[:19]).dt.floor("h")
    cnt = t.value_counts()
    for h in pd.date_range(a, b, freq="h", inclusive="left"):
        hourly.append({"scenario": s, "hour": h.strftime("%Y-%m-%dT%H:%M:%SZ"), "alerts": int(cnt.get(h, 0))})
pd.DataFrame(hourly).to_csv(os.path.join(OUT, "biz_hourly.csv"), index=False)
pd.DataFrame([
    {"scenario": "harrison", "event": "Chuỗi xâm nhập", "start": "2022-02-08T07:05:00Z", "end": "2022-02-08T08:37:26Z"},
    {"scenario": "harrison", "event": "service_stop", "start": "2022-02-08T09:14:59Z", "end": "2022-02-08T09:15:01Z"},
    {"scenario": "harrison", "event": "Khung dnsteal của time_label", "start": "2022-02-08T09:15:01Z", "end": "2022-02-08T11:15:01Z"},
    {"scenario": "santos", "event": "Chuỗi xâm nhập", "start": "2022-01-17T11:15:00Z", "end": "2022-01-17T11:58:59Z"},
    {"scenario": "santos", "event": "service_stop", "start": "2022-01-16T07:16:17Z", "end": "2022-01-16T07:16:19Z"},
    {"scenario": "santos", "event": "Khung dnsteal của time_label", "start": "2022-01-16T07:16:19Z", "end": "2022-01-16T08:16:19Z"},
]).to_csv(os.path.join(OUT, "biz_marks.csv"), index=False)

# Độ nhạy theo định nghĩa cụm (kết quả đã đo ở bước trước)
pd.DataFrame([
    {"definition": "rule + host + src_ip, lặng 5 phút", "combo_min": 52, "combo_max": 75},
    {"definition": "rule + host + src_ip, lặng 30 phút", "combo_min": 51, "combo_max": 73},
    {"definition": "rule + host + src_ip, không tách", "combo_min": 51, "combo_max": 73},
    {"definition": "rule + host, lặng 30 phút", "combo_min": 46, "combo_max": 59},
    {"definition": "host + src_ip, lặng 30 phút", "combo_min": 18, "combo_max": 39},
    {"definition": "chỉ src_ip, lặng 30 phút", "combo_min": 9, "combo_max": 18},
]).to_csv(os.path.join(OUT, "cluster_definitions.csv"), index=False)
print(st.to_string())
print(pd.DataFrame(matrix).to_string())
for f in sorted(os.listdir(OUT)):
    print(f, os.path.getsize(os.path.join(OUT, f)))
