"""Tính lại số liệu nhãn theo phạm vi sản phẩm (chỉ _wazuh.json, không AMiner, đã khử trùng lặp).

Khử trùng lặp:
  - bỏ /var/log/suricata/fast.log: bản sao 1:1 của alert eve.json (rule 20100/20101/20151/20152/20162),
    và luôn có event_label='-' nên làm phồng kiểu A;
  - bỏ /var/log/mail.info: rsyslog ghi cùng dòng Dovecot vào cả mail.info và mail.log.

Cụm (xấp xỉ pre-triage): khóa (rule_id, host, src_ip nếu có), cắt cụm mới khi khoảng lặng > GAP giây.
Một cụm được tính cho bước X nếu chứa ≥1 alert có event_label = X.

Dùng: python -I scope_analysis.py <thư mục parquet> [--gap 1800] [--out-dir out]
"""
import argparse
import glob
import itertools
import os
import sys

import pandas as pd

DUP_LOCATIONS = {"/var/log/suricata/fast.log", "/var/log/mail.info"}
STEP_ORDER = ["service_scan", "wpscan", "dirb", "webshell_cmd", "crack_passwords",
              "attacker_change_user", "escalated_sudo_command", "dnsteal"]


def load(path):
    d = pd.read_parquet(path)
    d["tm_atk"] = d.time_label.ne("false_positive")
    d["ev_atk"] = d.event_label.ne("-")
    return d


def clusterize(d, gap):
    d = d.sort_values("time").copy()
    d["key"] = d.rule_id.astype(str) + "|" + d.host + "|" + d.src_ip.fillna("")
    d = d.sort_values(["key", "time"])
    new = d.key.ne(d.key.shift()) | d.time.diff().gt(gap)
    d["cid"] = new.cumsum()
    return d


def stats(d, gap):
    A = int((d.tm_atk & ~d.ev_atk).sum())
    B = int((~d.tm_atk & d.ev_atk).sum())
    tp = int((d.tm_atk & d.ev_atk).sum())
    c = clusterize(d, gap)
    g = c.groupby("cid").agg(n=("time", "size"), atk=("ev_atk", "sum"))
    steps = c[c.ev_atk].groupby("event_label").cid.nunique()
    return {
        "alerts": len(d), "ev_atk": int(d.ev_atk.sum()), "tm_atk": int(d.tm_atk.sum()),
        "agree": 1 - (A + B) / len(d), "A": A, "B": B,
        "precision_tm": tp / max(d.tm_atk.sum(), 1), "recall_tm": tp / max(d.ev_atk.sum(), 1),
        "clusters": len(g), "atk_clusters": int((g.atk > 0).sum()),
        "mixed": int(((g.atk > 0) & (g.atk < g.n)).sum()),
        "atk_clusters_no_dnsteal": int(c[c.ev_atk & c.event_label.ne("dnsteal")].cid.nunique()),
        **{f"step:{s}": int(steps.get(s, 0)) for s in STEP_ORDER},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tables")
    ap.add_argument("--gap", type=int, default=1800)
    ap.add_argument("--out-dir", default="out")
    a = ap.parse_args()
    os.makedirs(a.out_dir, exist_ok=True)

    rows = []
    for p in sorted(glob.glob(os.path.join(a.tables, "*.parquet"))):
        s = os.path.basename(p)[:-8]
        d = load(p)
        for scope, sub in (("wazuh_raw", d), ("dedup", d[~d.location.isin(DUP_LOCATIONS)])):
            rows.append({"scenario": s, "scope": scope, **stats(sub, a.gap)})
        # Kiểu A còn lại sau khử trùng lặp, theo rule — dùng cho hướng dẫn gán nhãn
        dd = d[~d.location.isin(DUP_LOCATIONS)]
        (dd[dd.tm_atk & ~dd.ev_atk].groupby(["time_label", "name"]).size()
         .rename("n").reset_index().sort_values("n", ascending=False)
         .to_csv(os.path.join(a.out_dir, f"typeA_{s}.csv"), index=False))
    r = pd.DataFrame(rows)
    r.to_csv(os.path.join(a.out_dir, "scope_summary.csv"), index=False)

    pd.set_option("display.width", 250)
    pd.set_option("display.max_columns", 50)
    base = ["scenario", "alerts", "ev_atk", "agree", "A", "B", "precision_tm", "recall_tm"]
    for scope in ("wazuh_raw", "dedup"):
        print(f"\n=== {scope} ===")
        print(r[r.scope == scope][base].to_string(index=False, formatters={
            "agree": "{:.1%}".format, "precision_tm": "{:.1%}".format, "recall_tm": "{:.1%}".format}))
    dd = r[r.scope == "dedup"].set_index("scenario")
    print(f"\n=== Cụm (dedup, khóa rule_id+host+src_ip, khoảng lặng > {a.gap}s tách cụm) ===")
    print(dd[["clusters", "atk_clusters", "mixed", "atk_clusters_no_dnsteal"]].to_string())
    print("\n=== Số cụm theo bước tấn công (dedup) ===")
    print(dd[[f"step:{s}" for s in STEP_ORDER]].rename(columns=lambda x: x[5:]).to_string())

    print("\n=== Tổ hợp 3 kịch bản test: tổng cụm tấn công (dedup) ===")
    combos = []
    for c in itertools.combinations(dd.index, 3):
        combos.append((", ".join(c), dd.loc[list(c), "atk_clusters"].sum(),
                       dd.loc[list(c), "atk_clusters_no_dnsteal"].sum()))
    cb = pd.DataFrame(combos, columns=["combo", "atk", "atk_no_dnsteal"]).sort_values("atk")
    print(f"min={cb.atk.min()}  median={cb.atk.median():.0f}  max={cb.atk.max()}  "
          f"| không tính dnsteal: min={cb.atk_no_dnsteal.min()} max={cb.atk_no_dnsteal.max()}")
    print(f"Số tổ hợp đạt ≥100: {(cb.atk >= 100).sum()}/{len(cb)}  "
          f"(không tính dnsteal: {(cb.atk_no_dnsteal >= 100).sum()}/{len(cb)})")
    cb.to_csv(os.path.join(a.out_dir, "test_combos.csv"), index=False)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
