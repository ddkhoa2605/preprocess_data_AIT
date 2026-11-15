"""So sánh time_label và event_label trong file alert CSV của AIT Alert Data Set.

Dùng:  python compare_labels.py <alerts.txt> [--out mismatches.csv] [--gap 1800] [--n 100]
"""
import argparse
import sys

import pandas as pd

NEG_TIME = "false_positive"
NEG_EVENT = "-"


def section(title):
    print("\n" + "=" * 78 + "\n" + title + "\n" + "=" * 78)


def clusters(df, gap):
    """Gom cụm theo (name, host, ip); nếu gap>0 thì tách cụm khi hai alert liền nhau cách > gap giây."""
    d = df.sort_values(["name", "host", "ip", "time"]).copy()
    key = d["name"] + "|" + d["host"] + "|" + d["ip"]
    new = key.ne(key.shift())
    if gap > 0:
        new |= d["time"].diff().gt(gap)
    d["cid"] = new.cumsum()
    g = d.groupby("cid").agg(n=("time", "size"),
                              ev_atk=("ev_atk", "sum"),
                              tm_atk=("tm_atk", "sum"),
                              detector=("detector", "first"))
    g["ev_mixed"] = (g.ev_atk > 0) & (g.ev_atk < g.n)
    g["ev_attack"] = g.ev_atk > 0
    g["tm_attack"] = g.tm_atk > 0
    return g


def cluster_report(g, label):
    print(f"\n[{label}]")
    print(f"  Số cụm: {len(g):,}   (alert/cụm trung vị {g.n.median():.0f}, max {g.n.max():,})")
    print(f"  Cụm có tấn công theo event_label: {g.ev_attack.sum():,}   "
          f"theo time_label: {g.tm_attack.sum():,}")
    print(f"  Cụm lẫn (vừa tấn công vừa không, theo event_label): {g.ev_mixed.sum():,}")
    print(f"  Cụm time_label=tấn công nhưng event_label không có alert tấn công nào: "
          f"{(g.tm_attack & ~g.ev_attack).sum():,}")
    print("  Theo detector (cụm / cụm tấn công event_label):")
    for det, s in g.groupby("detector"):
        print(f"    {det:<10} {len(s):>6,} / {s.ev_attack.sum():>5,}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--out", default="mismatches.csv")
    ap.add_argument("--gap", type=int, default=1800, help="ngưỡng tách cụm theo thời gian (giây)")
    ap.add_argument("--n", type=int, default=100, help="số dòng mẫu mỗi kiểu lệch")
    a = ap.parse_args()

    df = pd.read_csv(a.csv, dtype=str, keep_default_na=False)
    df["time"] = df["time"].astype(int)
    df["detector"] = df["name"].str.split(":").str[0]
    df["tm_atk"] = df.time_label.ne(NEG_TIME)
    df["ev_atk"] = df.event_label.ne(NEG_EVENT)

    # 0. Tổng quan
    section("0. TỔNG QUAN")
    t0, t1 = pd.to_datetime(df.time.min(), unit="s"), pd.to_datetime(df.time.max(), unit="s")
    print(f"File: {a.csv}\nSố alert: {len(df):,}   Thời gian (UTC): {t0} -> {t1}")
    print(df.detector.value_counts().rename("alerts").to_string())
    if not df.ev_atk.any():
        print("\nCHÚ Ý: event_label toàn là '-'. event_label chưa được bật (xem Bước 3).")

    # 1. Phân phối nhãn
    section("1. PHÂN PHỐI NHÃN")
    print("time_label:\n" + df.time_label.value_counts().to_string())
    print("\nevent_label:\n" + df.event_label.value_counts().to_string())

    # 2. Bảng chéo nhị phân
    section("2. BẢNG CHÉO (tấn công / không)")
    ct = pd.crosstab(df.tm_atk.map({True: "time=attack", False: "time=benign"}),
                     df.ev_atk.map({True: "event=attack", False: "event=benign"}), margins=True)
    print(ct.to_string())
    A = df[df.tm_atk & ~df.ev_atk]
    B = df[~df.tm_atk & df.ev_atk]
    agree = 1 - (len(A) + len(B)) / len(df)
    print(f"\nTỉ lệ khớp: {agree:.2%}")
    print(f"Kiểu A (time=attack, event='-'): {len(A):,}  "
          f"= {len(A)/max(df.tm_atk.sum(),1):.2%} số alert time_label gọi là tấn công")
    print(f"Kiểu B (time=false_positive, event=attack): {len(B):,}  "
          f"= {len(B)/max(df.ev_atk.sum(),1):.2%} số alert event_label gọi là tấn công")
    tp = (df.tm_atk & df.ev_atk).sum()
    print(f"Nếu coi event_label là đáp án: precision time_label = {tp/max(df.tm_atk.sum(),1):.2%}, "
          f"recall = {tp/max(df.ev_atk.sum(),1):.2%}")
    print("\nTheo detector (A / B / tổng):")
    for det, s in df.groupby("detector"):
        print(f"  {det:<10} A={(s.tm_atk & ~s.ev_atk).sum():>5,}  B={(~s.tm_atk & s.ev_atk).sum():>5,}  "
              f"n={len(s):>6,}")

    # 3. Tên alert gây lệch
    section("3. TÊN ALERT GÂY LỆCH")
    print("Top kiểu A:\n" + A.name.value_counts().head(15).to_string())
    print("\nTop kiểu B:\n" + (B.name.value_counts().head(15).to_string() if len(B) else "(không có)"))

    # 4. Theo bước tấn công
    section("4. THEO BƯỚC TẤN CÔNG (time_label × event_label)")
    print(pd.crosstab(df.time_label, df.event_label).to_string())

    # 5. Cấp cụm
    section("5. CẤP CỤM (gần đúng: name + host + ip)")
    cluster_report(clusters(df, 0), "Không tách theo thời gian")
    cluster_report(clusters(df, a.gap), f"Tách khi cách nhau > {a.gap}s")

    # 6. Ghi mẫu
    section("6. FILE MẪU LỆCH")
    cols = ["time", "name", "ip", "host", "short", "time_label", "event_label"]
    samp = []
    for kind, part in (("A", A), ("B", B)):
        if len(part):
            s = part.sample(min(a.n, len(part)), random_state=0).sort_values("time")[cols].copy()
            s.insert(0, "kind", kind)
            s.insert(2, "time_utc", pd.to_datetime(s.time, unit="s"))
            samp.append(s)
    if samp:
        pd.concat(samp).to_csv(a.out, index=False)
        print(f"Đã ghi {sum(len(s) for s in samp)} dòng vào {a.out}")
    else:
        print("Không có dòng lệch.")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
