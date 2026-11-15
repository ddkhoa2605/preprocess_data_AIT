# Tiền xử lý và kiểm tra nhãn AIT Alert Data Set

Repo này phân tích bộ dữ liệu [AIT Alert Data Set (AIT-ADS)](https://github.com/ait-aecid/alert-data-set) để trả lời ba câu hỏi trước khi dùng nó làm dữ liệu train/test cho sản phẩm pre-triage alert:

1. Nên dùng nhãn nào làm đáp án: `time_label` hay `event_label`?
2. Nhãn đó có sai ở đâu không?
3. Có đủ **100 cụm tấn công** trong tập test (3 kịch bản) không?

Kết quả đầy đủ, kèm số liệu và giải thích, nằm trong [test_data.md](test_data.md). README này chỉ hướng dẫn cách lấy dữ liệu, chạy lại và đọc kết quả.

## Kết luận nhanh

- **Dùng `event_label`, không dùng `time_label`.** `time_label` gán theo khung giờ nên gọi nhầm nhiễu nền là tấn công, và bỏ sót cả vụ exfiltration DNS (dnsteal) ở harrison và santos.
- **`event_label` vẫn sót ít nhất 137 alert Nmap**, vì code gán nhãn của AIT không có file nhãn cho một số host. Sửa lại thì số cụm tấn công tăng từ 167 lên 201 trên cả 8 kịch bản.
- **3 kịch bản test không đạt 100 cụm** (tối đa 93). Cần 4 kịch bản (38/70 tổ hợp đạt) hoặc đổi cách chấm.
- **Phải bỏ AMiner và khử trùng lặp** (`fast.log`, `mail.info`), nếu không số liệu bị phồng. Tổng cộng 17,1% alert bị loại.
- **Điểm mù của IDS:** bước webshell và crack_passwords có 0 cụm ở mọi kịch bản, vì chỉ AMiner phát hiện được hai bước này.

## Cấu trúc repo

```
.
├── README.md
├── test_data.md              # Báo cáo kết quả chính (đọc file này)
├── compare_labels.py         # Bản phân tích đầu tiên trên CSV của AIT (còn tính AMiner, chỉ để tham khảo)
├── mismatches.csv            # 104 alert lệch nhãn của russellmitchell, sinh từ compare_labels.py
├── scripts/
│   ├── build_wazuh_table.py  # Bước 1: ghép JSON gốc với nhãn, ra parquet
│   ├── extract_biz.py        # Bước 1b: trích alert DNS ".biz" (dnsteal)
│   ├── scope_analysis.py     # Bước 2: khử trùng lặp, gom cụm, đếm
│   └── export_viz_data.py    # Bước 3: xuất CSV cho dashboard
├── out/                      # Kết quả của scope_analysis.py
└── viz_data/                 # Kết quả của export_viz_data.py + dashboard (index.html)
```

Hai thư mục **không có trong repo** vì quá lớn, phải tự tải (xem mục tiếp theo):

| Thư mục | Kích thước | Nội dung |
|---|---|---|
| `alert-data-set/` | ~260 MB | Repo của AIT, chứa CSV nhãn |
| `data_raw/` | ~2,8 GB | Alert JSON gốc từ Zenodo và các file trung gian |

## Lấy dữ liệu

### 1. CSV nhãn: repo `alert-data-set` của AIT

```bash
git clone https://github.com/ait-aecid/alert-data-set.git
cd alert-data-set/alerts_csv
unzip alerts_csv.zip -d alerts_csv
```

Sau bước này phải có các file `alert-data-set/alerts_csv/alerts_csv/<kịch bản>_alerts.txt`. Mỗi file là CSV 7 cột `time,name,ip,host,short,time_label,event_label`, gồm alert của cả AMiner, Wazuh và Suricata. `event_label` đã có sẵn, không cần chạy lại `analyze.py` của AIT.

### 2. Alert JSON gốc: Zenodo

Tải `ait_ads.zip` từ Zenodo, [record 8263181](https://zenodo.org/records/8263181) (khoảng 96 MB nén, 2,9 GB giải nén), rồi giải nén vào `data_raw/ait_ads/`:

```bash
mkdir -p data_raw/ait_ads
# đặt ait_ads.zip vào data_raw/ait_ads/ rồi:
unzip data_raw/ait_ads/ait_ads.zip -d data_raw/ait_ads
```

Repo chỉ dùng 8 file `*_wazuh.json` (mỗi dòng là một alert JSON):

```
data_raw/ait_ads/fox_wazuh.json
data_raw/ait_ads/harrison_wazuh.json
data_raw/ait_ads/russellmitchell_wazuh.json
data_raw/ait_ads/santos_wazuh.json
data_raw/ait_ads/shaw_wazuh.json
data_raw/ait_ads/wardbeck_wazuh.json
data_raw/ait_ads/wheeler_wazuh.json
data_raw/ait_ads/wilson_wazuh.json
```

Nếu file giải nén ra nằm trong thư mục con, chuyển chúng lên đúng đường dẫn trên.

## Cài đặt

Cần Python 3.10 trở lên, cùng `pandas` và `pyarrow` (để đọc/ghi parquet). Repo đã được chạy với pandas 2.2.3 và pyarrow 19.0.0.

```bash
pip install pandas pyarrow
```

## Chạy lại từ đầu

Tất cả lệnh chạy từ thư mục gốc của repo. Bash:

```bash
mkdir -p data_raw/tables
LBL=alert-data-set/alerts_csv/alerts_csv

# Bước 1: ghép JSON gốc với nhãn cho cả 8 kịch bản, ra data_raw/tables/<kịch bản>.parquet
for s in fox harrison russellmitchell santos shaw wardbeck wheeler wilson; do
  python -I scripts/build_wazuh_table.py data_raw/ait_ads/${s}_wazuh.json $LBL/${s}_alerts.txt data_raw/tables/${s}.parquet
done

# Bước 1b: trích alert ".biz" cho hai kịch bản có dnsteal
for s in harrison santos; do
  python -I scripts/extract_biz.py data_raw/ait_ads/${s}_wazuh.json data_raw/${s}_biz.csv
done

# Bước 2: khử trùng lặp, gom cụm, in bảng tóm tắt, ghi vào out/
python -I scripts/scope_analysis.py data_raw/tables --gap 1800 --out-dir out

# Bước 3: xuất CSV cho dashboard vào viz_data/
python -I scripts/export_viz_data.py
```

Mỗi kịch bản ở bước 1 chạy mất vài chục giây đến vài phút, vì file JSON lớn (tới vài trăm MB).

### Mỗi bước làm gì

**Bước 1: [scripts/build_wazuh_table.py](scripts/build_wazuh_table.py).** File JSON gốc có đầy đủ trường (rule id, location, src_ip, log…) nhưng không có nhãn. File CSV của AIT có nhãn nhưng ít trường. Script ghép hai file theo **thứ tự dòng**, vì `analyze.py` của AIT ghi CSV theo đúng thứ tự đọc JSON. Dòng AMiner được bỏ khỏi CSV trước khi ghép. Script dừng với lỗi nếu số dòng lệch hoặc agent IP không khớp từng dòng; cả 8 kịch bản đều qua kiểm tra này.

**Bước 1b: [scripts/extract_biz.py](scripts/extract_biz.py).** Lấy các alert Suricata "DNS Query to .biz TLD", là dấu vết của công cụ dnsteal, để vẽ đồ thị theo giờ.

**Bước 2: [scripts/scope_analysis.py](scripts/scope_analysis.py).** Áp quy tắc phạm vi sản phẩm rồi tính số liệu.

- Bỏ `/var/log/suricata/fast.log`: bản sao 1:1 của alert `eve.json`, luôn mang nhãn `-`.
- Bỏ `/var/log/mail.info`: rsyslog ghi cùng dòng Dovecot vào cả `mail.info` và `mail.log`.
- Gom cụm (xấp xỉ pre-triage) theo khóa `(rule_id, host, src_ip)`. Hai alert liền nhau cách quá `--gap` giây (mặc định 1800 = 30 phút) thì mở cụm mới.
- Một cụm là **cụm tấn công** nếu có ít nhất một alert có `event_label` khác `-`.

**Bước 3: [scripts/export_viz_data.py](scripts/export_viz_data.py).** Tính lại số liệu, sửa nhãn cho alert có dấu vết Nmap, rồi xuất 7 CSV vào `viz_data/`. Script này đọc đường dẫn cố định (`alert-data-set/...`, `data_raw/...`), nên phải giữ đúng cấu trúc thư mục ở trên.

## Đọc kết quả

### Khái niệm

| Thuật ngữ | Nghĩa |
|---|---|
| `time_label` | Nhãn theo khung giờ: alert nằm trong khung giờ của bước tấn công nào thì gán bước đó. `false_positive` nghĩa là không phải tấn công. |
| `event_label` | Nhãn theo sự kiện: AIT so khớp alert với log tấn công cụ thể. `-` nghĩa là không phải tấn công. |
| Kiểu A | `time_label` nói tấn công, `event_label` nói không. Thường là nhiễu nền trong giờ tấn công. |
| Kiểu B | `time_label` nói không, `event_label` nói tấn công. Chủ yếu là dnsteal. |
| Cụm | Nhóm alert cùng rule, host, IP nguồn, gần nhau về thời gian. Đơn vị dùng để đếm và chấm. |
| Kịch bản | Một trong 8 lần mô phỏng của AIT: fox, harrison, russellmitchell, santos, shaw, wardbeck, wheeler, wilson. |

### File kết quả

| File | Nội dung |
|---|---|
| [test_data.md](test_data.md) | Báo cáo đầy đủ: số liệu, giải thích, độ tin cậy, đề xuất chia tập. |
| [viz_data/scenario_stats.csv](viz_data/scenario_stats.csv) | Số liệu từng kịch bản: alert, độ khớp nhãn, kiểu A/B, số cụm, số cụm theo bước. |
| [viz_data/test_combos.csv](viz_data/test_combos.csv) | Tổng cụm tấn công của cả 56 tổ hợp 3 kịch bản test. |
| [viz_data/type_a_rules.csv](viz_data/type_a_rules.csv) | Rule gây lệch kiểu A, dùng làm ví dụ cho hướng dẫn gán nhãn. |
| [viz_data/russell_matrix.csv](viz_data/russell_matrix.csv) | Bảng chéo nhãn của russellmitchell ở 3 mức phạm vi. |
| [viz_data/biz_hourly.csv](viz_data/biz_hourly.csv), [viz_data/biz_marks.csv](viz_data/biz_marks.csv) | Số alert dnsteal theo giờ và các mốc thời gian để vẽ đồ thị. |
| [viz_data/cluster_definitions.csv](viz_data/cluster_definitions.csv) | Kiểm tra độ nhạy: số cụm theo 6 cách định nghĩa cụm. |
| [out/scope_summary.csv](out/scope_summary.csv) | Số liệu trước và sau khử trùng lặp. |
| [out/typeA_*.csv](out/) | Alert kiểu A theo rule, cho từng kịch bản. |

### Dashboard

[viz_data/index.html](viz_data/index.html) là dashboard dựng từ các CSV trên. Nó dùng biến CSS và thành phần của nền tảng dashboard nội bộ, nên **mở trực tiếp bằng trình duyệt có thể không hiển thị đúng**. Nguồn số liệu đáng tin là các file CSV và [test_data.md](test_data.md).

## Lưu ý

- [compare_labels.py](compare_labels.py) là bản phân tích đầu tiên, chạy thẳng trên CSV của AIT nên **còn tính AMiner và các bản sao**. Chỉ dùng nó để xem nhanh một kịch bản:
  ```bash
  python -I compare_labels.py alert-data-set/alerts_csv/alerts_csv/russellmitchell_alerts.txt --out mismatches.csv
  ```
  Khi đếm số liệu chính thức, hãy dùng các script trong `scripts/`.
- Cách sửa nhãn Nmap chỉ tìm chuỗi `nmap` trong log hoặc chữ ký Suricata, nên 137 là **cận dưới**.
- Cụm ở đây là xấp xỉ. Cụm thật do bước pre-triage của sản phẩm tạo ra và có thể khác.
- Các việc còn mở (kiểm tra tay mẫu cụm, chọn cách chia tập…) nằm ở mục 7 của [test_data.md](test_data.md).
