# Tổng hợp dữ liệu AIT Alert Data Set sau khi kiểm tra lại

Ngày chạy: 12/11/2026. Nguồn số liệu của tài liệu này là 7 file CSV trong [viz_data/](viz_data/), cũng là nguồn của dashboard. Mọi con số dưới đây đã được đối chiếu lại với các file đó.

## 1. Kết luận ngắn

1. **Dùng event_label làm nhãn chính, không dùng time_label.** Hai nhãn khớp nhau ở 98% alert của russellmitchell, nhưng chỗ lệch là chỗ quan trọng: time_label gán nhầm nhiễu nền thành tấn công (kiểu A) và bỏ sót cả một vụ exfiltration thật (kiểu B).
2. **event_label tốt hơn nhưng chưa sạch.** Nó bỏ sót ít nhất 137 alert Nmap, vì code gán nhãn của AIT không nạp file nhãn cho một số host. Vì vậy vẫn cần kiểm tra tay một mẫu.
3. **Chỉ tiêu 100 cụm tấn công trong 3 kịch bản test không đạt được.** Tốt nhất là 93 cụm, sau khi đã sửa nhãn Nmap. Với 4 kịch bản thì đạt ở 38/70 tổ hợp, với 5 kịch bản thì đạt ở mọi tổ hợp.
4. **Phạm vi phải là `_wazuh.json` đã khử trùng lặp.** Nếu để nguyên cả AMiner và các bản sao thì số cụm bị đội lên (113 thay vì tối đa 93) và số alert kiểu A bị phồng.
5. **Có hai điểm mù của IDS mà triage không sửa được:** bước webshell/cracking (0 cụm ở cả 8 kịch bản) và dnsteal ở 6/8 kịch bản. Phải ghi vào báo cáo như giới hạn của dữ liệu.

## 2. Dữ liệu được tạo thế nào (để tái lập)

| Bước | File | Việc làm |
|---|---|---|
| 1 | `alert-data-set/alerts_csv/alerts_csv/*_alerts.txt` | CSV của AIT: 7 cột `time,name,ip,host,short,time_label,event_label`, gồm cả AMiner, Wazuh và Suricata. event_label đã có sẵn, không cần chạy lại `analyze.py`. |
| 2 | `data_raw/ait_ads/*_wazuh.json` | Alert gốc từ Zenodo (record 8263181, 96 MB nén, 2,9 GB giải nén). |
| 3 | [scripts/build_wazuh_table.py](scripts/build_wazuh_table.py) | Ghép JSON gốc với nhãn theo thứ tự dòng, bỏ AMiner. Script kiểm tra số dòng và agent IP khớp từng dòng; cả 8 kịch bản đều qua. |
| 4 | [scripts/scope_analysis.py](scripts/scope_analysis.py) | Khử trùng lặp, gom cụm, đếm theo bước tấn công. |
| 5 | [scripts/export_viz_data.py](scripts/export_viz_data.py) | Xuất 7 CSV cho dashboard. |

Quy tắc phạm vi sản phẩm:
- Chỉ lấy alert trong `_wazuh.json` (Wazuh và Suricata do Wazuh thu), bỏ AMiner.
- Bỏ `/var/log/suricata/fast.log`: bản sao 1:1 của alert `eve.json`, luôn có event_label "-".
- Bỏ `/var/log/mail.info`: rsyslog ghi cùng dòng Dovecot vào cả `mail.info` và `mail.log`.
- Lọc theo **location**, không lọc theo group "ids", vì alert `eve.json` thật cũng thuộc group này.

Cụm (xấp xỉ pre-triage): khóa `(rule_id, host, src_ip)`, mở cụm mới khi hai alert liền nhau cách quá 30 phút. Cụm tấn công là cụm có ít nhất một alert với event_label khác "-".

## 3. Số liệu chính

### 3.1 Từng kịch bản (phạm vi sản phẩm, đã khử trùng lặp)

| Kịch bản | Alert cả 3 IDS | Alert phạm vi SP | Bị loại | Khớp nhãn | Kiểu A | Kiểu B | Precision time_label | Recall time_label |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| fox | 473.104 | 442.058 | 6,6% | 99,78% | 969 | 0 | 99,8% | 100% |
| harrison | 593.948 | 505.561 | 14,9% | 90,23% | 2.925 | **46.477** | 99,3% | 90,0% |
| russellmitchell | 45.544 | 27.458 | 39,7% | 98,12% | 516 | 0 | 93,7% | 100% |
| santos | 130.779 | 72.520 | 44,5% | **63,08%** | 1.067 | **25.707** | 87,9% | **23,2%** |
| shaw | 70.782 | 42.393 | 40,1% | 98,94% | 449 | 0 | 92,0% | 100% |
| wardbeck | 91.257 | 52.859 | 42,1% | 99,07% | 489 | 0 | 91,5% | 100% |
| wheeler | 616.161 | 519.974 | 15,6% | 99,83% | 880 | 0 | 99,8% | 100% |
| wilson | 634.246 | 538.054 | 15,2% | 99,45% | 2.933 | 0 | 99,3% | 100% |
| **Tổng** | 2.655.821 | 2.200.877 | **17,1%** | | | | | |

Precision/recall của time_label tính với event_label làm đáp án. Kiểu A là time_label gọi là tấn công nhưng event_label là "-". Kiểu B là ngược lại.

### 3.2 Số cụm tấn công

| Kịch bản | Theo event_label gốc | Sau khi sửa nhãn Nmap |
|---|---:|---:|
| fox | 21 | 27 |
| harrison | 20 | 22 |
| russellmitchell | 23 | 31 |
| santos | 22 | 25 |
| shaw | 12 | 12 |
| wardbeck | 19 | 22 |
| wheeler | 24 | 31 |
| wilson | 26 | 31 |
| **Cả 8** | **167** | **201** |

### 3.3 Số cụm theo bước tấn công (event_label gốc)

| Kịch bản | service_scan | wpscan | dirb | webshell_cmd | crack_passwords | change_user | escalated_sudo | dnsteal |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| fox | 10 | 6 | 7 | **0** | **0** | 2 | 3 | 0 |
| harrison | 8 | 6 | 7 | **0** | **0** | 2 | 4 | 2 |
| russellmitchell | 13 | 4 | 5 | **0** | **0** | 2 | 3 | 0 |
| santos | 7 | 5 | 5 | **0** | **0** | 2 | 4 | 2 |
| shaw | 0 | 5 | 5 | **0** | **0** | 2 | 4 | 0 |
| wardbeck | 6 | 7 | 5 | **0** | **0** | 2 | 4 | 0 |
| wheeler | 11 | 8 | 7 | **0** | **0** | 2 | 4 | 0 |
| wilson | 14 | 6 | 7 | **0** | **0** | 2 | 4 | 0 |
| **Cộng** | 69 | 47 | 48 | 0 | 0 | 16 | 30 | 4 |

Một cụm có thể chứa nhiều nhãn, nên tổng theo bước (214) lớn hơn tổng cụm (167).

### 3.4 Tổ hợp kịch bản test

| Số kịch bản test | Cụm ít nhất | Cụm nhiều nhất | Số tổ hợp đạt ≥100 |
|---|---:|---:|---:|
| 3 | 56 | 93 | **0/56** |
| 4 | 81 | 120 | 38/70 |
| 5 | 108 | 145 | 56/56 |

Ba kịch bản tốt nhất: russellmitchell + wheeler + wilson = 93. Bốn kịch bản tốt nhất: fox + russellmitchell + wheeler + wilson = 120; khi đó còn lại harrison, santos, shaw, wardbeck = 81 cụm cho train và validation.

## 4. Đọc dashboard: rút ra gì và tại sao

### 4.1 Phạm vi: AMiner và bản trùng chiếm 17,1% alert (6,6% đến 44,5% tùy kịch bản)

- **Thấy gì:** thanh phạm vi cho thấy fox, harrison, wheeler, wilson chỉ mất 7–16% vì chúng có rất nhiều alert Wazuh thật. russellmitchell, santos, shaw, wardbeck mất 40–45%.
- **Tại sao:** mỗi alert Suricata vào Wazuh hai lần (từ `eve.json` và `fast.log`), và Dovecot được ghi vào cả `mail.info` lẫn `mail.log`. Các kịch bản nhỏ ít alert thật hơn nên phần trùng chiếm tỉ trọng lớn hơn.
- **Hệ quả:** giữ bản `fast.log` thì sinh ra alert kiểu A giả (luôn mang nhãn "-") và cụm "lẫn" giả. Ví dụ russellmitchell có kiểu A là 1.057 khi tính cả 3 IDS, 854 khi chỉ bỏ AMiner, 516 sau khi khử trùng lặp.
- **Đối chiếu:** bỏ các rule Wazuh nhóm IDS thì russellmitchell còn đúng 23.116 alert Wazuh, trùng số trong paper CATS. Đây là bằng chứng cách đọc dữ liệu của nhóm đúng.

### 4.2 Hai nhãn: time_label sai ở hai hướng, event_label chủ yếu sai ở một hướng

- **Kiểu A (nhiễu nền gán nhầm là tấn công):** chủ yếu là đăng nhập Dovecot, Suricata TLS invalid và ClamAV. Chúng xảy ra trong khung giờ tấn công nhưng không liên quan. time_label chỉ dựa vào đồng hồ nên không phân biệt được.
- **Kiểu B (tấn công bị bỏ sót bởi time_label):** chỉ có ở harrison và santos, và gần như toàn bộ là exfiltration DNS (xem 4.3). Đây là lý do độ khớp của santos chỉ còn 63% và recall của time_label chỉ 23%.
- **Hệ quả:** nếu dùng time_label làm đáp án thì mọi chỉ số của sản phẩm trên santos đều sai, vì gần ba phần tư số alert tấn công bị tính là "bình thường".

### 4.3 dnsteal: time_label đặt khung giờ sai, event_label đúng

- **Thấy gì:** trên đồ thị theo giờ của harrison và santos, các alert ".biz" chạy đều từ phút đầu của dataset và **tắt đúng lúc service_stop**. Khung "dnsteal" của time_label nằm sau service_stop và không chứa alert nào.
- **Bằng chứng đây là tấn công thật:**
  - Tên miền có dạng mã hóa của công cụ dnsteal, ví dụ `…customers_2013.xlsx.db-21.greer.biz`.
  - Máy gửi là internal_share, chính file server chứa các file `customers_*.xlsx` và `payroll_*.xlsx`.
  - Code gán nhãn so khớp từng tên miền cụ thể, nên 10 truy vấn bình thường tới `neustar.biz` ở santos vẫn là "-".
- **Điều chưa biết:** vì sao exfiltration chạy trước chuỗi xâm nhập. Mô tả trên Zenodo không nói rõ. Kết luận dựa trên dữ liệu, không dựa trên tài liệu chính thức.
- **Hệ quả cho sản phẩm:** dnsteal là một nguồn đơn lẻ chạy liên tục, sinh hàng chục nghìn alert mỗi kịch bản (46.477 ở harrison, 25.707 ở santos) nhưng gom lại chỉ được 2 cụm. Nếu tính theo alert, nó át hết mọi bước khác; nếu tính theo cụm thì gần như không đáng kể. Phải báo cáo theo cụm.

### 4.4 event_label bỏ sót tấn công thật (Nmap)

- **Thấy gì:** biểu đồ Nmap cho thấy 137 alert có dấu vết Nmap rõ ràng (user-agent "Nmap Scripting Engine" hoặc chữ ký Suricata Nmap) nhưng bị gán "-". Có 180 alert Nmap được gán nhãn đúng. Riêng shaw không có alert Nmap nào.
- **Tại sao:** `analyze.py` chỉ nạp file nhãn cho một số log (intranet_server, dnsmasq, audit trên internal_share, monitoring). Request Nmap tới webserver, cloud_share và các máy mail không có file nhãn tương ứng nên mặc định "-".
- **Mức độ:** 137 là cận dưới, vì chỉ đếm alert có dấu vết Nmap rõ ràng. Sửa chúng thêm 34 cụm tấn công trên 8 kịch bản (167 → 201); russellmitchell tăng nhiều nhất, từ 23 lên 31.
- **Hệ quả:** nếu chấm sản phẩm bằng event_label chưa sửa, các cụm quét cổng sẽ bị tính là "bình thường" và sản phẩm bị phạt oan khi xếp chúng ở mức cao.

### 4.5 Số cụm và mục tiêu 100

- **Thấy gì:** mỗi kịch bản chỉ có 12–31 cụm tấn công, kể cả kịch bản có hàng trăm nghìn alert. Số alert không quyết định số cụm.
- **Tại sao:** chuỗi tấn công của AIT ngắn và lặp lại nhau: quét cổng, wpscan, dirb, một lần đổi user, vài lệnh sudo. Hàng trăm nghìn alert chỉ là cùng một hành vi lặp lại, nên gom thành vài cụm.
- **Kiểm tra độ nhạy:** thử 6 cách định nghĩa cụm (khóa khác nhau, khoảng lặng 5 phút/30 phút/không tách). Cách chi tiết nhất cho tối đa 75 cụm trong 3 kịch bản (theo event_label gốc); các cách gộp thô hơn cho ít hơn nhiều (host + src_ip: 18–39; chỉ src_ip: 9–18). Vậy 100 cụm không phải là vấn đề của cách đếm.
- **Hệ quả:** phải đổi thiết kế đánh giá, không phải đếm lại.

### 4.6 Điểm mù của IDS: webshell, cracking và dnsteal

- **Thấy gì:** hai cột webshell_cmd và crack_passwords là 0 ở cả 8 kịch bản, và dnsteal chỉ có ở harrison và santos.
- **Tại sao:** ở russellmitchell, các alert mang nhãn webshell_cmd, crack_passwords và dnsteal đều là của AMiner (ví dụ "High entropy in Apache Access request", bất thường CPU, truy vấn DNS bất thường). Sản phẩm không dùng AMiner nên không có dữ liệu. Chưa kiểm tra riêng từng kịch bản khác, nhưng bảng 3.3 cho kết quả 0 ở cả 8.
- **Hệ quả:** sản phẩm không thể được chấm trên các bước này. Đây là giới hạn của dữ liệu đầu vào, không phải lỗi của triage, và phải ghi vào báo cáo.

## 5. Độ tin cậy của các kết luận

| Kết luận | Mức chắc chắn | Cơ sở và giới hạn |
|---|---|---|
| Khử trùng lặp đúng | Cao | Đối chiếu từng dòng với JSON gốc; khớp 23.116 với CATS. |
| dnsteal ".biz" là tấn công thật | Cao | Tên miền, máy gửi, tên file bị tuồn đều rõ. Chưa biết lý do thời điểm. |
| event_label bỏ sót Nmap | Cao về hướng, trung bình về số lượng | 137 là cận dưới, và việc nhận diện dựa trên chuỗi "nmap" trong log. |
| Kiểu A còn lại là nhiễu nền | Trung bình | Mới đọc từng dòng nhóm web 400/403. Dovecot, TLS và ClamAV được kết luận từ tên rule và vị trí log, chưa đọc từng dòng. |
| Số cụm tấn công | Trung bình | Cụm là xấp xỉ. Cụm thật do pre-triage của sản phẩm tạo ra và có thể khác. |
| Cụm "chỉ chứa alert Nmap" được sửa đúng | Thấp | Sửa chỉ là quy tắc tối thiểu, chưa có ai đọc từng cụm. |

**Về dashboard:** trang được dựng từ chính 7 file CSV trong [viz_data/](viz_data/), nhưng ở phiên làm việc này nó chưa được xác nhận hiển thị đúng. Hệ thống không trả về báo cáo chạy nào, và bạn cũng báo chưa xem được. Hãy dùng tài liệu này và các file CSV làm nguồn đáng tin; dashboard chỉ để minh họa. Tiêu đề phần phạm vi trên dashboard ("Một phần lớn số alert…") hơi quá so với tổng 17,1%; con số đúng là trong bảng 3.1.

## 6. Áp dụng vào bài mới

Các đề xuất dưới đây suy ra từ số liệu ở trên. Tài liệu này giả định "bài mới" là vòng gán nhãn và đánh giá sản phẩm pre-triage; nếu khác, các mục 6.1–6.3 vẫn dùng được.

### 6.1 Nhãn và cách kiểm tra

1. **Nhãn chính là event_label, sau khi sửa Nmap.** Thay vì gán tay toàn bộ cụm, nhóm chỉ kiểm tra lại event_label.
2. **Kiểm tra tay một mẫu phân tầng 100–150 cụm của tập test**, theo ba loại:
   - **Cụm mang nhãn "-" nhưng nằm trong khung giờ tấn công**: ưu tiên cao nhất, vì đây là nơi event_label bỏ sót (lỗi Nmap).
   - **Cụm lẫn** (vừa có alert tấn công vừa không): mỗi kịch bản có 0–5 cụm loại này, là nơi ranh giới tấn công/bình thường mờ nhất.
   - **Cụm dnsteal** (harrison, santos): để xác nhận 2 cụm này đúng.
3. **Ngưỡng quyết định:** từ mẫu ước lượng tỉ lệ sai của event_label. Thấp (vài phần trăm) thì dùng event_label đã sửa cho toàn bộ tập; cao thì quay lại gán tay hết. Nên chốt ngưỡng trước khi xem kết quả.
4. **Ghi rõ đã kiểm tra bao nhiêu cụm và thuộc rule nào** khi báo cáo, để người đọc biết độ phủ.

### 6.2 Hướng dẫn gán nhãn cho người gán

Dùng làm ví dụ trong hướng dẫn (có sẵn ở [viz_data/type_a_rules.csv](viz_data/type_a_rules.csv) và [mismatches.csv](mismatches.csv)):

| Loại | Ví dụ rule | Cách xử lý |
|---|---|---|
| Nhiễu nền trong giờ tấn công | Dovecot Authentication Success, ClamAV database update, Suricata TLS invalid record/traffic và handshake message | Không phải tấn công, dù xảy ra trong khung giờ tấn công. |
| Tấn công bị event_label bỏ sót | Web server 400 error code, Apache forbidden access, Suricata Nmap, mà log chứa "Nmap Scripting Engine" | Là tấn công (quét cổng), dù event_label là "-". |
| Exfiltration DNS | Suricata "DNS Query to .biz TLD" từ internal_share | Là tấn công, kể cả khi nằm ngoài khung giờ. |

### 6.3 Quy tắc dữ liệu đầu vào

- Mọi lần nạp dữ liệu đều: bỏ AMiner, bỏ `fast.log`, bỏ `mail.info`. Dùng [scripts/build_wazuh_table.py](scripts/build_wazuh_table.py) và [scripts/scope_analysis.py](scripts/scope_analysis.py), không dùng `compare_labels.py` bản đầu (còn tính AMiner và bản sao).
- Commit thư mục `scripts/` vào repo của nhóm để số liệu tái lập được. Thư mục hiện tại không phải git repo nên chưa commit.

### 6.4 Chia tập train/validation/test

Ba kịch bản test không đủ 100 cụm, nên cần chọn một trong ba hướng. Đề xuất theo thứ tự ưu tiên:

| Hướng | Nội dung | Ưu | Nhược |
|---|---|---|---|
| **A. 4 kịch bản test** | Test: fox + russellmitchell + wheeler + wilson = 120 cụm. Train/val: harrison, santos, shaw, wardbeck = 81 cụm. | Đạt chỉ tiêu 100 cụm. | Train/val chỉ có 81 cụm; test và train có phân bố rule khác nhau (harrison và santos có dnsteal, test thì không). |
| B. Giữ 3 kịch bản, đổi đơn vị chấm | Chấm theo bước tấn công hoặc theo chuỗi tấn công thay vì theo cụm. | Không phải giảm train/val. | Phải định nghĩa lại chỉ số. |
| C. Giữ 3 kịch bản, báo cáo khoảng tin cậy rộng | Test 93 cụm, báo cáo rõ không đạt 100. | Đơn giản nhất. | Kết luận kém chắc. |

Đề xuất trước đó (santos làm validation, harrison làm test) vẫn dùng được về mặt nhãn, vì kiểu B ở hai kịch bản này là tấn công thật. Nhưng với 3 kịch bản test thì khó đạt 100 cụm (xem 3.4). Nếu theo hướng A, harrison và santos nằm trong train/val, nên tập test không có cụm dnsteal nào; điều này khớp với việc sản phẩm không chấm được bước đó.

### 6.5 Báo cáo kết quả

- **Báo cáo theo cụm, không theo alert.** dnsteal và wpscan/dirb sinh hàng chục nghìn alert nhưng chỉ vài cụm.
- **Báo cáo recall theo từng bước, kèm khoảng tin cậy.** Mỗi bước chỉ có 2–14 cụm mỗi kịch bản; khoảng tin cậy Wilson 95% khi tìm đủ n cụm là:

| Số cụm n | Tìm đủ n/n | Tìm được 90% |
|---:|---|---|
| 2 | 34–100% | 34–100% |
| 5 | 57–100% | 38–96% |
| 10 | 72–100% | 60–98% |
| 31 | 89–100% | 75–97% |
| 100 | 96–100% | 83–94% |

  Nghĩa là recall theo bước ở một kịch bản không thể kết luận chặt; nên gộp các kịch bản test lại.
- **Ghi giới hạn:** webshell/cracking (0 cụm ở mọi kịch bản) và dnsteal (chỉ 2/8 kịch bản) nằm ngoài khả năng của đầu vào Wazuh. Nếu không ghi, người đọc sẽ nhầm đó là lỗi của sản phẩm.
- **Khử trùng lặp Wazuh IDS và Suricata trước khi tạo cụm.** Nếu không, một sự kiện bị đếm hai lần.

## 7. Việc còn mở

1. Kiểm tra tay mẫu 100–150 cụm để có tỉ lệ sai của event_label (mục 6.1). Đây là việc quyết định nhất.
2. Chọn hướng chia tập (mục 6.4) với cả nhóm.
3. Mở rộng cách nhận diện alert bị bỏ sót: hiện chỉ tìm chuỗi "nmap". Có thể còn tấn công khác trên các host không có file nhãn, nhưng chưa có bằng chứng.
4. Xác nhận với AIT (hoặc đọc paper CATS kỹ hơn) về việc exfiltration chạy trước chuỗi xâm nhập.
5. Sau khi dashboard xem được, kiểm tra từng biểu đồ và sửa tiêu đề phần phạm vi cho đúng với 17,1%.

## 8. Các file liên quan

| File | Nội dung |
|---|---|
| [scripts/build_wazuh_table.py](scripts/build_wazuh_table.py) | Ghép JSON gốc và nhãn, bỏ AMiner. |
| [scripts/scope_analysis.py](scripts/scope_analysis.py) | Khử trùng lặp, gom cụm, đếm tổ hợp. |
| [scripts/export_viz_data.py](scripts/export_viz_data.py) | Xuất CSV cho dashboard. |
| [scripts/extract_biz.py](scripts/extract_biz.py) | Trích alert ".biz" từ JSON gốc. |
| [viz_data/scenario_stats.csv](viz_data/scenario_stats.csv) | Bảng 3.1–3.3. |
| [viz_data/test_combos.csv](viz_data/test_combos.csv) | Bảng 3.4 (56 tổ hợp 3 kịch bản). |
| [viz_data/type_a_rules.csv](viz_data/type_a_rules.csv) | Rule gây lệch kiểu A, cho hướng dẫn gán nhãn. |
| [viz_data/biz_hourly.csv](viz_data/biz_hourly.csv), [viz_data/biz_marks.csv](viz_data/biz_marks.csv) | Đồ thị dnsteal. |
| [out/](out/) | Kết quả phân tích gốc (scope_summary, typeA theo kịch bản). |
| [mismatches.csv](mismatches.csv) | 104 alert lệch của russellmitchell từ bản phân tích đầu (còn gồm AMiner). Dùng làm ví dụ chứ không dùng để đếm. |
