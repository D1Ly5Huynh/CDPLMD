# So sánh lab hiện tại với ảnh kq1

Ngày ghi: 2026-10-20.

Câu hỏi: kết quả nào né detector hiệu quả hơn.

Kết luận: ảnh `C:\Users\tuonghk\Downloads\kq1.jpg` hiệu quả hơn trên AUC, ODR và ADR. Bốn mô hình trong ảnh còn bắt mẫu đã sửa ít hơn lab hiện tại rất nhiều. Mức detection tụt cũng lớn hơn ở cả bốn mô hình.

Ảnh không có VirusTotal, Cuckoo hay adversarial retrain. Ba phần đó chỉ có ở lab hiện tại, nên không dùng để tuyên bố bên nào né engine hoặc giữ hành vi tốt hơn.

## Hai nguồn số

Ảnh chụp notebook `Project2_chuyen-de-ma-doc.ipynb`. Dòng phía trên bảng ghi đang sinh mẫu đối kháng cho 200 malware kiểm thử. Bảng in bốn cột: AUC, ODR, ADR, mức suy giảm.

Lab hiện tại là corpus `data/lab_dataset`, kết quả trong `results/lab_dataset`.

| Mục | Ảnh kq1 | Lab hiện tại |
|---|---|---|
| Số malware đánh giá | 200 | 50 mẫu eval, lấy từ 100 malware test |
| Tập train | Không có trong ảnh | 2.400 malware + 1.000 benign |
| Malware | Không có trong ảnh | 2.500 PE RanDS |
| Benign | Không có trong ảnh | 1.000 PE Windows trên máy |
| Đặc trưng | Không có trong ảnh | 3.523 bit: 3.269 import + 254 section |
| Seed | Không có trong ảnh | 42 |
| File số | Chỉ thấy bảng trên ảnh | `summary.json`, `table6_engine_detection.json`, `table7_evasion.json`, `baselines.json`, `cuckoo_pair0.json` đến `cuckoo_pair49.json` |

Notebook không nằm trong `C:\Users\tuonghk\CDPLMD` và không thấy khi tìm `Project2_chuyen-de-ma-doc.ipynb` dưới `C:\Users\tuonghk` ở độ sâu 4. Mọi số của ảnh lấy từ bảng trong `kq1.jpg`. Không suy diễn thuật toán bên trong notebook.

## Định nghĩa dùng để so

Ba chỉ số trong ảnh và trong Table 4 của lab cùng nghĩa:

- **AUC**: khả năng tách malware và benign. Gần 100% là tách rất chắc.
- **ODR**: tỷ lệ mẫu gốc bị gọi là malware. Ngưỡng lab là 0,8.
- **ADR**: tỷ lệ mẫu đã sửa vẫn bị gọi là malware. ADR thấp nghĩa là cuộc tấn công né detector tốt hơn.
- **Mức suy giảm** trên ảnh bằng ODR trừ ADR, đơn vị điểm phần trăm. Kiểm lại đúng từng ô: 94,50 − 20,50 = 74,00; 92,50 − 20,50 = 72,00; 96,50 − 45,00 = 51,50; 85,50 − 16,50 = 69,00.

Lab không in sẵn cột mức suy giảm. Cột này ở dưới được tính cùng cách đó từ ODR và ADR trong `summary.json`.

## Bảng bốn detector

Số lab làm tròn một chữ số cho dễ đọc. Giá trị gốc nằm ở mục sau.

| Mô hình | AUC ảnh | AUC lab | ODR ảnh | ODR lab | ADR ảnh | ADR lab | Tụt ảnh | Tụt lab |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Decision Tree | 94,14% | 99,82% | 94,50% | 100% | 20,50% | 76% | 74,00 | 24 |
| Gradient Boosting | 99,58% | 99,63% | 92,50% | 100% | 20,50% | 96% | 72,00 | 4 |
| MLP | 99,45% | 99,81% | 96,50% | 98% | 45,00% | 72% | 51,50 | 26 |
| Random Forest | 99,84% | 99,72% | 85,50% | 98% | 16,50% | 60% | 69,00 | 38 |

Tụt tương đối, tức (ODR − ADR) / ODR:

| Mô hình | Ảnh kq1 | Lab hiện tại |
|---|---:|---:|
| Decision Tree | 78,3% | 24,0% |
| Gradient Boosting | 77,8% | 4,0% |
| MLP | 53,4% | 26,5% |
| Random Forest | 80,7% | 38,8% |

Đọc từng mô hình:

- **Random Forest** là chỗ lab né tốt nhất trong bốn detector của chính lab, ADR 60%, tụt 38 điểm. Ảnh vẫn thấp hơn nhiều: ADR 16,50%, tụt 69 điểm. ODR của ảnh chỉ 85,50%, nên detector trong ảnh bỏ sót bản gốc nhiều hơn lab (ODR lab 98%). Dù vậy ADR ảnh vẫn thấp hơn ADR lab 43,5 điểm.
- **Gradient Boosting** là chỗ hai bên cách nhau lớn nhất. Ảnh tụt 72 điểm, ADR còn 20,50%. Lab gần như không tụt: ODR 100%, ADR 96%.
- **Decision Tree** của ảnh có AUC thấp nhất trong bảng ảnh, 94,14%, nhưng ADR 20,50%. Lab có AUC 99,82% và ADR 76%. Detector lab tách lớp chắc hơn, và mẫu đã sửa vẫn bị bắt nhiều hơn.
- **MLP** là detector khó né nhất trong ảnh, ADR 45%. Lab còn cao hơn, ADR 72%.

Trung bình ADR bốn mô hình: ảnh 25,6%, lab 76,0%. Trung bình mức tụt: ảnh 66,6 điểm, lab 23,0 điểm.

## Số lab chưa làm tròn

Từ `results/lab_dataset/summary.json`, mục `table4`:

| Mô hình | AUC | ODR | ADR |
|---|---:|---:|---:|
| Random Forest | 0,997245 | 0,98 | 0,60 |
| Gradient Boosting | 0,996301 | 1,00 | 0,96 |
| MLP | 0,998148 | 0,98 | 0,72 |
| Decision Tree | 0,998182 | 1,00 | 0,76 |

Cùng file, các chỉ số tấn công trên 50 mẫu eval, detector bị tấn công là Random Forest:

| Chỉ số | Giá trị | Nghĩa |
|---|---:|---|
| `mutate_evade` | 0,40 | 40% mẫu eval bị Random Forest gọi dưới 0,8 |
| `gan_last_evade_batch` | 0,619583 | Batch cuối của MalGAN né được khoảng 62,0% |
| `dqn_evade_last20` | 0,60 | 20 episode cuối của DQN né được 60% |
| `mean_turns` | 30,54 | Trung bình 30,54 lượt sửa mỗi mẫu eval |

`mutate_evade` 0,40 khớp ADR Random Forest 0,60: phần bị bắt và phần né cộng lại thành 1 trên cùng 50 mẫu.

## Những gì chỉ lab có

Ảnh dừng ở bốn detector. Các mục dưới đây không có ô tương ứng trong `kq1.jpg`.

### Table 5, sau khi train lại

Retrain dùng 50% mẫu eval. ADR sau retrain cao hơn nghĩa là detector bắt lại được mẫu đã sửa.

| Mô hình | ADR trước | ADR sau |
|---|---:|---:|
| Random Forest | 60% | 88% |
| Gradient Boosting | 96% | 96% |
| MLP | 72% | 90% |
| Decision Tree | 76% | 96% |

Ba detector tăng ADR sau retrain. Gradient Boosting đứng yên ở 96%.

### VirusTotal, 50 cặp IF-MalEvade

Detection là số engine bắt file chia cho số engine đã trả lời. Evasion của một cặp là (N gốc − N adversarial) / N gốc. 20,5% là trung bình 50 tỷ lệ đó, không phải tỷ lệ mẫu né hoàn toàn.

| Chỉ tiêu | Thấp | Trung bình | Cao |
|---|---:|---:|---:|
| Table 6, detection gốc | 58,4% | 76,8% | 90,8% |
| Table 6, detection adversarial | 18,7% | 62,4% | 88,0% |
| Table 7, evasion | 0% | 20,5% | 75% |

### Hai baseline trên cùng 50 mẫu

Detector cục bộ bị tấn công là Gradient Boosting. VirusTotal đã đủ 50/50 cặp cho cả hai.

| Phương pháp | Né Gradient Boosting | ADR RF / GB / MLP / DT | VT detection | VT evasion |
|---|---:|---|---:|---:|
| MAB-Malware | 70% | 64% / 30% / 74% / 46% | 60,0% | 23,2% |
| MalFox | 4% | 88% / 96% / 98% / 84% | 57,3% | 26,6% |

MAB trên Gradient Boosting, ADR 30%, là ô lab gần bảng ảnh nhất. Ảnh ghi Gradient Boosting ADR 20,50% trên 200 mẫu. Hai thí nghiệm không cùng corpus và không cùng số mẫu, nên 30% và 20,50% chỉ là cùng loại chỉ số, không phải cùng một phép đo.

### Cuckoo

50/50 cặp đã chạy. Khớp 42. Lệch 8. Khớp nghĩa là mọi signature của bản gốc còn trên bản mutate. Lệch không đổi Table 4 đến Table 7, vì các bảng đó đã tính trên cả 50 mẫu.

## Paper để làm mốc, không phải ảnh

Paper IF-MalEvade, Table 4, ADR công bố: Random Forest 9,1%, Gradient Boosting 13,6%, MLP 7,7%, Decision Tree 8,1%. ODR paper khoảng 84,5–95,2%. AUC paper khoảng 86,5–96,6%.

Ảnh gần các ô ADR của paper hơn lab hiện tại. Lab gần paper hơn ảnh ở ODR của Random Forest: paper 92,3%, lab 98%, ảnh 85,5%. AUC lab cao hơn cả paper và cao hơn ảnh ở Decision Tree.

Gần paper và né detector hiệu quả là hai câu khác nhau. Câu của file này là câu thứ hai. Trên câu đó, ảnh thắng cả bốn mô hình.

## Điều không kết luận được từ ảnh

- Ảnh dùng 200 malware kiểm thử. Lab đánh giá 50 mẫu. Một ADR 16,5% trên 200 mẫu và một ADR 60% trên 50 mẫu không có cùng độ rộng của sai số.
- Ảnh không ghi họ malware, benign, chiều đặc trưng, seed, ngưỡng 0,8, hay phép sửa file. Có thể pipeline khác IF-MalEvade.
- ODR Random Forest của ảnh thấp hơn lab 12,5 điểm. Một phần ADR thấp có thể đến từ detector bắt bản gốc yếu hơn, không chỉ từ mẫu sửa mạnh hơn. Mức tụt 69 điểm vẫn lớn hơn mức tụt 38 điểm của lab, nên kết luận “né tốt hơn” vẫn đứng sau khi đã trừ phần ODR.
- Không có dòng VirusTotal hay Cuckoo trên ảnh. Không xếp hạng hai bên ở hai mục đó.
