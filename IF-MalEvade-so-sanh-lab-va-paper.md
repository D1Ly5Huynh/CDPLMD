# So sánh kết quả lab và paper IF-MalEvade

Đối chiếu số công bố của Arif et al., IEEE Access 2023 (DOI `10.1109/ACCESS.2023.3334645`) với lần chạy Dike đã chốt trong repo này. Hai cột đứng riêng. Ô paper không được thay bằng số lab.

Nguồn lab:

- `results/dike2500/summary.json` — Table 4–7 của IF-MalEvade
- `results/dike2500/baselines.json` — MAB và MalFox, gồm VirusTotal 50/50
- `results/dike2500/cuckoo_pair*.json` — 50 cặp Cuckoo

Nguồn paper: Table 4–7 trong bài (chép ở `IF-MalEvade-phuong-phap-va-tai-hien.md` §7.4).

## 1. Điều kiện thí nghiệm

| | Paper | Lab |
|---|---|---|
| Malware | 25.000 PE VirusShare, họ backdoor và ransomware | 2.500 PE DikeDataset |
| Benign | 10.000 PE Windows 10 sạch | 1.000 PE (100 Dike + PE Windows trên máy lab) |
| Train / test | 25k độc + 10k lành; test 1.000 malware | 2.400 độc + 1.000 lành; test 100 malware |
| Eval | 500 cặp | 50 cặp |
| Feature | 3.523 bit = 3.269 import + 254 section | Cùng chiều. Quan sát được 206 tên section, 48 cột đệm bằng 0 |
| Detector | RF, GB, MLP, DT. Ngưỡng 0,8 | Cùng bốn mô hình sklearn, cùng ngưỡng |
| DQN | leaky 0,2; hidden 256/64; γ 0,98; 500 episode; MAXTURN 50; lr 10⁻³; ε từ 1,0 xuống 0,05 | Giữ nguyên chín giá trị này |
| VirusTotal | N = 61 engine | 75 engine trả về trên mọi mẫu. Tỉ lệ = số engine bắt / số engine trả về |

Cột `detection_rate_*_paper_N61` trong JSON chia cho 61 dù lab có 75 engine, nên trung bình vượt 100%. Bảng dưới đây không dùng cột đó.

## 2. Table 4 và Table 5

Đơn vị là phần trăm.

| Detector | AUC paper | AUC lab | ODR paper | ODR lab | ADR paper | ADR lab | ADR sau retrain paper | ADR sau retrain lab |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Random Forest | 96,12 | 99,996 | 92,32 | 100 | 9,1 | 98 | 57,9 | 100 |
| Gradient Boosting | 95,85 | 99,995 | 95,24 | 100 | 13,56 | 94 | 48,1 | 100 |
| MLP | 86,50 | 99,998 | 84,52 | 100 | 7,69 | 100 | 49,8 | 100 |
| Decision Tree | 96,56 | 99,998 | 92,98 | 100 | 8,1 | 100 | 54,6 | 100 |

AUC lab là `summary.json` nhân 100: RF 0,99996; GB 0,999950; MLP 0,999978; DT 0,999981.

Paper: mẫu adversarial bị bắt khoảng 8–14%, sau retrain tăng lên khoảng 48–58%. Lab: mẫu gốc bị bắt hết (ODR 100%), mẫu sau sửa vẫn bị bắt 94–100%. Retrain không còn khoảng trống để ADR tăng.

Trên không gian vector, batch MalGAN cuối né được 96,5%. Khi ghi ra PE, `mutate_evade` = 2% (1/50) và `mean_turns` = 49,04/50.

## 3. Table 6 — detection rate trên VirusTotal

Trung bình (min–max), đơn vị phần trăm.

| Mẫu | Paper | Lab |
|---|---|---|
| Malware gốc | 61,8 (27,2–85,1) | 82,3 (65,3–89,5) |
| MAB-Malware | 42,9 (25,5–62,2) | 65,8 (41,3–81,3) |
| MalFox | 30,2 (21,9–49,7) | 64,4 (44,0–81,3) |
| IF-MalEvade | 21,8 (15,4–35,5) | 74,1 (45,3–85,3) |

## 4. Table 7 — evasion rate trên VirusTotal

| Mẫu | Paper | Lab |
|---|---|---|
| MAB-Malware | 19,2 (7,8–44,5) | 21,2 (0–51,5) |
| MalFox | 38,2 (10,2–61,9) | 22,6 (0–45,0) |
| IF-MalEvade | 57,8 (15,7–75,5) | 11,5 (0–45,2) |

Thứ tự né của paper: IF-MalEvade, MalFox, MAB-Malware. Thứ tự của lab: MalFox 22,6%, MAB 21,2%, IF-MalEvade 11,5%.

Ô gần paper nhất là evasion của MAB (21,2% so với 19,2%). MalFox lab thấp hơn paper khoảng 16 điểm. IF-MalEvade lab thấp hơn paper khoảng 46 điểm. Mẫu gốc lab đã bị bắt 82,3%, paper 61,8%, nên cả ba hàng detection sau khi sửa đều cao hơn paper.

Baseline lab chỉ dùng 7 action ở Table 3. MAB của Song et al. còn xóa chữ ký, phá checksum và random hóa code. MalFox của Zhong et al. còn Obfusmal, Stealmal và Hollowmal. Hai cột VirusTotal dùng cùng công thức detection rate và evasion rate, trên hai bộ biến đổi khác nhau.

## 5. ADR local của MAB và MalFox

Paper không công bố ADR của MAB hay MalFox trên bốn detector sklearn. Số dưới đây chỉ thuộc lab, ngưỡng 0,8, black-box là Gradient Boosting. Đơn vị phần trăm mẫu còn bị gọi là malware.

| | Né được black-box | ADR RF | ADR GB | ADR MLP | ADR DT |
|---|---:|---:|---:|---:|---:|
| MAB | 70 | 66 | 30 | 92 | 38 |
| MalFox | 28 | 90 | 72 | 100 | 82 |
| IF-MalEvade | 2 | 98 | 94 | 100 | 100 |

ADR của IF-MalEvade ở hàng này chính là Table 4. Ba hàng không thay cho Table 6–7.

## 6. Cuckoo

Paper giữ mutant khi chữ ký Cuckoo khớp mẫu gốc, và không công bố tỉ lệ khớp. Lab chạy đủ 50 cặp: 41 khớp, 9 lệch (chỉ số 1, 6, 9, 13, 22, 23, 34, 35, 38).

## 7. Vì sao Table 4 không về gần paper

Điểm malware trên tập train nằm sát 1, điểm benign sát 0. Ngưỡng 0,8 nằm lệch về phía malware khoảng 0,2 điểm. Paper có ODR 85–95% và AUC 0,865–0,966, nên một phần mẫu gốc đã ở gần ngưỡng.

Trên 50 vector eval đã lưu (`orig_vectors.npy`, `adv_vectors.npy`) và `models/dike2500/detectors.joblib`:

- 31/50 mutant không đổi bit nào. Trung bình 6,6 bit trên 3.523 bit, tối đa 113.
- Random Forest: 1/50 xuống dưới 0,8 (min 0,79).
- Gradient Boosting: 3/50 (min 0,47).
- MLP: mức giảm lớn nhất 0,036, min còn 0,96.
- Decision Tree: mọi mẫu vẫn 1,0.

Pool GAN có 30 import và 2 tên section. Thêm vài bit import không đổi lá thuần malware của Decision Tree. Chạy lại cùng corpus, cùng chín hyperparameter, không thu hẹp biên điểm này.
