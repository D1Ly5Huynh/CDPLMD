# IF-MalEvade — giải thích đầy đủ paper

**Nguồn:** file PDF trong thư mục `C:\Users\tuonghk\CDPLMD`

**Citation:** Rahat Maqsood Arif, Muhammad Aslam, Shaha Al-Otaibi, Ana Maria Martinez-Enriquez, Tanzila Saba, Saeed Ali Bahaj, Amjad Rehman. *A Deep Reinforcement Learning Framework to Evade Black-Box Machine Learning Based IoT Malware Detectors Using GAN-Generated Influential Features*. IEEE Access, vol. 11, pp. 133717–133729, 2023. DOI: [10.1109/ACCESS.2023.3334645](https://doi.org/10.1109/ACCESS.2023.3334645)

**Tên framework:** IF-MalEvade (Influential-Feature Malware Evasion)

**Ngày nhận / chấp nhận / xuất bản:** nhận 29/10/2023, chấp nhận 12/11/2023, xuất bản 20/11/2023, version hiện tại 01/12/2023.

**License:** CC BY-NC-ND 4.0

**Tài trợ:** Princess Nourah bint Abdulrahman University Researchers Supporting Project, grant PNURSP2023R136.

---

## 1. Paper này làm gì, một câu

Đây là bài **đánh giá độ bền** của bộ phát hiện malware IoT kiểu black-box: tạo biến thể malware Windows PE **vẫn chạy được, vẫn độc**, nhưng detector học máy và engine trên VirusTotal nhận nhầm thành file lành.

Cách làm: **MalGAN lọc ra tập feature “có ảnh hưởng”** (import + tên section), rồi **Deep Q-Network chọn chuỗi vài phép sửa file PE** theo tập đó. Sau khi sửa, **Cuckoo Sandbox** kiểm tra hành vi còn khớp mẫu gốc.

---

## 2. Bối cảnh và động lực

### 2.1. IoT + malware

Internet of Things (nhà thông minh, thành phố thông minh, thiết bị tự hành, 5G) làm bề mặt tấn công phình ra. Ước lượng Statista: khoảng 74,44 tỷ thiết bị IoT vào 2025. McAfee Labs Q1/2021: trung bình 688 cuộc tấn công malware mỗi phút. VirusTotal (01/2021–04/2022): hơn một triệu mẫu đã ký số bị coi là đáng ngờ (hơn 15% antivirus đánh độc).

Malware trên IoT đánh cắp dữ liệu, tống tiền, bán quyền riêng tư. Chữ ký truyền thống không theo kịp biến thể mới. Thương mại antivirus chuyển sang học máy.

### 2.2. Detector học máy

Nghiên cứu phát hiện malware IoT dùng:

- đặc trưng tĩnh: opcode, header PE, API/import, quyền;
- đặc trưng động: system call;
- miền ảnh: biến binary thành ảnh xám, CNN phân loại họ malware.

Paper cho rằng **đặc trưng tĩnh rẻ hơn** phân tích động (động tốn thời gian, cần sandbox, có rủi ro khi chạy mẫu).

### 2.3. Lỗ hổng: adversarial sample

Mô hình học máy bị đánh lừa bởi **adversarial sample**: sửa input có chủ đích để detector gán nhãn lành với độ tin cao. Symantec: hơn một nửa malware mới mỗi năm chỉ là biến thể của mẫu cũ. Kẻ tấn công sửa file vừa đủ để né detector, giữ nguyên hành vi độc.

### 2.4. Hướng evasion trước đó

| Hướng | Đại diện | Việc làm | Hạn chế paper nêu |
|-------|----------|----------|-------------------|
| Gradient / white-box | FGSM | Dựa đạo hàm mô hình | Cần biết nội bộ detector |
| Thuật toán tiến hóa / đồ thị | Liu, Wang, Jin, Abusnaina | Sinh mẫu đối kháng cho IoT/Android | Không phải chuỗi sửa PE có kiểm soát |
| Reinforcement learning trên PE | Anderson (Black Hat 2017), Fang DQEAF, Song MAB-Malware, Labaca-Castro AIMED-RL | Agent chọn action sửa file, giữ ngữ nghĩa | Action space lấy **toàn bộ** import/section chưa lọc; agent học khó, sửa nhiều |
| GAN vector import | Hu & Tan **MalGAN** | Generator sinh vector import đánh lừa black-box | Chỉ ra **vector**, không ra file PE chạy được; nhiều feature làm GAN không ổn định |
| GAN + autoencoder / ảnh | Kim, Bai AI-GAN, Moti | Malware thành ảnh, GAN nhiễu ảnh | Ít kiểm soát từng feature; sửa pixel khác sửa PE (1 byte có thể phá format/payload) |
| GAN + RL botnet / IDS | Randhawa, Benaddi | Né detector botnet / IDS công nghiệp | Khác miền PE |
| So RL vs GAN | Phan et al. 2022 | So hai hướng trên backdoor | Không so SOTA gần; không chứng minh file còn chạy trong sandbox |
| Conv-GAN + PE editor | Zhong et al. **MalFox** | CNN-GAN ra đường perturbation, PE editor sửa, đánh VirusTotal | GAN phức tạp (hai CNN); feature space lớn |

IF-MalEvade đứng giữa: **GAN đơn giản** (feed-forward, import+section) sinh **feature có ảnh hưởng**, **DRL** chỉ làm **ít phép sửa giữ chức năng**.

### 2.5. Đóng góp paper tự nêu

1. Phương pháp evasion mới: dùng danh sách influential feature từ GAN để sinh malware **giữ chức năng**, nhằm đánh độ bền detector IoT black-box.
2. Retrain detector bằng mẫu adversarial thì tỉ lệ phát hiện tăng.
3. Ghép GAN với DRL giúp huấn luyện với **ít sửa hơn, sửa đúng chỗ hơn**.
4. Đánh engine thương mại VirusTotal, kết quả tốt hơn MalFox và MAB-Malware.

### 2.6. Bố cục paper (đánh số trong thân bài)

Paper ghi mục lục hơi lệch với thân bài. Thân bài:

1. Introduction
2. Literature review (detection + evasion)
3. Methodology (Windows IoT, PE, MalGAN, DRL, Cuckoo)
4. Experimentation
5. Results (figure)
6. Discussion (bảng số)
7. Conclusion

---

## 3. Vì sao nói “IoT” trong khi dataset là Windows PE

Windows chiếm khoảng **70,39%** thị phần OS desktop/tablet/console (Statista, 01/2023). Windows còn chạy trên ATM, POS, thin client, tự động hóa công nghiệp, thiết bị y tế, biển quảng cáo, kiosk — tức Windows IoT / thiết bị chuyên dụng. File thực thi Windows dùng format **Portable Executable (PE)**. Paper coi PE là nguồn tấn công hợp lệ trong hệ sinh thái IoT gắn Windows (kể cả Windows 11 IoT).

Dataset thực tế: **Windows PE backdoor + ransomware**, 25.000 malware + 10.000 file lành. “IoT” là bối cảnh ứng dụng.

---

## 4. Cấu trúc PE họ thao tác

### 4.1. Header

Thông tin thiết yếu của executable: MS-DOS header, PE signature, file header, optional header, data directories. Ngay sau đó là **section table**: mỗi section kèm thuộc tính.

### 4.2. Sections

Dữ liệu thật của file. Các section then chốt:

- `.text` — lệnh máy (code);
- `.data` — biến toàn cục / static đã khởi tạo;
- `.idata` — thông tin import.

### 4.3. Cách sửa “giữ chức năng”

Sửa **một byte** lung tung có thể phá format PE hoặc mất payload. Paper theo Anderson: thêm import lành không dùng, thêm section rỗng, đổi tên section, nhét byte vào vùng code không bao giờ nhảy tới, append byte cuối file, pack/unpack bằng UPX (nén một phần file, giải nén lúc chạy).

---

## 5. Kiến trúc IF-MalEvade — hai giai đoạn

Figure 1: kiến trúc tổng. Cảm hứng **MalGAN** (Hu & Tan) + **DQEAF** (Fang et al.).

Figure 3: luồng sinh một adversarial sample.

### 5.1. Giai đoạn A — MalGAN tạo tập feature có ảnh hưởng

1. Parse malware + benign bằng thư viện PE (`pefile`; paper in nhầm `pelife`).
2. Lấy **tên hàm import** (DLL/API) và **tên section**.
3. Dựng **feature mapping dictionary**: mỗi tên → một chỉ số.
4. Mỗi file → vector nhị phân: `1` = có feature, `0` = không có.
5. Đưa vector + nhiễu vào MalGAN.
6. Generator ra **vector adversarial**.
7. Map ngược bit `1` ra tên import/section, thành **thư viện feature** cho DQN.

Kích thước vector: **3523 chiều = 3269 import + 254 section** (MalGAN gốc: 160 chiều).

### 5.2. Giai đoạn B — DRL mutate file PE thật

1. Môi trường OpenAI Gym chứa file malware.
2. State \(s_t\) = vector import + section hiện tại.
3. Agent chọn action \(a_t\) trong 7 action.
4. Khi action là thêm/đổi import hoặc section, **bốc ngẫu nhiên từ pool GAN**.
5. Sửa file bằng `pefile`, rebuild bằng **PE Bliss**.
6. Classifier / VirusTotal gán nhãn malware hoặc benign.
7. Tính reward \(r_t\). Tối đa **MAXTURN = 50** lượt. Hết lượt vẫn độc → fail.
8. Chạy Cuckoo. Trường **signatures** khớp mẫu gốc → lưu adversarial sample.

---

## 6. MalGAN — chi tiết

### 6.1. Ba khối

| Khối | Vai trò |
|------|---------|
| **Generator** | Mạng học, nhận vector malware + nhiễu, sinh feature trông lành nhưng giữ chức năng độc (thêm import/section). |
| **Discriminator** | Quyết định output generator là độc hay lành; bắt chước năng lực phân loại của detector black-box. |
| **Black-box detector** | Mô hình ML kiểu antivirus; gắn nhãn output generator để discriminator học. |

Huấn luyện: vector adversarial từ G + vector benign được gắn nhãn, đưa vào D. D tính loss so với nhãn. G dùng giá trị đó để lần sau đánh lừa D và detector tốt hơn. Lặp đến khi mẫu sinh ra đánh lừa được **cả detector lẫn discriminator**.

### 6.2. Ràng buộc “chỉ thêm, không xóa”

Generator **bật thêm** bit import/section (phép OR). Tắt import gốc là mất API malware thật sự gọi. Paper lặp lại điểm này nhiều lần.

### 6.3. Siêu tham số MalGAN

| Tham số | Giá trị |
|---------|---------|
| Kiến trúc G và D | Feed-forward giống nhau |
| Hidden layer | 256 node |
| Kích thước nhiễu đầu vào G | 10, phân phối ngẫu nhiên |
| Chiều vector | 3523 (3269 import + 254 section) |
| Activation | Leaky ReLU |
| Batch size | 32 |
| Số epoch | 100 |

Paper nói cảm hứng thêm từ Bae et al. (Learn2Evade / MalGan trên PDF) khi dựng feature library. PE header (import + section) được survey gần đó xem là đặc trưng mạnh cho detector ML.

---

## 7. Deep Reinforcement Learning — chi tiết

Nền: DQEAF của Fang. Mô hình MDP.

### 7.1. Ba thành phần module DRL

1. **Malware environment** — cho agent sửa mẫu, phân loại, chấm điểm.
2. **DRL agent** — mạng nơ-ron học chuỗi mutation để né classifier.
3. **Classifier** — mạng/mô hình gán nhãn benign hoặc malware.

### 7.2. Bảy hành động (Table 3)

Paper in tiêu đề “Actin space” (thiếu chữ *o*).

| Action | Specified by | Việc trên file |
|--------|----------------|----------------|
| `insert_import` | Vector adversarial GAN | Thêm hàm import vào Import Table |
| `rename_section` | Vector adversarial GAN | Đổi tên section |
| `insert_section` | Vector adversarial GAN | Thêm section lành / không dùng |
| `section_append` | DRL action | Append byte vào section |
| `upx_pack` | DRL action | Pack bằng UPX |
| `upx_unpack` | DRL action | Unpack bằng UPX |
| `overly_append` | DRL action | Append số byte ngẫu nhiên cuối file (overlay) |

Ba action đầu **lấy ứng viên từ pool GAN**. Bốn action sau là phép sửa cấu trúc/byte, không cần GAN.

### 7.3. Reward — phương trình (1)

Nếu detector **vẫn gọi là malware**:

\[
r_t = 0
\]

Nếu detector **gọi là benign**:

\[
r_t = 20 \times 100^{-(\mathrm{TURN}-1)/\mathrm{MAXTURN}}
\]

Né **sớm** → thưởng gần 20. Né **muộn** (gần lượt 50) → thưởng nhỏ. Mục tiêu: chuỗi sửa **ngắn**.

Phần thí nghiệm còn viết: reward theo **số engine VirusTotal bắt được** (ít engine bắt → thưởng cao), đồng thời “dùng Eq. (1)”. Hai mô tả nằm cạnh nhau.

**Discount \(\gamma\)**

- Đoạn lý thuyết: cân bằng ở **0.9** (\(\gamma=0\) chỉ nhìn thưởng trước mắt; \(\gamma=1\) nhìn hết tương lai).
- Đoạn thí nghiệm: **\(\gamma = 0.98\)**.

### 7.4. Loss DQN — phương trình (2)

TD error bình phương:

\[
\ell_t(\theta_t)=\bigl(r_{t+1}+\gamma\max_{a_{t+1}}Q(s_{t+1},a_{t+1};\theta_{t-1})-Q(s_t,a_t;\theta_t)\bigr)^2
\]

Agent tối ưu trọng số \(\theta\) để giảm lỗi này. Q-network sau train là policy mạng cho danh sách action tối ưu.

### 7.5. Siêu tham số DRL

| Tham số | Giá trị |
|---------|---------|
| Môi trường | OpenAI Gym, kiểu DQEAF |
| Mạng agent | 2 hidden layer, 256 và 64 node |
| Activation | ReLU |
| Số episode | 500 |
| \(\gamma\) (thí nghiệm) | 0.98 |
| MAXTURN / giới hạn mutation mỗi PE | 50 |
| Parse / sửa PE | `pefile` |
| Rebuild PE | PE Bliss |

---

## 8. Cuckoo Sandbox — giữ hành vi độc

Cuckoo: công cụ mã nguồn mở phân tích malware tự động, chạy file trong VM khách, cách ly host bằng virtual switch, ghi API và mạng.

Paper dẫn Ijaz et al.: phân tích động bằng Cuckoo đạt accuracy 94,64%. Nhiều bài evasion (MAB-Malware, Jin, …) dùng Cuckoo khi cần chứng minh mẫu adversarial **còn độc**.

Báo cáo Cuckoo có:

- **static:** string, hash, kích thước file;
- **dynamic:** API call, đặc trưng mạng, trường **signatures** (tạo thêm file exe, tạo service, cấp phát bộ nhớ, …).

IF-MalEvade so **signatures** mẫu gốc với mẫu mutate. Khớp thì giữ. Đây là điều kiện “fully-working malware” trong abstract.

---

## 9. Setup thí nghiệm (Section IV)

### 9.1. Phần cứng / phần mềm

- CPU Intel Core i7-1165G7, Windows 10.
- VM: 200 GB disk, 16 GB RAM (vì làm việc với malware).
- TensorFlow + scikit-learn cho detector đích.
- `pefile` parse PE.
- OpenAI Gym cho môi trường sửa file.

### 9.2. Dataset (Table 2)

Toàn bộ: **25.000 malware + 10.000 benign**, Windows executable.

| | Malicious | Benign |
|--|-----------|--------|
| Training | 25K | 10K |
| Test | 1000 | 0 |

- Malware: kho VirusShare và VirusTotal, gồm **backdoor** và **ransomware** (paper nói ransomware là mối đe dọa nghiêm trên IoT).
- Benign: file hệ thống Windows 10 sạch trong VM + crawl phần mềm phổ biến.
- Lọc nhãn: VirusTotal, **61 engine**.

### 9.3. Tấn công detector ML nội bộ

Bốn thuật toán sklearn **tham số mặc định**, thường gặp trong antivirus công nghiệp:

- Random Forest
- Gradient Boosting
- Multi-Layer Perceptron
- Decision Tree

Đặc trưng train: **import + section** (cùng không gian với GAN/DRL).

Đoạn văn còn ghi learning rate 0.0003, 150 epoch, batch 50 — sát với huấn luyện mạng (MLP / detector neural), trong khi RF/DT/GB sklearn mặc định không dùng epoch theo nghĩa đó.

**Ngưỡng malware = 0.8:** score > 0.8 mới gọi là malware. Lấy từ setup MAB-Malware.

Đánh giá: **500** file gốc và 500 file adversarial tương ứng từ test set.

Hai chỉ số:

- **ODR** (Original Detection Rate): tỉ lệ detector bắt đúng malware gốc.
- **ADR** (Adversarial Detection Rate): tỉ lệ detector bắt được mẫu đã mutate.

**Adversarial retraining:** train lại detector với adversarial sinh từ **50% test set** cộng phần malware còn lại. Đo ADR sau retrain (Table 5).

### 9.4. Tấn công VirusTotal, so MalFox và MAB-Malware

Train các mô hình trên cùng 25K malware + benign. Giữ hyperparameter repo GitHub của MalFox và MAB-Malware.

**Phương trình (3) — detection rate**

\[
\text{detection rate} = \frac{n}{N}
\]

- \(n\): số search engine VirusTotal bắt mẫu (gốc hoặc adversarial);
- \(N\): tổng số engine.

**Phương trình (4) — evasive rate**

\[
\text{evasive rate} = \frac{N_{\mathrm{org}} - N_{\mathrm{adv}}}{N_{\mathrm{org}}}
\]

- \(N_{\mathrm{org}}\): số engine bắt mẫu gốc;
- \(N_{\mathrm{adv}}\): số engine bắt biến thể.

Evasive rate cao → nhiều engine từng bắt mẫu gốc **tha** biến thể (nhìn như lành).

Tấn công **thành công** khi adversarial có detection rate thấp hơn mẫu gốc và evasive rate cao.

---

## 10. Kết quả (Section V–VI)

### 10.1. Figure 4–7 (mô tả)

- **Figure 4:** AUC, ODR, ADR theo từng thuật toán ML (cột hình còn vẽ SVM, bảng số thì không có SVM).
- **Figure 5:** ADR trước và sau adversarial training.
- **Figure 6:** detection rate VirusTotal — min / max / trung bình — cho malware gốc, MAB-Malware, MalFox, IF-MalEvade.
- **Figure 7:** evasion rate tương ứng.

### 10.2. Table 4 — detector ML trên mẫu gốc và adversarial

Đơn vị: phần trăm.

| ML detector | AUC | Original Detection Rate (ODR) | Adversarial Detection Rate (ADR) |
|-------------|-----|-------------------------------|----------------------------------|
| Decision Tree | 96.56 | 92.98 | **8.1** |
| Gradient Boosting | 95.85 | 95.24 | **13.56** |
| Multi-Layer Perceptron | 86.50 | 84.52 | **7.69** |
| Random Forest | 96.12 | 92.32 | **9.1** |

ODR và AUC đều trên ~80–96%. Sau mutate, ADR còn khoảng 8–14%. Gradient Boosting là ADR **cao nhất** trong bốn mô hình (13.56%), tức khó né nhất trong nhóm này; MLP có ADR thấp nhất (7.69%).

Abstract: detection của mô hình ML “được kéo xuống tới 97%”. Đọc cùng bảng: mức phát hiện trên mẫu adversarial giảm rất mạnh so với mẫu gốc (ví dụ RF 92.32% → 9.1%).

### 10.3. Table 5 — ADR trước / sau adversarial retraining

| ML detector | ADR không retrain | ADR có retrain |
|-------------|-------------------|----------------|
| Decision Tree | 8.1 | 54.6 |
| Gradient Boosting | 13.56 | 48.1 |
| Multi-Layer Perceptron | 7.69 | 49.8 |
| Random Forest | 9.1 | 57.9 |

Lời văn: RF 9.1% → **57.6%**. Bảng in **57.9%**. Abstract gom thành “tăng khoảng 35%” — cách nói của abstract, không khớp sát hiệu số trên bảng (57.6 − 9.1 = 48.5 điểm phần trăm).

Ý nghĩa: mẫu IF-MalEvade vừa **né** detector, vừa dùng được để **cứng hóa** detector bằng adversarial training.

### 10.4. Table 6 — detection rate trên VirusTotal

| Evaluation benchmark | Average | Min | Max |
|----------------------|---------|-----|-----|
| Detection rate (original malware) | 61.8 | 27.2 | 85.1 |
| Detection rate (MAB-Malware) | 42.9 | 25.5 | 62.2 |
| Detection rate (MalFox) | 30.2 | 21.9 | 49.7 |
| Detection rate (**IF-MalEvade**) | **21.8** | **15.4** | **35.5** |

Trung bình detection giảm khoảng **21.8 điểm** so với mẫu gốc (61.8 → 21.8). Lời văn: “decline of roughly 21.8%”.

Paper còn viết: khi so từng cặp gốc–adversarial, detection có thể giảm tới **58** (điểm / phần trăm, câu văn bị cắt). Khoảng detection adversarial: thấp hơn gốc từ 21.8% đến 35.5% (câu này trong discussion dễ đọc nhầm với hàng “Proposed malware” của Table 6, vốn đã là detection rate tuyệt đối 21.8 / 15.4 / 35.5).

### 10.5. Table 7 — evasion rate trên VirusTotal

| Evaluation benchmark | Average | Min | Max |
|----------------------|---------|-----|-----|
| Evasion rate (MAB-Malware) | 19.2 | 7.8 | 44.5 |
| Evasion rate (MalFox) | 38.2 | 10.2 | 61.9 |
| Evasion rate (**IF-MalEvade**) | **57.8** | **15.7** | **75.5** |

Lời văn dùng trung bình **~57.9%**; bảng **57.8%**. Mẫu né tốt nhất: **75.5%** engine từng bắt mẫu gốc thì tha mẫu mutate.

Thứ tự né VirusTotal theo paper: IF-MalEvade > MalFox > MAB-Malware.

---

## 11. Kết luận paper (Section VII)

Ghép GAN (lọc feature có ảnh hưởng) với DRL (chuỗi sửa ngắn, giữ chức năng) cho evasion mạnh hơn MalFox và MAB-Malware, trên detector ML nội bộ và VirusTotal, **không cần biết** tham số nội bộ detector (black-box).

Mẫu adversarial còn nâng detector khi retrain.

**Hướng mở:**

- format khác: **ELF** (Linux), **Android** — vì IoT gồm nhiều kiến trúc;
- action space DRL **gọn và hiệu quả hơn**;
- feature khác: **API call** hoặc **system call** động.

Tác giả tuyên bố không xung đột lợi ích.

---

## 12. Công thức và thuật ngữ — bảng tra nhanh

| Ký hiệu / thuật ngữ | Nghĩa |
|---------------------|--------|
| PE | Portable Executable, format file `.exe`/`.dll` Windows |
| Influential features | Import + section mà MalGAN cho là đáng thêm để trông lành |
| Black-box | Chỉ cần nhãn malware/benign, không cần trọng số / dữ liệu train của detector |
| ODR | Tỉ lệ bắt malware gốc |
| ADR | Tỉ lệ bắt malware đã mutate |
| MAXTURN | 50 — số lượt sửa tối đa mỗi file |
| TURN | Lượt hiện tại, bắt đầu từ 1 trong Eq. (1) |
| \(\gamma\) | Discount DQN, thí nghiệm 0.98 |
| Eq. (1) | \(r_t = 20 \times 100^{-(\mathrm{TURN}-1)/\mathrm{MAXTURN}}\) khi nhãn benign |
| Eq. (2) | Loss TD của DQN |
| Eq. (3) | Detection rate = \(n/N\) trên VirusTotal |
| Eq. (4) | Evasive rate = \((N_{\mathrm{org}}-N_{\mathrm{adv}})/N_{\mathrm{org}}\) |
| Threshold 0.8 | Score detector > 0.8 mới gọi là malware |

---

## 13. Chỗ paper tự mâu thuẫn hoặc mơ hồ

Những điểm dưới đây **không đổi ý chính**, nhưng cần biết khi đọc số liệu hoặc tái hiện:

1. Mục lục: Literature = III, Methodology = IV. Thân bài: Literature = II, Methodology = III, Experimentation = IV.
2. \(\gamma\) lúc 0.9 (lý thuyết), lúc 0.98 (thí nghiệm).
3. Reward vừa Eq. (1) theo số lượt, vừa theo số engine VirusTotal.
4. Table 5 Random Forest sau retrain: bảng **57.9**, câu **57.6**.
5. Abstract “tăng 35%” sau retrain không khớp sát hiệu số Table 5.
6. Figure 4 vẽ SVM; Table 4 không có SVM.
7. Thư viện parse PE in **pelife**; thực tế **pefile**.
8. Table 3 tiêu đề “Actin space”.
9. Test set Table 2: 1000 malware, 0 benign — hợp lý cho đánh evasion, detector ML thì train trên 25k+10k.
10. Câu discussion về “21.8% to 35.5% lower” dễ chồng với hàng detection rate tuyệt đối của mô hình đề xuất trong Table 6.

---

## 14. Dòng chảy một mẫu, từ đầu đến cuối

1. Lấy file malware PE (backdoor hoặc ransomware).
2. `pefile` đọc Import Table + tên section → vector 3523 bit.
3. MalGAN (đã train 100 epoch) sinh vector adversarial: bit nào nên bật thêm.
4. Map bit → tên API / tên section, bỏ vào pool.
5. DQN nhận file gốc, tối đa 50 lượt:
   - thêm import từ pool GAN, hoặc
   - đổi tên / thêm section từ pool GAN, hoặc
   - nhét byte, pack/unpack UPX, append overlay.
6. Mỗi lượt: rebuild PE (PE Bliss) → hỏi detector (ngưỡng 0.8) hoặc VirusTotal.
7. Nhãn lành: thưởng Eq. (1), kết thúc thành công.
8. Nhãn độc: thưởng 0, sang lượt tiếp.
9. Hết 50 lượt: fail.
10. Mẫu thành công đưa vào Cuckoo; signatures khớp gốc thì vào tập adversarial.
11. Tập này đánh RF / GB / MLP / DT (Table 4), retrain (Table 5), và so MalFox / MAB-Malware trên VirusTotal (Table 6–7).

---

## 15. Liên hệ nhanh với repo local `CDPLMD`

Repo tái hiện không gian **3523 bit** (3269 import + 254 section), MalGAN OR-only, DQN 7 action, Eq. (1), Table 4–5, Cuckoo so signature. Table 6–7 (VirusTotal 61 engine) không chạy vì lab không upload. Binary VirusShare không dump lên host; vector malware lấy từ jsonl 25k.

---

*File này tóm tắt và giải thích toàn bộ nội dung kỹ thuật của paper 13 trang, theo PDF trong `CDPLMD`. Số liệu bảng lấy từ Table 2–7 in trong PDF.*
