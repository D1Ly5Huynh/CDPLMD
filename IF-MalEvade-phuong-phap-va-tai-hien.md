# IF-MalEvade — phương pháp paper và cách CDPLMD đang làm theo

**Paper:** Rahat Maqsood Arif et al. *A Deep Reinforcement Learning Framework to Evade Black-Box Machine Learning Based IoT Malware Detectors Using GAN-Generated Influential Features*. IEEE Access, vol. 11, pp. 133717–133729, 2023. DOI: [10.1109/ACCESS.2023.3334645](https://doi.org/10.1109/ACCESS.2023.3334645)

**Framework:** IF-MalEvade (Influential-Feature Malware Evasion)

**Repo tái hiện:** `C:\Users\tuonghk\CDPLMD` — package `if_malevade/`, runner `run_experiment.py`

**File giải thích paper (nội dung 13 trang):** `IF-MalEvade-paper-giai-thich.md`

Tài liệu này ghi **toàn bộ phương pháp** paper đang được bám, rồi map từng bước sang code lab.

---

## 1. Ý tưởng gốc, một mạch

Paper là khung **né detector malware học máy kiểu black-box**. Detector chỉ bị hỏi “độc hay lành”; không cần trọng số, kiến trúc hay dữ liệu train. Mục tiêu: sửa file Windows PE sao cho detector (và engine VirusTotal) gọi là lành, trong khi **hành vi độc còn nguyên** — Cuckoo so trường `signatures` của mẫu gốc và mẫu mutate.

Paper đứng giữa hai hướng cũ:

- **MalGAN** (Hu & Tan) sinh *vector* import trông lành, nhưng không ra file PE chạy được.
- **DQEAF** (Fang) dùng DRL sửa file PE thật, nhưng action space lấy toàn bộ import/section, agent học khó, sửa nhiều.

IF-MalEvade ghép hai cái: GAN feed-forward (import + section) sinh **tập feature có ảnh hưởng**, rồi DRL **chỉ sửa ít, đúng chỗ**, rebuild PE, hỏi detector, cuối cùng Cuckoo xác nhận hành vi.

Đóng góp paper tự nêu:

1. Evasion giữ chức năng, đánh độ bền detector IoT black-box.
2. Retrain detector bằng mẫu adversarial thì tỉ lệ bắt tăng.
3. GAN + DRL giúp huấn luyện với ít sửa hơn, sửa đúng chỗ hơn.
4. Trên VirusTotal tốt hơn MalFox và MAB-Malware.

“IoT” ở đây là bối cảnh: Windows (~70% desktop) còn chạy ATM, POS, thin client, công nghiệp, thiết bị y tế. Dataset thực tế là **Windows PE backdoor + ransomware**.

Repo `CDPLMD` đi theo đúng hai giai đoạn: **MalGAN lọc feature có ảnh hưởng → DQN chọn chuỗi sửa PE → detector ML + Cuckoo**.

---

## 2. Không gian đặc trưng (đầu vào của cả GAN và DRL)

Mỗi file PE được `pefile` parse thành **vector nhị phân**:

\[
x \in \{0,1\}^{3523},\quad 3523 = 3269\ \text{import} + 254\ \text{tên section}
\]

- Bit `1` = file có API/section đó.
- Bit `0` = không có.

Từ điển ánh xạ tên → chỉ số được dựng từ toàn bộ malware + benign. Detector ML nội bộ cũng train trên **cùng** không gian import + section.

**Ràng buộc cứng:** chỉ **thêm** bit (phép OR). Tắt import gốc là mất API malware thật sự gọi → file có thể chết hoặc đổi hành vi. Paper và code không xóa import gốc.

### Map sang CDPLMD

| Paper | `if_malevade/config.py` |
|-------|-------------------------|
| 3269 import + 254 section = 3523 | `n_imports=3269`, `n_sections=254`, `n_features=3523` |
| GAN 100 epoch, DQN 500 episode, MAXTURN 50 | `Config` mặc định, `python run_experiment.py` |

---

## 3. Giai đoạn A — MalGAN tạo “influential features”

Ba khối:

| Khối | Việc |
|------|------|
| **Generator G** | Nhận vector malware \(x\) + nhiễu \(z\) (10 chiều, Gaussian), ra vector “nên thêm gì” |
| **Discriminator D** | Học bắt chước detector black-box: độc hay lành |
| **Black-box detector** | Mô hình ML (paper và lab: Random Forest làm teacher cho GAN) |

Code: `if_malevade/malgan.py`.

### 3.1. Kiến trúc (paper §E)

- G: `[d + 10] → 256 (Leaky ReLU) → d (sigmoid)`
- D: `[d] → 256 (Leaky ReLU) → 1 (sigmoid)`
- Batch 32, **100 epoch** (preset `paper`)
- Chỉ **bật thêm** bit:

\[
x_{\mathrm{adv}} = x \lor \mathbf{1}(g \ge 0.5)
\]

Code: `hard_or` / `soft_or` — `malware + (1-malware)*gen`, rồi ngưỡng 0.5.

### 3.2. Vòng train

Mỗi batch:

1. Lấy malware \(m\), nhiễu \(z\), G ra \(g\).
2. `m_hard = hard_or(m, g)` — vector adversarial cứng.
3. D học nhãn của **detector đóng băng** trên `[benign; m_hard]`.
4. G muốn `D(m_adv) → 0` (lành). Gradient chỉ chảy vào bit **đang tắt** (`dL_dg = dL_dx * (1-m)`), nên G không được tắt import gốc.

### 3.3. Ra pool cho DQN

Sau train, G sinh adversarial trên malware. Những mẫu **né được detector** được giữ. Bit nào được **thêm** (từ 0→1) trên các mẫu thành công thì được đếm tần suất. Rank:

- Top import → `pools["imports"]`
- Top section → `pools["sections"]`

Pool là mọi bit GAN **thêm** (0→1) trên mẫu né được detector. Ba action đầu của DQN chỉ bốc ứng viên từ đây, từng bit một.

Output lab: `results/influential_features.json`.

---

## 4. Giai đoạn B — DRL mutate file (DQEAF-style)

Mô hình MDP. Code: `if_malevade/env.py`, `if_malevade/dqn.py`.

- **State \(s_t\)**: vector import + section (và 3 bit aux) hiện tại của file.
- **Action \(a_t\)**: 1 trong **7** phép sửa (Table 3).
- **MAXTURN = 50**. Hết 50 lượt vẫn độc → fail.
- **γ = 0.98** (đoạn thí nghiệm; đoạn lý thuyết paper viết 0.9).
- Agent: 2 hidden layer **256 rồi 64**, ReLU, 500 episode (preset `paper`).
- Loss: TD error bình phương, phương trình (2):

\[
\ell_t(\theta_t)=\bigl(r_{t+1}+\gamma\max_{a}Q(s_{t+1},a;\theta^-)-Q(s_t,a_t;\theta_t)\bigr)^2
\]

`dqn.py` dùng Q-network + target network (`tgt.copy_from` mỗi `target_sync` bước), replay buffer, ε-greedy từ 1.0 → 0.05.

### 4.1. Bảy action — Table 3

Map 1:1 với `env.ACTIONS` và `pe_mutate.py`.

| Paper | Code vector (`env.py`) | Code file PE (`pe_mutate.py`) | Lấy ứng viên từ GAN? |
|-------|------------------------|-------------------------------|----------------------|
| `insert_import` | `add_import` — bật **một** bit từ pool GAN | thêm hàm vào Import Table | Có |
| `insert_section` | `add_section` — bật **một** bit từ pool GAN | thêm section rỗng (LIEF) | Có |
| `rename_section` | `rename_section` — tắt 1 tên đang có, bật 1 tên từ pool | đổi tên section (LIEF/pefile) | Có |
| `section_append` | `add_unused_bytes` — bật bit aux unused | nhét byte vào vùng không execute | Không |
| `upx_pack` | `upx_pack` | nén UPX | Không |
| `upx_unpack` | `upx_unpack` | giải nén UPX | Không |
| `overly_append` | `append_bytes` | append overlay cuối file | Không |

Paper rebuild bằng **PE Bliss**. Lab rebuild bằng **LIEF + pefile + UPX**, cùng ý: sửa header/section/overlay, không chèn payload/shellcode.

Trên không gian vector, import gốc **không bị xóa**. `rename_section` là chỗ duy nhất được **đổi** một bit section (tắt tên cũ, bật tên pool).

### 4.2. Reward — phương trình (1)

Detector **vẫn độc** (score ≥ 0.8):

\[
r_t = 0
\]

Detector **gọi lành** (score < 0.8):

\[
r_t = 20 \times 100^{-(\mathrm{TURN}-1)/\mathrm{MAXTURN}}
\]

Né **sớm** → thưởng gần 20. Né gần lượt 50 → thưởng nhỏ. Mục tiêu: chuỗi sửa **ngắn**.

`env.success_reward()` cài đúng công thức này. Lượt chưa né: `r_t = 0`. Không có reward shaping.

Ngưỡng **0.8** lấy từ setup MAB-Malware. Paper và `Config.threshold` cùng dùng.

---

## 5. Cuckoo — cổng “fully-working malware”

Đây là điều kiện abstract: mẫu adversarial **còn chạy, còn độc**.

Cuckoo chạy file trong VM khách, cách ly host bằng virtual switch, ghi:

- **static:** string, hash, kích thước;
- **dynamic:** API, mạng, trường **signatures** (tạo file, tạo service, cấp phát bộ nhớ, …).

Paper so **signatures gốc vs mutate**. Khớp thì giữ mẫu. Không khớp thì loại, dù detector ML đã bị đánh lừa.

Code: `if_malevade/cuckoo_client.py` — `signatures_match()` giữ mutant khi **mọi** tên signature gốc còn xuất hiện trên mutant (`min_recall=1.0`).

Lab Cuckoo 3 (cert-ee) trên WSL2 Ubuntu 22.04 + QEMU. Guest **paper-min**: Win10 1703 + agent + `disableservices` (Defender/WU tắt) + Threemon + snapshot `win10vm_`. Không cài IE/.NET/Edge/Adobe — paper §IV chỉ cần guest chạy được để so signature.

---

## 6. Luồng một mẫu, từ đầu đến cuối (paper)

1. PE malware (backdoor/ransomware).
2. `pefile` → vector 3523 bit.
3. MalGAN (100 epoch) → pool import/section.
4. DQN tối đa 50 lượt, 7 action, rebuild PE Bliss.
5. Hỏi detector (ngưỡng 0.8) hoặc VirusTotal.
6. Nhãn lành → thưởng Eq. (1), kết thúc thành công.
7. Nhãn độc → thưởng 0, sang lượt tiếp.
8. Hết 50 lượt → fail.
9. Mẫu thành công đưa vào Cuckoo; signatures khớp gốc thì vào tập adversarial.
10. Tập này đánh RF / GB / MLP / DT (Table 4), retrain (Table 5), và so MalFox / MAB-Malware trên VirusTotal (Table 6–7).

---

## 7. Thực nghiệm paper (Section IV)

### 7.1. Dataset (Table 2)

- **25.000 malware** VirusShare + VirusTotal, họ **backdoor + ransomware**.
- **10.000 benign** PE sạch Windows 10 (VM + phần mềm phổ biến).
- Lọc nhãn: VirusTotal **61 engine**.
- Train: 25k độc + 10k lành. Test evasion: **1000 malware**, 0 benign.

### 7.2. Bốn detector sklearn

Random Forest, Gradient Boosting, MLP, Decision Tree — tham số mặc định. Train trên import + section.

MLP paper còn ghi learning rate 0.0003, 150 epoch, batch 50. `detectors.py` đặt `learning_rate_init=3e-4`, `mlp_max_iter=150`.

Đánh **500** cặp gốc–adversarial.

- **ODR** (Original Detection Rate) = tỉ lệ bắt malware gốc.
- **ADR** (Adversarial Detection Rate) = tỉ lệ bắt mẫu đã mutate.

**Adversarial retraining (Table 5):** train lại với adversarial từ **50%** eval + malware train còn lại (`retrain_frac=0.5` trong `pipeline.py`).

### 7.3. VirusTotal — phương trình (3)(4)

\[
\text{detection rate} = \frac{n}{N}
\]

\(n\) = số engine bắt mẫu, \(N\) = tổng engine.

\[
\text{evasive rate} = \frac{N_{\mathrm{org}} - N_{\mathrm{adv}}}{N_{\mathrm{org}}}
\]

So với **MalFox** và **MAB-Malware** trên cùng tập.

### 7.4. Số paper công bố (đối chiếu)

**Table 4–5**

| Detector | AUC | ODR | ADR | ADR sau retrain |
|----------|-----|-----|-----|-----------------|
| Decision Tree | 96.56 | 92.98 | 8.1 | 54.6 |
| Gradient Boosting | 95.85 | 95.24 | 13.56 | 48.1 |
| Multi-Layer Perceptron | 86.50 | 84.52 | 7.69 | 49.8 |
| Random Forest | 96.12 | 92.32 | 9.1 | 57.9 |

**Table 6 — detection rate VirusTotal**

| Benchmark | Average | Min | Max |
|-----------|---------|-----|-----|
| Original malware | 61.8 | 27.2 | 85.1 |
| MAB-Malware | 42.9 | 25.5 | 62.2 |
| MalFox | 30.2 | 21.9 | 49.7 |
| **IF-MalEvade** | **21.8** | **15.4** | **35.5** |

**Table 7 — evasion rate VirusTotal**

| Benchmark | Average | Min | Max |
|-----------|---------|-----|-----|
| MAB-Malware | 19.2 | 7.8 | 44.5 |
| MalFox | 38.2 | 10.2 | 61.9 |
| **IF-MalEvade** | **57.8** | **15.7** | **75.5** |

Thứ tự né VirusTotal theo paper: IF-MalEvade > MalFox > MAB-Malware.

---

## 8. Pipeline CDPLMD bám paper, từng bước

`run_experiment.py` → `if_malevade/pipeline.py` → `run()`:

1. **Load** `data/paper25k/dataset.npz` (3523 chiều; test 1000 malware / 0 benign).
2. **Fit 4 detector** sklearn (RF/GB/MLP/DT), lưu `models/detectors.joblib`. RF là black-box cho GAN.
3. **`MalGAN.train(rf, …)`** — OR-only, leaky, noise 10, hidden 256, 100 epoch.
4. **`influential_pools`** từ mẫu GAN né được → `results/influential_features.json`.
5. **`MalwareEnv` + `DQNAgent.train`** — 7 action, γ=0.98, 500 episode, MAXTURN=50, Eq. (1).
6. **`mutate`** 500 mẫu test (ε=0), ghi `adv_vectors.npy` / `orig_vectors.npy`.
7. **Table 4** ODR/ADR/AUC; **Table 5** retrain 50%. Table 6–7 (VirusTotal) không chạy.
8. Nếu Cuckoo lên: `CuckooClient.health()`; giữ mutant khi signatures khớp gốc.

```bash
python run_experiment.py
```

---

## 9. Bảng tra công thức và thuật ngữ

| Ký hiệu / thuật ngữ | Nghĩa |
|---------------------|--------|
| PE | Portable Executable, format `.exe`/`.dll` Windows |
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
| Threshold 0.8 | Score detector ≥ 0.8 mới gọi là malware |

---

## 10. File code tương ứng từng khối

| Khối paper | File |
|------------|------|
| Hyperparameter / preset | `if_malevade/config.py` |
| Dataset 3523-d, Table 2 split | `if_malevade/data.py` |
| MalGAN + influential pool | `if_malevade/malgan.py` |
| MLP G/D/Q | `if_malevade/nn.py` |
| 7 action trên vector + Eq. (1) | `if_malevade/env.py` |
| DQN agent, replay, Eq. (2) | `if_malevade/dqn.py` |
| 7 action trên file PE lab | `if_malevade/pe_mutate.py` |
| RF / GB / MLP / DT, threshold 0.8 | `if_malevade/detectors.py` |
| ODR/ADR, eq. 3–4 | `if_malevade/metrics.py` |
| Cuckoo REST + so signature | `if_malevade/cuckoo_client.py` |
| Pipeline Table 4–7 | `if_malevade/pipeline.py` |
| Entry | `run_experiment.py` |

---

## 11. Chỗ lab khác paper (còn lại)

Những phần phương pháp **đã cài trong code**: vector import+section, MalGAN OR-only, pool influential, DQN 7 action, Eq. (1), γ=0.98, MAXTURN=50, 4 detector, threshold 0.8, retrain 50%, Cuckoo client so signature.

Những phần **chưa khớp vì ràng buộc lab** (không còn lệch kiến trúc):

1. **25k PE nhị phân VirusShare** — không dump binary lên host. Vector 25k lấy từ `malware_raw.jsonl` (EMBER import/section, họ ransom/backdoor) + 10k PE lành local.
2. Pipeline mutate **trên vector 3523**; `pe_mutate.py` sửa PE lab khi so Cuckoo.
3. **VirusTotal 61 engine** và so MalFox / MAB-Malware — không upload. Table 6–7 ghi `not_run`.
4. Rebuild PE: LIEF/pefile thay PE Bliss.

Cuckoo đúng vai trò paper §IV: guest Win10 tối thiểu, so `signatures` orig vs mutant.

---

## 12. Chỗ paper tự mâu thuẫn (khi đọc số liệu)

Không đổi ý chính phương pháp, cần biết khi đối chiếu bảng:

1. Mục lục: Literature = III, Methodology = IV. Thân bài: Literature = II, Methodology = III, Experimentation = IV.
2. \(\gamma\) lúc 0.9 (lý thuyết), lúc 0.98 (thí nghiệm) — lab lấy **0.98**.
3. Reward vừa Eq. (1) theo số lượt, vừa theo số engine VirusTotal.
4. Table 5 Random Forest sau retrain: bảng **57.9**, câu **57.6**.
5. Abstract “tăng 35%” sau retrain không khớp sát hiệu số Table 5.
6. Figure 4 vẽ SVM; Table 4 không có SVM.
7. Thư viện parse PE in **pelife**; thực tế **pefile**.
8. Table 3 tiêu đề “Actin space”.
9. Test set Table 2: 1000 malware, 0 benign — hợp lý cho đánh evasion.

---

*Xuất từ giải thích phương pháp khi tái hiện IF-MalEvade trong `CDPLMD`. Số liệu Table 2–7 lấy từ PDF paper.*
