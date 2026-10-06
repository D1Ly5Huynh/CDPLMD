# Snapshot lab — 2026-10-01 17:09 +07

Máy sắp tắt: RAM/process mất. File dưới đây **đã nằm trên đĩa**, không mất.

## An toàn khi tắt máy

| Việc | Trên đĩa | Sau khi bật lại |
|------|----------|-----------------|
| `data/paper25k/malware_raw.jsonl` + `benign_raw.jsonl` | Có (25k + 10k) | Giữ nguyên |
| `data/paper25k/dataset.npz` | Có, 3523-d, train 34000 / test 1000 | Giữ nguyên, **không cần rebuild** |
| Lookup VirusTotal hash gốc | `results/vt_original_reports.jsonl` **87 dòng** (HTTP 200) | Resume được |
| `run_experiment.py` (fit 4 detector) | **Chưa ghi** Table 4/5, chưa `models/detectors.joblib` | Phải chạy **lại từ đầu** |
| Cuckoo API/backend | Đã tắt trước đó | Guest snapshot Win10 vẫn trong WSL |
| `data/vt.api` | Có (gitignore) | Giữ nguyên |

## VirusTotal — 87 / 500

- File: `results/vt_original_reports.jsonl`
- Cách ghi: mỗi hash một dòng, flush ngay → tắt máy không làm hỏng các dòng đã xong.
- Hash cuối lúc snapshot: `c7e92917ac8bd7f7…` n=49, ok.

Bật máy xong, **đừng xóa jsonl**, chạy:

```powershell
cd C:\Users\tuonghk\CDPLMD
python -u scripts\vt_table67.py --eval-n 500
```

Script bỏ qua hash đã có trong jsonl, tiếp từ ~88.

## Thí nghiệm Table 4–5 — chưa có checkpoint

Log lúc snapshot:

```
paper features=3523 gan_epochs=100 episodes=500 eval_n=500 max_turn=50
load source=paper25k Xtr=(34000, 3523) Xte=(1000, 3523) mal_tr=24000 mal_te=1000
fit 4 detectors...
```

Chưa xong fit detector nên không lưu model. Tắt máy = mất tiến độ RAM. Sau khi bật:

```powershell
cd C:\Users\tuonghk\CDPLMD
$env:PYTHONUNBUFFERED = '1'
python -u run_experiment.py
```

Kết quả kỳ vọng: `results/table4_ml_detectors.csv`, `table5_adversarial_retrain.csv`, `summary.json`.

## Không mất khi tắt

- Code `if_malevade/`, `run_experiment.py`
- Dataset vector paper25k
- 87 report VT gốc
- CASE_SCOPE, giải thích phương pháp
