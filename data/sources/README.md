# Paper sources (IF-MalEvade §IV.B)

Dataset đang dùng là PE trong `data/pe/` (2.500 độc + 100 lành, DikeDataset). Thư mục `data/paper25k/` và `data/lab2500/` đã xóa.

Ba kho tải thô đã xóa sau khi parse xong, vì `run_experiment.py` không đọc chúng:

- `ember/` — 3 file `.tar.bz2` (2017 v1, 2017 v2, 2018 v2)
- `virusshare/` — catalog MD5 công khai
- `maldict/` — tag hành vi MalDICT

Muốn dựng lại jsonl từ đầu thì chạy `scripts/fetch_virusshare_vt.py`. Script tự tải lại các file đó.
