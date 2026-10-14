Lab này chạy 2.500 PE độc và 1.000 PE lành.

- `malware/` — 2.500 PE độc. 100 file được tách làm test, 2.400 file train.
- `benign/` — 1.000 PE lành. 100 file Dike (malice 0) cộng PE Windows trên máy cho đủ 1.000. Cả 1.000 vào train. Test không có mẫu lành.
- Đánh giá evasion dùng 50 file trong số 100 file test.

Mẫu độc và 100 file lành đầu đã lấy từ [DikeDataset](https://github.com/iosifache/DikeDataset) (MIT; PE gốc figshare CC BY 4.0), seed 42, chỉ `type = 0` và file bắt đầu bằng `MZ`. OLE bị loại. 900 file lành còn lại là PE từ System32, SysWOW64 và Program Files. Danh sách hash nằm ở `dike_manifest.json`.

2.500 PE độc: trojan 1.761, generic 733, worm 6. 100 PE lành Dike: mọi điểm malice bằng 0. Bốn file lành đuôi `.exe` không phải PE hợp lệ đã được thay bằng file PE khác trong cùng tập.

`data/paper25k/` và `data/lab2500/` đã xóa. Chưa dựng `dataset.npz` từ 2.600 file này.

File sửa ghi ở `data/cuckoo/work/`.
