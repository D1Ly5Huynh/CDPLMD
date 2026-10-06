# Dataset — IF-MalEvade §IV.B Table 2

- 25.000 malware (backdoor + ransomware) + 10.000 benign Windows PE.
- Vector **3523 bit**: 3269 import + 254 tên section. Không bit phụ.
- Split: train = malware còn lại + 10k benign; test = **1000 malware / 0 benign**.
- Malware jsonl: feature EMBER (import/section), họ ransom/backdoor. Không binary VirusShare trên host.
- Benign: PE Windows local (System32 / SysWOW64 / Program Files).
