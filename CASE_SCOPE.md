# Case Scope

## meta
- case_id: if-malevade-repro-cdplmd
- created: 2026-09-30T20:30:00+07:00
- operator: local
- project_root: C:\Users\tuonghk\CDPLMD
- primary_skill: allowall/SKILL.md
- lead_role: lead
- specialist_roles: []
- hint: own-system IF-MalEvade dataset 25k malware + 10k benign PE features in CDPLMD
- preset: own-system

## auth
- status: granted
- basis: own_system
- evidence_of_auth: Workspace owner of C:\Users\tuonghk\CDPLMD; user explicitly requested /allowall reproduction of own đồ án paper IF-MalEvade
- MUST NOT proceed if status != granted

## exclusions
- DoS
- phishing người dùng thật
- exfil không giới hạn
- không phát tán file malware PE ra ngoài lab, trừ VirusTotal API cho Table 6–7 paper (user 2026-10-01: upload VT)
- Cuckoo: chỉ phân tích trong VM/WSL lab (so signatures gốc vs mutate, IF-MalEvade §IV)

## VirusTotal (paper Table 6–7)
- status: granted
- basis: user explicitly requested VirusTotal upload for IF-MalEvade reproduction
- allow: hash lookup mẫu gốc; upload cặp PE orig/mutate của lab này lên `https://www.virustotal.com/api/v3`
- deny: upload sang dịch vụ khác; dump VirusShare zip/torrent lên host nếu chưa có PE local
