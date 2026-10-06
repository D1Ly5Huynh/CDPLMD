# Paper sources (IF-MalEvade §IV.B)

Malware in the paper comes from **VirusShare + VirusTotal**. This folder stores only public metadata:

| Path | What |
| --- | --- |
| `maldict/` | MalDICT behavior tags: VirusShare chunks 0–465, labeled from VirusTotal reports (ClarAVy). JSONL `{md5, ranking}`. |
| `virusshare/` | Public MD5 lists from https://virusshare.com/hashfiles/ (no sample zips). |

Import/section vectors for matching hashes are taken from EMBER raw features (VirusTotal-side static PE). Live malware PE / VirusShare torrents are not downloaded.
