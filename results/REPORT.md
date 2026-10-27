# modelscan-eval report

- Corpus: `sha256:385b48c417f80e3c110e9e3bbfa54735b0e723f97369fe5d8ee94b5f5615bdd9` (41 items)
- Available scanners: `picklescan`, `modelscan`, `opcode_baseline`
- Unavailable scanners: none
- `picklescan` version: 1.0.5
- `modelscan` version: 0.8.8

## Leaderboard

| Scanner | Detection rate | False-positive rate | Scan errors |
|---|---:|---:|---:|
| picklescan | 11.1% (2/18) | 0.0% (0/18) | 0 |
| modelscan | 0.0% (0/18) | 0.0% (0/18) | 0 |
| opcode_baseline | 44.4% (8/18) | 0.0% (0/18) | 0 |

## Evasion robustness

| Scanner | indirect_aliased_global_import | nested_second_stage_payload | non_standard_reducer | opcode_level_obfuscation | protocol_framing_variance |
|---|---:|---:|---:|---:|---:|
| picklescan | 100.0% (1/1) | 100.0% (1/1) | 0.0% (0/1) | 0.0% (0/1) | 0.0% (0/1) |
| modelscan | 100.0% (1/1) | 100.0% (1/1) | 0.0% (0/1) | 0.0% (0/1) | 0.0% (0/1) |
| opcode_baseline | 100.0% (1/1) | 100.0% (1/1) | 100.0% (1/1) | 100.0% (1/1) | 100.0% (1/1) |
