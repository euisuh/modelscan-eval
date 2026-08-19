# modelscan-eval report

- Corpus: `sha256:385b48c417f80e3c110e9e3bbfa54735b0e723f97369fe5d8ee94b5f5615bdd9` (41 items)
- Available scanners: `opcode_baseline`
- Unavailable scanners: `picklescan`, `modelscan`

## Leaderboard

| Scanner | Detection rate | False-positive rate |
|---|---:|---:|
| picklescan | no data | no data |
| modelscan | no data | no data |
| opcode_baseline | 38.9% | 0.0% |

## Evasion robustness

| Scanner | indirect_aliased_global_import | nested_second_stage_payload | non_standard_reducer | opcode_level_obfuscation | protocol_framing_variance |
|---|---:|---:|---:|---:|---:|
| picklescan | no data | no data | no data | no data | no data |
| modelscan | no data | no data | no data | no data | no data |
| opcode_baseline | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% |
