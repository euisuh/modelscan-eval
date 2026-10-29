# modelscan-eval report

- Corpus: `sha256:daa6dd0a7c7f46d7aaefaa2f340a942b4d991213661dd247c33db0b6c20a439f` (47 items)
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

## Control group (known-dangerous global, harmless echo)

| Scanner | Base | indirect_aliased_global_import | nested_second_stage_payload | non_standard_reducer | opcode_level_obfuscation | protocol_framing_variance |
|---|---:|---:|---:|---:|---:|---:|
| picklescan | 100.0% (1/1) | 100.0% (1/1) | 100.0% (1/1) | 100.0% (1/1) | 100.0% (1/1) | 100.0% (1/1) |
| modelscan | 100.0% (1/1) | 100.0% (1/1) | 100.0% (1/1) | 100.0% (1/1) | 100.0% (1/1) | 100.0% (1/1) |
| opcode_baseline | 100.0% (1/1) | 100.0% (1/1) | 100.0% (1/1) | 100.0% (1/1) | 100.0% (1/1) | 100.0% (1/1) |
