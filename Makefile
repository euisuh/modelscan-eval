.PHONY: check eval report

check:
	python3 tools/safety_lint.py corpus/ && pytest

eval:
	mkdir -p results
	python3 -m eval.runner --scanner picklescan --scanner modelscan --scanner opcode_baseline > results/verdicts.jsonl

report:
	python3 -m eval.report
