.PHONY: check

check:
	python tools/safety_lint.py corpus/ && pytest
