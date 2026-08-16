.PHONY: check test syntax shell capabilities index smoke

PYTHON ?= python3

check: syntax shell test capabilities index smoke

test:
	$(PYTHON) -m unittest discover -s tests -v

syntax:
	$(PYTHON) -m py_compile scripts/*.py tools/*.py tests/*.py

shell:
	bash -n agentsec install.sh install-deps.sh scripts/local_server_audit.sh

capabilities:
	$(PYTHON) tools/validate_skills.py

index:
	$(PYTHON) tools/build_skill_index.py

smoke:
	./agentsec --version
	./agentsec --help >/dev/null
	./agentsec capabilities >/dev/null
