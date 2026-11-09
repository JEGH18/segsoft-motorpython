PYTHON ?= python3
REPORT_DIR ?= reports

.PHONY: validate-engine

# Ejecuta la suite de validación del motor y genera validation-report.json y
# validation-report.md en $(REPORT_DIR). Sale con código distinto de 0 si algún
# fixture falla o las métricas no alcanzan validation-thresholds.yml.
validate-engine:
	VALIDATION_REPORT_DIR=$(REPORT_DIR) $(PYTHON) -m pytest tests/validation/ -v
