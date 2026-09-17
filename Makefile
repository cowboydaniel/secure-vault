SBOM_DIR := build
SBOM_FILE := $(SBOM_DIR)/sbom.xml

.PHONY: sbom release-artifacts deps-update deps-test deps-dev compile test qt-test lint type-check validate clean

sbom: $(SBOM_FILE)

$(SBOM_FILE): requirements.txt
	mkdir -p $(SBOM_DIR)
	cyclonedx-py requirements requirements.txt --of XML -o $(SBOM_FILE)

release-artifacts: sbom
	mkdir -p release_artifacts
	cp $(SBOM_FILE) release_artifacts/sbom.xml
	echo "Stored SBOM at release_artifacts/sbom.xml"

deps-update:
	pip3 install -r requirements.txt
	$(MAKE) sbom

deps-test:
	pip3 install -r requirements-test.txt

deps-dev:
	pip3 install -r requirements-dev.txt

compile:
	python -m compileall -q .

test:
	QT_QPA_PLATFORM=offscreen python -m pytest

qt-test:
	QT_QPA_PLATFORM=offscreen python -m pytest tests/test_qt.py tests/test_gui.py tests/test_gui_regression.py tests/test_secure_clipboard.py

lint:
	python -m flake8 . --select=E9,F63,F7

type-check:
	python -m mypy --follow-imports=skip --ignore-missing-imports auth_secrets.py

validate: compile lint type-check test qt-test

clean:
	rm -rf $(SBOM_DIR) release_artifacts
