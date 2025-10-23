SBOM_DIR := build
SBOM_FILE := $(SBOM_DIR)/sbom.xml

.PHONY: sbom release-artifacts deps-update clean

sbom: $(SBOM_FILE)

$(SBOM_FILE): requirements.txt
	mkdir -p $(SBOM_DIR)
	cyclonedx-py --requirements requirements.txt --format xml --output $(SBOM_FILE)

release-artifacts: sbom
	mkdir -p release_artifacts
	cp $(SBOM_FILE) release_artifacts/sbom.xml
	echo "Stored SBOM at release_artifacts/sbom.xml"

deps-update:
	pip3 install -r requirements.txt
	$(MAKE) sbom

clean:
	rm -rf $(SBOM_DIR) release_artifacts
