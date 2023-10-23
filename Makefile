.PHONY: run-download-api-specs

test-shellcheck:
	@echo "--- make: test-shellcheck"; \
		for file in $$(find . -type f -name "*.sh"); do \
			docker run \
				-v "$$PWD:/mnt" \
				koalaman/shellcheck:stable \
				"$$file"; \
		done

test: test-shellcheck

run-download-api-specs:
	@echo "--- make: run-download-api-specs"; \
		bash ./scripts/download-api-specs.sh

run: run-download-api-specs
