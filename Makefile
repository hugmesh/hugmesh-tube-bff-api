# HugMesh tube-bff — developer Makefile.
#
# `make pentest` runs the repo-local OWASP self-scan that MIRRORS the CI pentest
# stage (.gitlab-ci.yml -> the generator's pentest-stage.gitlab-ci.yml):
#   * SCA  : OWASP Dependency-Check over this Maven project (offline-capable;
#            mirrors the .pentest-sca CI job).
#   * DAST : when $DAST_TARGET_URL is set, delegate to the shared pen-test
#            harness (tests/pentest/run-pentest.sh in hugmesh-generator), the
#            SAME driver .pentest-dast-baseline runs (full probes + nuclei).
#
# It is self-contained and does NOT hard-fail when no target / tooling is
# present — it skips with a note so `make pentest` is safe to run anywhere.

SHELL := /usr/bin/env bash

# CVSS gate for the local SCA self-scan. CI's .pentest-sca uses 7; the local
# self-scan defaults to a looser 9 (per the pentest standard's repo-local
# `make pentest` contract) so devs aren't blocked on transitive advisories.
PENTEST_SCA_CVSS ?= 9

# Where the shared DAST harness lives. Defaults to a sibling generator checkout;
# override PENTEST_HARNESS_DIR to point at a vendored / cloned harness.
PENTEST_HARNESS_DIR ?= ../hugmesh-generator/tests/pentest
PENTEST_HARNESS_REPO ?= https://github.com/hugmesh-net/hugmesh-generator.git

.PHONY: pentest pentest-sca pentest-dast

# Full local pen-test mirror: SCA self-scan, then DAST when a target is set.
pentest: pentest-sca pentest-dast

# SCA — OWASP Dependency-Check over this Maven project (mirrors CI .pentest-sca).
pentest-sca:
	@echo "[pentest] SCA: OWASP Dependency-Check (failBuildOnCVSS=$(PENTEST_SCA_CVSS))"
	./mvnw -B org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=$(PENTEST_SCA_CVSS)
	@echo "[pentest] SCA complete — report under target/dependency-check-report.*"

# DAST — delegate to the shared harness, the SAME run-pentest.sh CI invokes.
# No $DAST_TARGET_URL => skip cleanly (don't hard-fail in a no-target dev run).
pentest-dast:
	@if [ -z "$$DAST_TARGET_URL" ]; then \
		echo "[pentest] DAST: \$$DAST_TARGET_URL not set — skipping authenticated ZAP DAST."; \
		echo "[pentest] DAST: set DAST_TARGET_URL=<gateway-url> to run the full harness:"; \
		echo "[pentest]   ZAP_TARGET=\$$DAST_TARGET_URL bash $(PENTEST_HARNESS_DIR)/run-pentest.sh --env compose --scan baseline --pipeline main"; \
		echo "[pentest]   (harness missing? git clone $(PENTEST_HARNESS_REPO) and point PENTEST_HARNESS_DIR at tests/pentest)"; \
		exit 0; \
	fi; \
	if [ ! -f "$(PENTEST_HARNESS_DIR)/run-pentest.sh" ]; then \
		echo "[pentest] DAST: harness not found at $(PENTEST_HARNESS_DIR)/run-pentest.sh — skipping."; \
		echo "[pentest]   clone it: git clone $(PENTEST_HARNESS_REPO) (then PENTEST_HARNESS_DIR=<repo>/tests/pentest)"; \
		exit 0; \
	fi; \
	echo "[pentest] DAST: running shared harness against $$DAST_TARGET_URL"; \
	ZAP_TARGET="$$DAST_TARGET_URL" bash "$(PENTEST_HARNESS_DIR)/run-pentest.sh" --env compose --scan baseline --pipeline main
