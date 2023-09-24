# -------------------------------------------------------------------------
# Copyright 2023-2023, Boling Consulting Solutions, bcsw.net
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License
# -------------------------------------------------------------------------
#
#  Makefile method of doing things should you prefer
#
# Configure shell
SHELL = bash -eu -o pipefail

# Variables
THIS_MAKEFILE	:= $(abspath $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)))
WORKING_DIR		:= $(dir $(THIS_MAKEFILE) )
PACKAGE_DIR     := $(WORKING_DIR)/tls_packet
TEST_DIR        := $(WORKING_DIR)/test

include setup.mk

# Variables
VENVDIR         := venv
TESTVENVDIR		:= $(VENVDIR)-test
PYVERSION       ?= ${PYVERSION:-"3.11"}
PYTHON          := python${PYVERSION}

COVERAGE_OPTS	 = --with-xcoverage --with-xunit \
                   --cover-html --cover-html-dir=tmp/cover

PYLINT_DISABLES  = -d similarities -d broad-except -d missing-class-docstring
PYLINT_OPTS		 = -j 4 --exit-zero --rcfile=${WORKING_DIR}.pylintrc $(PYLINT_DISABLES)
PYLINT_OUT		 = $(WORKING_DIR)pylint.out

PYLAMA_DISABLES  =
PYLAMA_OPTS      = --async $(PYLAMA_DISABLES)
PYLAMA_OUT       = $(WORKING_DIR)pylama.out

LICENSE_OUT      = $(WORKING_DIR)license-check.out

.PHONY: venv test dist clean distclean upload

## Defaults
default: help		## Default operation is to print this help text

## Virtual Environment
venv: $(PACKAGE_DIR)/requirements.txt $(VENVDIR)/.built		    ## Application virtual environment

venv-test: $(TEST_DIR)/requirements.txt $(TESTVENVDIR)/.built   ## Unit-test/lint/... virtual environment

$(VENVDIR)/.built:
	@ ${PYTHON} -m venv ${VENVDIR}
	@ (source ${VENVDIR}/bin/activate && \
	    if python -m pip install --disable-pip-version-check -r $(PACKAGE_DIR)/requirements.txt; \
	    then \
	        uname -s > ${VENVDIR}/.built; \
	    fi)

$(TESTVENVDIR)/.built:
	@ ${PYTHON} -m venv ${TESTVENVDIR}
	@ (source ${TESTVENVDIR}/bin/activate && \
	    if python -m pip install --disable-pip-version-check -r test/requirements.txt; \
	    then \
	        python -m pip install --disable-pip-version-check pylint; \
	        uname -s > ${TESTVENVDIR}/.built; \
	    fi)

######################################################################
## License and security

show-licenses: venv							## Show licenses of imported modules
	@ (source ${VENVDIR}/bin/activate && \
       python -m pip install --upgrade --disable-pip-version-check pip-licenses && \
       pip-licenses 2>&1 | tee ${LICENSE_OUT})

bandit-test: venv-test						## Run security test on python source
	$(Q) echo "Running python security check with bandit on module code"
	@ (source ${TESTVENVDIR}/bin/activate && \
       python -m pip install --upgrade --disable-pip-version-check bandit && \
       bandit -n 3 -r $(PACKAGE_DIR))

bandit-test-all: venv bandit-test			## Run security test on python source and imported modules
	$(Q) echo "Running python security check with bandit on imports"
	@ (source ${TESTVENVDIR}/bin/activate && \
       python -m pip install --upgrade --disable-pip-version-check bandit && \
       bandit -n 3 -r $(WORKING_DIR)/${VENVDIR})

######################################################################
## Testing

test: venv-test		## Run tox-based unit tests
	$(Q) echo "Executing unit tests w/tox"
	@ python -m pip install --upgrade --disable-pip-version-check tox && \
	   . ${TESTVENVDIR}/bin/activate && tox

######################################################################
## Linting

lint: venv-test pylint-lint pylama-lint  ## Run lint on all sources and dockerfiles
	$(Q) echo "Installing pylint"
	$(Q) (source ${TESTVENVDIR}/bin/activate && \
       python -m pip install --upgrade --disable-pip-version-check pylint)

pylint-lint: venv-test     ## Run lint on PON Automation using pylint
	@ (source ${TESTVENVDIR}/bin/activate && \
       pylint ${PYLINT_OPTS} ${PACKAGE_DIR} 2>&1 | tee ${PYLINT_OUT} && \
       echo; echo "See \"file://${PYLINT_OUT}\" for lint report")

# Pylama is a document and code linter collection of other tools
pylama-lint: venv-test     ## Run lint on PON Automation using pylama
	$(Q) echo "Executing pylama"
	$(Q) (source ${TESTVENVDIR}/bin/activate && \
       python -m pip install --upgrade --disable-pip-version-check pylama[all] && \
       $(MAKE) app-pylama)

app-pylama: venv-test
	pylama ${PYLAMA_OPTS} ${PACKAGE_DIR} 2>&1 | tee ${PYLAMA_OUT}
	$(Q) echo
	$(Q) echo "See \"file://${PYLAMA_OUT}\" for pylama report"

######################################################################
# Release related (Lint ran last since it probably will have errors until
# the code is refactored (which is not planned at this time)
## Release and Publishing Procedures
release-check: distclean venv venv-test test bandit-test lint	## Clean distribution and run unit-test, security, and lint

dist:										## Create source distribution of the python package
	$(Q) echo "Creating python source distribution"
	rm -rf dist/
	python setup.py sdist

upload: clean lint test  dist	## Upload test version of python package to test.pypi.org
	$(Q) echo "Uploading sdist to legacy.pypi.org"
	${PYTHON} -m twine upload --repository tls-packet dist/*

######################################################################
## Utility
clean:		## Cleanup directory of build and test artifacts
	@ -rm -rf .tox *.coverage *.egg-info ${DOCKER_TARBALLNAME}.gz build/*.deb test/.pytest_cache ${PYLAMA_OUT} ${PYLINT_OUT} ${LICENSE_OUT}
	@ -find . -name '*.pyc' | xargs rm -f
	@ -find . -name '__pycache__' | xargs rm -rf
	@ -find . -name '__pycache__' | xargs rm -rf
	@ -find . -name 'htmlcov' | xargs rm -rf
	@ -find . -name 'junit-report.xml' | xargs rm -rf
	@ -find . -name 'coverage.xml' | xargs rm -rf
	@ -find . -name '.coverage' | xargs rm -rf

distclean: clean	## Cleanup all build, test, and virtual environment artifacts
	@ -rm -rf ${VENVDIR} ${TESTVENVDIR} ${BUILD_DIR}

help: ## Print help for each Makefile target
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${RESET} ${GREEN}<target> [<target> ...]${RESET}'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} { \
		if (/^[a-zA-Z_-]+:.*?##.*$$/) {printf "    ${YELLOW}%-23s${GREEN}%s${RESET}\n", $$1, $$2} \
		else if (/^## .*$$/) {printf "  ${CYAN}%s${RESET}\n", substr($$1,4)} \
		}' $(MAKEFILE_LIST)

# end file
