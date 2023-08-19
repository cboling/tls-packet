#!/usr/bin/env bash
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

# load local python virtualenv if exists
VENVDIR=${VENVDIR:-venv}
PACKAGEDIR=${PACKAGEDIR:-packet}
PYVERSION ?= ${PYVERSION:-"3.8"}

if [ -e "${VENVDIR}/.built" ]; then
    . $VENVDIR/bin/activate
else
   echo "Creating python development environment"
 	 virtualenv --python=python${PYVERSION} -v ${VENVDIR} &&\
        source ./${VENVDIR}/bin/activate && set -u && \
        pip install --disable-pip-version-check -r ${PACKAGEDIR}/requirements.txt && \
        uname -s > ${VENVDIR}/.built
fi
