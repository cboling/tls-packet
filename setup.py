#!/usr/bin/env python3
# Copyright 2023, Boling Consulting Solutions
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
# limitations under the License.
#
# pylint: disable=missing-module-docstring

# Always prefer setuptools over distutils
from __future__ import absolute_import
from os import path
from glob import glob
from setuptools import setup, find_packages

PACKAGE = 'tls_packet'
setup_dir = path.dirname(path.abspath(__file__))
version_file = path.join(setup_dir, "VERSION")

# Get the long description from the README file
with open(path.join(setup_dir, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

with open(version_file) as version_file:
    version = version_file.read().strip()

requirements = open(path.join(setup_dir, "tls_packet/requirements.txt")).read().splitlines()
required = [line for line in requirements if not line.startswith("-")]

setup(
    name=PACKAGE,
    version=version,
    description='A python library for encoding and decoding TLS Packets',
    author='Chip Boling',
    author_email='chip@bcsw.net',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/cboling/tls-client',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    python_requires='>=3.8',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    py_modules=[path.splitext(path.basename(path))[0] for path in glob('tls-client/*.py')],
    install_requires=[required],
    include_package_data=True,
)
