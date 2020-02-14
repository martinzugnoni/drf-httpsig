#!/usr/bin/env python
from setuptools import setup, find_packages

# create long description
with open('README.rst') as file:
    long_description = file.read()
with open('CHANGELOG.rst') as file:
    long_description += '\n\n' + file.read()

# Tox testing command
from setuptools.command.test import test as TestCommand
import sys

setup(
    name='drf-httpsig',
    description='HTTP Signature support for Django REST framework',
    long_description=long_description,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        'Framework :: Django',
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.8.0",
        "Programming Language :: Python :: 3.7.5",
        "Programming Language :: Python :: 3.6.9",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    author='Adam Knight',
    author_email='adam@movq.us',
    url='https://github.com/ahknight/drf-httpsig',
    license='MIT',
    packages=find_packages(),
    zip_safe=True,
    use_scm_version=True,
    setup_requires=['pytest-runner', 'setuptools_scm'],
    tests_require=[
        'pytest',
        'pytest-django',
        'freezegun'
    ],
    install_requires=[
        'djangorestframework>3',
        'django>=1.11',
        'httpsig>=1.3.0'
    ]
)
