#!/usr/bin/env python3
# coding: utf-8

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='natchecker',
    version='0.2.1',
    author='onewesong',
    author_email='onewesong@gmail.com',
    url='https://github.com/onewesong/natchecker',
    description='check nat type by stun server.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=['argparse', 'ipaddress', 'netifaces'],
    entry_points={'console_scripts': [
        'natchecker=src.main:main',
    ]},
)
