"""
SMUDGE setup.py
"""

from setuptools import setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='smudge',
    version='1.0.1',
    description='Passive OS detection with dynamic signatures.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=["smudge"],
    py_modules=["smudge"],
    package_dir={'smudge': 'smudge'},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: System :: Networking :: Monitoring",
        "Natural Language :: English",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)"
    ],
    install_requires=[
        "scapy ~= 2.4.5",
        "colorama ~= 0.4.3"
    ],
    extras_require = {
        "dev": [
            "pylint>=2.15.0",
        ],
    },
    url="https://github.com/activecm/smudge",
    author="Dave Quartarolo",
    author_email="david@activecountermeasures.com",
)
