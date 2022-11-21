# -*- coding: utf-8 -*-
# pylint: disable=missing-module-docstring
from setuptools import setup

packages = ["tricore_backtrace"]

package_data = {"": ["*"]}

install_requires = [
    "coloredlogs>=15.0.1",
    "pyelftools>=0.29.0",
    "argparse>=1.4.0,<2.0.0",
    "datetime>=4.2,<5.0",
    "uuid==1.30",
    "htmlmin>=0.1.12",
    "intelhex>=2.3.0",
    "py-dateutil>=2.2",
    "typing>=3.7.4.3",
    "typing_extensions>=4.4.0",
]

entry_points = {"console_scripts": ["tricore_backtrace = tricore_backtrace.cli:main"]}

setup(
    name="tricore-backtrace",
    version="0.1.0",
    description="Parser for tricore backtraces",
    author="Martin Lampacher",
    author_email="martin.lampacher@gmail.com",
    maintainer="None",
    maintainer_email="None",
    packages=packages,
    package_data=package_data,
    install_requires=install_requires,
    entry_points=entry_points,
    python_requires=">=3.6,<4.0",
)
