# -*- coding: utf-8 -*-
from setuptools import setup

packages = ['tricore_backtrace']

package_data = {'': ['*']}

install_requires = [
    "airspeed",
    "coloredlogs",
    "pyelftools>=0.29.0",
    "argparse>=1.4.0,<2.0.0",
    "datetime>=4.2,<5.0",
    "uuid==1.30",
    "htmlmin>=0.1.12",
    "py-dateutil>=2.2",
    ]

entry_points = {'console_scripts': ['tricore_backtrace = tricore_backtrace.cli:main']}

setup(
    name='tricore-backtrace',
    version='0.1.0',
    description='Parser for tricore backtraces',
    author='Martin Lampacher',
    author_email='martin.lampacher@gmail.com',
    maintainer='None',
    maintainer_email='None',
    packages=packages,
    package_data=package_data,
    install_requires=install_requires,
    entry_points=entry_points,
    python_requires='>=3.6,<4.0',
    )
