#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name='MausoleumClient',
      version='0.1',
      description='Client for MausoleumServer',
      author='Alex Chernyakhovsky, Drew Dennison, and Patrick Hurst',
      author_email='mausoleum@mit.edu',
      url='https://github.com/mausoleum/mausoleum-client',
      packages=find_packages(),
      test_suite='MausoleumClient.crypto.test',
     )
