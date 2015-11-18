#!/usr/bin/env python
import os

from setuptools import setup, find_packages

setup(name='pyramid_bricks',
      version='0.1',
      description='Common bricks for Pyramid framework',
      classifiers=[
          "Programming Language :: Python",
          "Framework :: Pyramid",
          "Topic :: Internet :: WWW/HTTP",
      ],
      author='Sherwood Wang',
      author_email='sherwood@wang.onl',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'jwt',
          'pyramid',
          'redis',
          'requests',
          'venusian',
          'zope.interface',
      ],
      )
