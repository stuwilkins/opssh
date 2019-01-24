#!/usr/bin/env python

from setuptools import setup

setup(name='opssh',
      version='0.1',
      description='Python library for interfacing with 1password and ssh keys',
      author='Stuart B. Wilkins',
      author_email='stuart@stuwilkins.org',
      packages=['opssh'],
      entry_points = {
        'console_scripts': ['opssh_askpass=opssh.command_line:askpass',
                            'opssh=opssh.command_line:add_keys_to_agent'],
        }
     )
