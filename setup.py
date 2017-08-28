# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


with open('README.rst') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='vaultkeeper',
    version='0.0.1',
    description='A daemon that fetches and renews '
                + 'Vault credentials for Gunicorn-on-Docker'
                + 'Django applications',
    long_description=readme,
    author='mracter',
    author_email='paracetamolboy@gmail.com',
    url='https://github.com/praekeltfoundation/django-vaultkeeper',
    license=license,
    packages=find_packages(exclude=('tests', 'docs'))
)

