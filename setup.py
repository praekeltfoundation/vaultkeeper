# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

install_requires = ['setuptools==36.2.7',
                    'hvac==0.2.17+git.b817da4',
                    'requests==2.18.4',
                    'python_daemon==2.1.2',
                    ]
dependency_links = ['https://github.com/mracter/hvac/archive/b0811f0446760125baefea6383711035104e6df1.zip'
                    + '#egg=hvac-0.2.17+git.b817da4']

setup(
    name='vaultkeeper',
    version='0.0.1',
    description='An agent that fetches and renews '
                + 'Vault credentials for Gunicorn-on-Docker'
                + 'Django applications',
    long_description=readme,
    install_requires=install_requires,
    extras_require={
        'testing': [
            'pytest==3.2.1',
            'responses==0.7.0',
    ]},
    author='mracter',
    author_email='mary@praekelt.org',
    url='https://github.com/praekeltfoundation/vaultkeeper-agent',
    license=license,
    packages=find_packages(exclude=('tests', 'docs')),
    dependency_links=dependency_links
)

