# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


with open('README.rst') as f:
    readme = f.read()

install_requires = [
                    'hvac==0.2.17',
                    'requests',
                    'subprocess32'
]

extras_require = {
        'test': [
            'pytest>=3.0.0',
            'responses',
            'pytest-cov',
        ]
}

dependency_links = [
    ('https://github.com/mracter/hvac/archive/'
        'b0811f0446760125baefea6383711035104e6df1.zip'
        '#egg=hvac-0.2.17+git.b817da4'),
]

setup(
    name='vaultkeeper',
    version='0.1.1',
    description='A daemon that fetches and renews '
                + 'Vault credentials for Gunicorn-on-Docker'
                + 'Django applications',
    long_description=readme,
    install_requires=install_requires,
    extras_require=extras_require,
    author='mracter',
    author_email='mary@praekelt.org',
    url='https://github.com/praekeltfoundation/vaultkeeper',
    license='BSD',
    packages=find_packages(),
    dependency_links=dependency_links,
    entry_points={
        'console_scripts': [
            'vaultkeeper = vaultkeeper.vaultkeeper:main'
        ]
    },
)
