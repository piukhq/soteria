import os
import sys
import setuptools


if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    sys.exit()


setuptools.setup(
    name='soteria',
    version='1.1.0',
    description="Configuration and security methods for the merchant API framework",
    long_description='see README',
    author='Bink',
    author_email='cprior@bink.com',
    url='http://gitlab.loyaltyangels.local/Olympus/soteria',
    packages=setuptools.find_packages(exclude=['tests']),
    package_dir={'soteria': 'soteria'},
    include_package_data=True,
    install_requires=[
        'certifi>=2018.8.24',
        'chardet>=3.0.4',
        'hashids>=1.2.0',
        'hvac>=0.6.4',
        'idna>=2.7',
        'pycryptodome>=3.6.6',
        'requests>=2.19.1',
        'urllib3>=1.23',
    ],
    license="Internal",
    zip_safe=False,
    keywords='configuration security',
    classifiers=[
        'Development Status :: 1 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: Internal',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.6',
    ],
    test_suite='tests',
)
