import os
import sys
import setuptools


if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    sys.exit()


setuptools.setup(
    name='soteria',
    version='1.0.0',
    description="Configuration and security methods for the merchant API framework",
    long_description='see README',
    author='Bink',
    author_email='cprior@bink.com',
    url='http://gitlab.loyaltyangels.local/Olympus/soteria',
    packages=[
        'soteria',
    ],
    package_dir={'soteria': 'soteria'},
    package_data={
        'soteria': ['*.json']
    },
    include_package_data=True,
    install_requires=[
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
