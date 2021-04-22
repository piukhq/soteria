import os
import sys
import setuptools


if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    sys.exit()


setuptools.setup(
    name='soteria',
    version='1.4.0',
    description="Configuration and security methods for the merchant API framework",
    long_description_content_type="text/markdown",
    long_description='see README',
    author='Bink',
    author_email='cprior@bink.com',
    url='http://git.bink.com/Olympus/soteria',
    packages=setuptools.find_packages(exclude=['tests']),
    package_dir={'soteria': 'soteria'},
    include_package_data=True,
    install_requires=[
        'hashids>=1.3.1',
        'pycryptodome>=3.10.1',
        'requests>=2.25.1',
        'PGPy>=0.5.3',
        'azure-identity>=1.5.0',
        'azure-keyvault-secrets>=4.2.0',
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
