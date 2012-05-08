# -*- encoding: utf-8 -*-
import os
import setuptools
import sys

# TODO: Figuring out how we are going to do the versionning (and if
# any).
version = '1.0'
name = 'python-swiftclient'
requires = []


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

if sys.version_info < (2, 6):
    requires.append('simplejson')

setuptools.setup(
    name=name,
    version=version,
    description='Client Library for OpenStack Object Storage API',
    long_description=read('README.rst'),
    url='https://github.com/chmouel/python-swiftclient',
    license='Apache License (2.0)',
    author='OpenStack, LLC.',
    author_email='openstack-admins@lists.launchpad.net',
    packages=setuptools.find_packages(exclude=['tests', 'tests.*']),
    install_requires=requires,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.6',
        'Environment :: No Input/Output (Daemon)',
    ],
    test_suite='nose.collector',
    scripts=[
        'bin/swift',
    ],
)
