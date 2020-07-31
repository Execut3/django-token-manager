import os
from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.md')).read()

setup(
    name='django-token-manager',
    version='1.0',
    packages=['token_manager'],
    description='A Django Rest Token Authentication system like telegram which will be using JWT as core with extended features.',
    long_description=README,
    author='Execut3',
    author_email='execut3.binarycodes@gmail.com',
    url='https://github.com/Execut3/django-token-manager',
    license='GPT',
    install_requires=[
        'Django>=2.0',
        'djangorestframework>=3.0',
        'djangorestframework-jwt>=1.1'
    ]
)