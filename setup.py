import os
from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.md')).read()

setup(
    name='django-token-manager',
    version='1.1.2',
    packages=['token_manager'],
    description='A Django Rest Token Authentication system like telegram which will be using JWT as core with extended features.',
    long_description=README,
    long_description_content_type='text/markdown',
    author='Execut3',
    author_email='execut3.binarycodes@gmail.com',
    url='https://github.com/Execut3/django-token-manager',
    license='GPT',
    install_requires=[
        'Django>=2.0',
        'djangorestframework>=3.0',
        'django-jalali>=3.1.0',
        'django-rest-captcha==0.1.0',
        'django-user-agents>=0.3.2',
    ],
    package_data={
        'token_manager': ['migrations/*'],
    },
)
