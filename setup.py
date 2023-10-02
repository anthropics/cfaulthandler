from setuptools import setup, Extension

setup(
    name = 'cfaulthandler',
    version = '1.0',
    description = 'Like faulthandler, but also prints C backtraces',
    ext_modules = [
        Extension(
            'cfaulthandler',
            sources = ['cfaulthandler.c'],
        ),
    ],
)