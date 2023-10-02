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
    # cfaulthandler calls some Python internal functions; it works on Python
    # 3.11, but isn't guaranteed to work with any other version
    python_requires = '==3.11.*',
)