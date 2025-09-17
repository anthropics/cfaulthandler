from setuptools import setup, Extension
import platform
import sys
import sysconfig

# Determine platform-specific compile and link flags
extra_compile_args = []
extra_link_args = []
libraries = []

# Enable C stack trace support
extra_compile_args.extend([
    '-DHAVE_EXECINFO_H',
    '-DHAVE_BACKTRACE',
    '-DHAVE_DLFCN_H',
    '-DHAVE_DLADDR',
    '-DHAVE_SIGACTION',
    '-DHAVE_SIGALTSTACK',
])

# Get Python library to link against
python_lib = f"python{sys.version_info.major}.{sys.version_info.minor}"
lib_dir = sysconfig.get_config_var('LIBDIR')

# Platform-specific settings
if platform.system() == 'Linux':
    libraries.extend(['dl'])
    extra_compile_args.extend([
        '-DHAVE_LINUX_AUXVEC_H',
        '-DHAVE_SYS_AUXV_H',
        '-DHAVE_SYS_RESOURCE_H',
        '-DHAVE_UNISTD_H',
        '-DHAVE_PTHREAD_SIGMASK',
        '-DHAVE_PTHREAD_H',
    ])
    # Link against the Python shared library to resolve internal symbols
    extra_link_args.extend([
        f'-L{lib_dir}',
        f'-l{python_lib}',
        '-Wl,-rpath,{}'.format(lib_dir),
    ])
elif platform.system() == 'Darwin':  # macOS
    libraries.extend(['dl'])
    extra_compile_args.extend([
        '-DHAVE_SYS_RESOURCE_H',
        '-DHAVE_UNISTD_H',
        '-DHAVE_PTHREAD_SIGMASK',
        '-DHAVE_PTHREAD_H',
    ])
    # macOS handles symbols differently
    extra_link_args.extend([
        '-undefined', 'dynamic_lookup',
    ])

setup(
    name = 'cfaulthandler',
    version = '2.0',
    description = 'Like faulthandler, but also prints C backtraces',
    ext_modules = [
        Extension(
            'cfaulthandler',
            sources = ['cfaulthandler.c'],
            libraries = libraries,
            extra_compile_args = extra_compile_args,
            extra_link_args = extra_link_args,
        ),
    ],
    # cfaulthandler now works with Python 3.13
    python_requires = '>=3.13',
)