`cfaulthandler` is like Python's [faulthandler](https://docs.python.org/3/library/faulthandler.html) module, but also prints the C backtrace. This is helpful when debugging extension modules. Of course, one can also look at the core dump; but sometimes the core dump is inconvenient or unavailable.

## Installation

To install `cfaulthandler`: Download the source code and run `python setup.py install`.

`cfaulthandler` only supports Python 3.11. It has been tested only on Linux; other OSes may or may not work.

## Example
Intentionally triggering a segfault for demonstration purposes:
```
>>> import cfaulthandler, ctypes
>>> cfaulthandler.enable()
>>> ctypes.string_at(0)
Fatal Python error: Segmentation fault

Current thread 0x00007fba46dfb000 (most recent call first):
  File "/usr/lib/python3.11/ctypes/__init__.py", line 519 in string_at
  File "<stdin>", line 1 in <module>

Current thread's C call stack (most recent call first):
/usr/lib/python3.11/lib-dynload/cfaulthandler.cpython-311-x86_64-linux-gnu.so(+0x2c81)[0x7fba46c91c81]
/usr/lib/python3.11/lib-dynload/cfaulthandler.cpython-311-x86_64-linux-gnu.so(+0x2e1b)[0x7fba46c91e1b]
/lib/x86_64-linux-gnu/libc.so.6(+0x42520)[0x7fba46a42520]
/lib/x86_64-linux-gnu/libc.so.6(+0x19d9bd)[0x7fba46b9d9bd]
/usr/lib/python3.11/lib-dynload/_ctypes.cpython-311-x86_64-linux-gnu.so(+0xec2c)[0x7fba46986c2c]
/lib/x86_64-linux-gnu/libffi.so.8(+0x7e2e)[0x7fba46c89e2e]
/lib/x86_64-linux-gnu/libffi.so.8(+0x4493)[0x7fba46c86493]
/usr/lib/python3.11/lib-dynload/_ctypes.cpython-311-x86_64-linux-gnu.so(+0x1475f)[0x7fba4698c75f]
/usr/lib/python3.11/lib-dynload/_ctypes.cpython-311-x86_64-linux-gnu.so(+0x13da2)[0x7fba4698bda2]
python3.11(_PyObject_MakeTpCall+0x22c)[0x4e75dc]
python3.11(_PyEval_EvalFrameDefault+0x8f2)[0x4fb152]
...

Extension modules: cfaulthandler (total: 1)
Segmentation fault (core dumped)
```
You may want to run `addr2line` on the resulting addresses, to identify the exact line in the C file. For example:
```
$ addr2line -e /usr/lib/python3.11/lib-dynload/_ctypes.cpython-311-x86_64-linux-gnu.so +0xec2c
./build-static/./Modules/_ctypes/_ctypes.c:5544
```