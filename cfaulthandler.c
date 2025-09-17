/*
Note: cfaulthandler.c was forked from the builtin Python module faulthandler.c:
https://github.com/python/cpython/blob/v3.13.0/Modules/faulthandler.c

The main change is to print the C call stack in addition to the Python call
stack. In addition, some changes were needed to adapt cfaulthandler to run as a
3rd-party module, rather than being built into the Python interpreter like
faulthandler is.

Copyright (c) 2001-2023 Python Software Foundation; All Rights Reserved
*/

#include "Python.h"
#include <signal.h>               // sigaction()
#include <stdlib.h>               // abort()

#ifdef HAVE_UNISTD_H
#  include <unistd.h>             // _exit()
#endif

#if defined(HAVE_PTHREAD_SIGMASK) && !defined(HAVE_BROKEN_PTHREAD_SIGMASK) && defined(HAVE_PTHREAD_H)
#  include <pthread.h>
#endif

#ifdef MS_WINDOWS
#  include <windows.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>       // setrlimit()
#endif

/* For C stack trace support */
#ifdef HAVE_EXECINFO_H
#  include <execinfo.h>
#endif

#ifdef HAVE_DLFCN_H
#  include <dlfcn.h>
#  ifndef HAVE_DLADDR
#    ifdef __linux__
#      define HAVE_DLADDR 1
#    endif
#  endif
#endif

/* Check if we can use C backtrace */
#if defined(HAVE_EXECINFO_H) && defined(HAVE_BACKTRACE) && defined(HAVE_DLFCN_H)
#  if defined(__APPLE__) && defined(HAVE_DLADDR)
#    define CAN_C_BACKTRACE 1
#  elif defined(__linux__) && defined(HAVE_DLADDR)
#    define CAN_C_BACKTRACE 1
#  endif
#endif

/* Using an alternative stack requires sigaltstack()
   and sigaction() SA_ONSTACK */
#if defined(HAVE_SIGALTSTACK) && defined(HAVE_SIGACTION)
#  define CFAULTHANDLER_USE_ALT_STACK
#endif

#if defined(CFAULTHANDLER_USE_ALT_STACK) && defined(HAVE_LINUX_AUXVEC_H) && defined(HAVE_SYS_AUXV_H)
#  include <linux/auxvec.h>       // AT_MINSIGSTKSZ
#  include <sys/auxv.h>           // getauxval()
#endif

/* Allocate at maximum 100 MiB of the stack to raise the stack overflow */
#define STACK_OVERFLOW_MAX_SIZE (100 * 1024 * 1024)

#ifndef MS_WINDOWS
   /* register() is useless on Windows, because only SIGSEGV, SIGABRT and
      SIGILL can be handled by the process, and these signals can only be used
      with enable(), not using register() */
#  define CFAULTHANDLER_USER
#endif

#define PUTS(fd, str) (void)_Py_write_noraise(fd, str, strlen(str))

/* Maximum number of C stack frames to dump */
#define CFAULTHANDLER_MAX_C_FRAMES 100

/* Clang and GCC 9.0+ use __attribute__((no_sanitize("undefined"))) */
#if defined(__has_feature)
#  if __has_feature(undefined_behavior_sanitizer)
#    define _Py_NO_SANITIZE_UNDEFINED __attribute__((no_sanitize("undefined")))
#  endif
#endif

/* GCC 4.9+ uses __attribute__((no_sanitize_undefined)) */
#if !defined(_Py_NO_SANITIZE_UNDEFINED) && defined(__GNUC__) \
    && ((__GNUC__ >= 5) || (__GNUC__ == 4) && (__GNUC_MINOR__ >= 9))
#  define _Py_NO_SANITIZE_UNDEFINED __attribute__((no_sanitize_undefined))
#endif
#ifndef _Py_NO_SANITIZE_UNDEFINED
#  define _Py_NO_SANITIZE_UNDEFINED
#endif

/* Define Py_NSIG if not defined */
#ifdef _SIG_MAXSIG
   // gh-91145: On FreeBSD, <signal.h> defines NSIG as 32: it doesn't include
   // realtime signals: [SIGRTMIN,SIGRTMAX]. Use _SIG_MAXSIG instead.
#  define Py_NSIG _SIG_MAXSIG
#elif defined(NSIG)
#  define Py_NSIG NSIG
#elif defined(_NSIG)
#  define Py_NSIG _NSIG            // BSD/SysV
#elif defined(_SIGMAX)
#  define Py_NSIG (_SIGMAX + 1)    // QNX
#elif defined(SIGMAX)
#  define Py_NSIG (SIGMAX + 1)     // djgpp
#else
#  define Py_NSIG 64               // Use a reasonable default value
#endif

#ifdef HAVE_SIGACTION
typedef struct sigaction _Py_sighandler_t;
#else
typedef PyOS_sighandler_t _Py_sighandler_t;
#endif

/* The built-in faulthandler module uses these internal Python functions for
   printing stack traces. Since we're a third-party module, we need to provide
   our own implementations or use alternatives when available. */

/* Check if these symbols are available (they might be in some Python builds) */
#ifdef HAVE_PY_INTERNAL_SYMBOLS
extern void _Py_DumpExtensionModules(int fd, PyInterpreterState *interp);
extern const char* _Py_DumpTracebackThreads(int fd, PyInterpreterState *interp, PyThreadState *current_thread);
extern void _Py_DumpTraceback(int fd, PyThreadState *tstate);
extern void _Py_DumpHexadecimal(int fd, uintptr_t value, Py_ssize_t width);
extern void _Py_DumpDecimal(int fd, size_t value);
extern void _Py_DumpASCII(int fd, PyObject *text);
extern int _Py_write_noraise(int fd, const void *buf, size_t count);
#else

/* Provide our own implementations for third-party module use */
#include <unistd.h>
#include <stdio.h>

static int _Py_write_noraise(int fd, const void *buf, size_t count) {
    ssize_t res;
    do {
        res = write(fd, buf, count);
    } while (res < 0 && errno == EINTR);
    return res >= 0 ? (int)res : -1;
}

static void _Py_DumpHexadecimal(int fd, uintptr_t value, Py_ssize_t width) {
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%0*lx", (int)width, (unsigned long)value);
    _Py_write_noraise(fd, buffer, strlen(buffer));
}

static void _Py_DumpDecimal(int fd, size_t value) {
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%zu", value);
    _Py_write_noraise(fd, buffer, strlen(buffer));
}

static void _Py_DumpASCII(int fd, PyObject *text) {
    if (!PyUnicode_Check(text))
        return;

    Py_ssize_t size;
    const char *str = PyUnicode_AsUTF8AndSize(text, &size);
    if (str != NULL) {
        _Py_write_noraise(fd, str, size);
    }
}

/* Internal helper to dump traceback without header */
static void dump_traceback_internal(int fd, PyThreadState *tstate) {
    if (tstate == NULL) {
        PUTS(fd, "  <no Python thread state>\n");
        return;
    }

    /* Try to get the current frame */
    PyFrameObject *frame = PyThreadState_GetFrame(tstate);
    if (frame == NULL) {
        PUTS(fd, "  <no current frame>\n");
        return;
    }

    /* Walk the frame stack and dump each frame */
    int depth = 0;
    while (frame != NULL && depth < 100) {
        PyCodeObject *code = PyFrame_GetCode(frame);
        if (code != NULL) {
            /* Get filename */
            const char *filename = PyUnicode_AsUTF8(code->co_filename);
            if (filename == NULL) {
                filename = "???";
            }

            /* Get function name */
            const char *funcname = PyUnicode_AsUTF8(code->co_name);
            if (funcname == NULL) {
                funcname = "???";
            }

            /* Get line number */
            int lineno = PyFrame_GetLineNumber(frame);

            /* Write the frame info - truncate long function names */
            PUTS(fd, "  File \"");
            PUTS(fd, filename);
            PUTS(fd, "\", line ");
            _Py_DumpDecimal(fd, lineno);
            PUTS(fd, " in ");

            /* Truncate function name if too long (500 chars max) */
            size_t funcname_len = strlen(funcname);
            if (funcname_len > 500) {
                char truncated[504];
                memcpy(truncated, funcname, 500);
                strcpy(truncated + 500, "...");
                PUTS(fd, truncated);
            } else {
                PUTS(fd, funcname);
            }
            PUTS(fd, "\n");

            Py_DECREF(code);
        }

        /* Get the previous frame */
        PyFrameObject *back = PyFrame_GetBack(frame);
        Py_DECREF(frame);
        frame = back;
        depth++;
    }

    if (frame != NULL) {
        PUTS(fd, "  ...\n");
        Py_DECREF(frame);
    }
}

/* Public API that writes header - matches CPython's _Py_DumpTraceback */
static void _Py_DumpTraceback(int fd, PyThreadState *tstate) {
    PUTS(fd, "Stack (most recent call first):\n");
    dump_traceback_internal(fd, tstate);
}

/* Dump all threads - matches CPython's _Py_DumpTracebackThreads */
static const char* _Py_DumpTracebackThreads(int fd, PyInterpreterState *interp, PyThreadState *current_thread) {
    if (current_thread != NULL) {
        /* Write thread header like CPython does */
        PUTS(fd, "Current thread 0x");
        _Py_DumpHexadecimal(fd, (uintptr_t)pthread_self(), sizeof(pthread_t) * 2);
        PUTS(fd, " (most recent call first):\n");

        /* Dump traceback without header since we wrote our own */
        dump_traceback_internal(fd, current_thread);
    }
    return NULL;
}

static void _Py_DumpExtensionModules(int fd, PyInterpreterState *interp) {
    /* Extension module dumping not available in third-party module */
    PUTS(fd, "\nExtension modules: <not available in third-party module>\n");
}

#endif /* HAVE_PY_INTERNAL_SYMBOLS */

/* Compatibility for missing _PyEval_StopTheWorld and _PyEval_StartTheWorld in 3.13 */
#if PY_VERSION_HEX < 0x030E0000
static void _PyEval_StopTheWorld(PyInterpreterState *interp) {
    /* No-op for Python < 3.14 */
}
static void _PyEval_StartTheWorld(PyInterpreterState *interp) {
    /* No-op for Python < 3.14 */
}
#else
extern void _PyEval_StopTheWorld(PyInterpreterState *interp);
extern void _PyEval_StartTheWorld(PyInterpreterState *interp);
#endif

/* Compatibility for _PySys_GetRequiredAttr and _PyFile_Flush */
static PyObject* _PySys_GetRequiredAttr(PyObject *name) {
    PyObject *sysdict = PyImport_GetModuleDict();
    if (sysdict == NULL) {
        return NULL;
    }
    PyObject *sys_module = PyDict_GetItemString(sysdict, "sys");
    if (sys_module == NULL) {
        return NULL;
    }
    return PyObject_GetAttr(sys_module, name);
}

static int _PyFile_Flush(PyObject *file) {
    PyObject *result = PyObject_CallMethod(file, "flush", NULL);
    if (result == NULL) {
        return -1;
    }
    Py_DECREF(result);
    return 0;
}

/* _Py_ID macro replacement for third-party modules */
#define _Py_ID(name) (PyUnicode_FromString(#name))

typedef struct {
    int signum;
    int enabled;
    const char* name;
    _Py_sighandler_t previous;
    int all_threads;
} fault_handler_t;

static struct {
    int enabled;
    PyObject *file;
    int fd;
    int all_threads;
    int c_stack;  /* Added for C stack support */
    PyInterpreterState *interp;
#ifdef MS_WINDOWS
    void *exc_handler;
#endif
} fatal_error = {0, NULL, -1, 0, 1, NULL};

static struct {
    PyObject *file;
    int fd;
    PY_TIMEOUT_T timeout_us;   /* timeout in microseconds */
    int repeat;
    PyInterpreterState *interp;
    int exit;
    char *header;
    size_t header_len;
    /* The lock is held by the thread in faulthandler_thread() */
    PyThread_type_lock running;
    PyThread_type_lock cancel_event;
} thread;

#ifdef CFAULTHANDLER_USER
typedef struct {
    int enabled;
    PyObject *file;
    int fd;
    int all_threads;
    int chain;
    _Py_sighandler_t previous;
    PyInterpreterState *interp;
} user_signal_t;

static user_signal_t *user_signals = NULL;

static void faulthandler_user(int signum);
#endif /* CFAULTHANDLER_USER */

static fault_handler_t faulthandler_handlers[] = {
#ifdef SIGBUS
    {SIGBUS, 0, "Bus error", },
#endif
#ifdef SIGILL
    {SIGILL, 0, "Illegal instruction", },
#endif
    {SIGFPE, 0, "Floating-point exception", },
    {SIGABRT, 0, "Aborted", },
    /* define SIGSEGV at the end to make it the default choice if searching the
       handler fails in faulthandler_fatal_error() */
    {SIGSEGV, 0, "Segmentation fault", }
};
static const size_t faulthandler_nsignals =
    sizeof(faulthandler_handlers) / sizeof(faulthandler_handlers[0]);

#ifdef CFAULTHANDLER_USE_ALT_STACK
static stack_t stack;
static stack_t old_stack;
#endif

/* Forward declarations */
static void faulthandler_dump_c_stack(int fd);

/* Get the file descriptor of a file by calling its fileno() method and then
   call its flush() method.

   If file is NULL or Py_None, use sys.stderr as the new file.
   If file is an integer, it will be treated as file descriptor.

   On success, return the file descriptor and write the new file into *file_ptr.
   On error, return -1. */

static int
faulthandler_get_fileno(PyObject **file_ptr)
{
    PyObject *result;
    long fd_long;
    int fd;
    PyObject *file = *file_ptr;
    PyObject *stderr_str = NULL;

    if (file == NULL || file == Py_None) {
        stderr_str = _Py_ID(stderr);
        if (stderr_str == NULL) {
            return -1;
        }
        file = _PySys_GetRequiredAttr(stderr_str);
        Py_DECREF(stderr_str);
        if (file == NULL) {
            return -1;
        }
        if (file == Py_None) {
            PyErr_SetString(PyExc_RuntimeError, "sys.stderr is None");
            Py_DECREF(file);
            return -1;
        }
    }
    else if (PyLong_Check(file)) {
        if (PyBool_Check(file)) {
            if (PyErr_WarnEx(PyExc_RuntimeWarning,
                    "bool is used as a file descriptor", 1))
            {
                return -1;
            }
        }
        fd = PyLong_AsInt(file);
        if (fd == -1 && PyErr_Occurred())
            return -1;
        if (fd < 0) {
            PyErr_SetString(PyExc_ValueError,
                            "file is not a valid file descriptor");
            return -1;
        }
        *file_ptr = NULL;
        return fd;
    }
    else {
        Py_INCREF(file);
    }

    PyObject *fileno_str = PyUnicode_FromString("fileno");
    if (fileno_str == NULL) {
        Py_DECREF(file);
        return -1;
    }
    result = PyObject_CallMethodNoArgs(file, fileno_str);
    Py_DECREF(fileno_str);
    if (result == NULL) {
        Py_DECREF(file);
        return -1;
    }

    fd = -1;
    if (PyLong_Check(result)) {
        fd_long = PyLong_AsLong(result);
        if (0 <= fd_long && fd_long < INT_MAX)
            fd = (int)fd_long;
    }
    Py_DECREF(result);

    if (fd == -1) {
        PyErr_SetString(PyExc_RuntimeError,
                        "file.fileno() is not a valid file descriptor");
        Py_DECREF(file);
        return -1;
    }

    if (_PyFile_Flush(file) < 0) {
        /* ignore flush() error */
        PyErr_Clear();
    }
    *file_ptr = file;
    return fd;
}

/* Get the state of the current thread: only call this function if the current
   thread holds the GIL. Raise an exception on error. */
static PyThreadState*
get_thread_state(void)
{
    PyThreadState *tstate = PyThreadState_Get();
    if (tstate == NULL) {
        /* just in case but very unlikely... */
        PyErr_SetString(PyExc_RuntimeError,
                        "unable to get the current thread state");
        return NULL;
    }
    return tstate;
}

#ifdef CAN_C_BACKTRACE
static void
dump_c_stack_symbols(int fd, void *const *array, Py_ssize_t size)
{
    /* Based on glibc's implementation of backtrace_symbols(), but only uses stack memory. */
    for (Py_ssize_t i = 0; i < size; ++i) {
        Dl_info info;
        memset(&info, 0, sizeof(info));

        int status = dladdr(array[i], &info);

        if (status == 0
            || info.dli_fname == NULL
            || info.dli_fname[0] == '\0'
        ) {
            PUTS(fd, "  Binary file '<unknown>' [");
            _Py_DumpHexadecimal(fd, (uintptr_t)array[i], sizeof(void*) * 2);
            PUTS(fd, "]\n");
            continue;
        }

        if (info.dli_sname == NULL) {
            /* We found no symbol name to use, so describe it as
               relative to the file. */
            info.dli_saddr = info.dli_fbase;
        }

        if (info.dli_sname == NULL && info.dli_saddr == 0) {
            PUTS(fd, "  Binary file \"");
            PUTS(fd, info.dli_fname);
            PUTS(fd, "\" [");
            _Py_DumpHexadecimal(fd, (uintptr_t)array[i], sizeof(void*) * 2);
            PUTS(fd, "]\n");
        } else {
            PUTS(fd, "  Binary file \"");
            PUTS(fd, info.dli_fname);
            PUTS(fd, "\", in ");
            if (info.dli_sname != NULL) {
                PUTS(fd, info.dli_sname);
            } else {
                PUTS(fd, "???");
            }

            PUTS(fd, " at ");
            _Py_DumpHexadecimal(fd, (uintptr_t)array[i], sizeof(void*) * 2);

            if (info.dli_saddr != NULL && info.dli_sname != NULL) {
                PUTS(fd, " (");
                if (array[i] >= info.dli_saddr) {
                    PUTS(fd, "+");
                    _Py_DumpHexadecimal(fd,
                        (uintptr_t)array[i] - (uintptr_t)info.dli_saddr,
                        sizeof(void*) * 2);
                } else {
                    PUTS(fd, "-");
                    _Py_DumpHexadecimal(fd,
                        (uintptr_t)info.dli_saddr - (uintptr_t)array[i],
                        sizeof(void*) * 2);
                }
                PUTS(fd, ")");
            }
            PUTS(fd, "\n");
        }
    }
}
#endif

static void
faulthandler_dump_c_stack(int fd)
{
#ifdef CAN_C_BACKTRACE
    static volatile int reentrant = 0;

    if (reentrant) {
        return;
    }

    reentrant = 1;

    PUTS(fd, "\nCurrent thread's C call stack (most recent call first):\n");

    void *callstack[CFAULTHANDLER_MAX_C_FRAMES];
    int frames = backtrace(callstack, CFAULTHANDLER_MAX_C_FRAMES);

    if (frames == 0) {
        PUTS(fd, "  <system returned no stack trace>\n");
    } else {
        dump_c_stack_symbols(fd, callstack, frames);
        if (frames == CFAULTHANDLER_MAX_C_FRAMES) {
            PUTS(fd, "  <truncated>\n");
        }
    }

    reentrant = 0;
#else
    PUTS(fd, "\nCurrent thread's C call stack (most recent call first):\n");
    PUTS(fd, "  <C stack dumping not supported on this platform>\n");
#endif
}

static void
faulthandler_dump_traceback(int fd, int all_threads,
                            PyInterpreterState *interp)
{
    static volatile int reentrant = 0;

    if (reentrant)
        return;

    reentrant = 1;

    /* SIGSEGV, SIGFPE, SIGABRT, SIGBUS and SIGILL are synchronous signals and
       are thus delivered to the thread that caused the fault. Get the Python
       thread state of the current thread.

       PyThreadState_Get() doesn't give the state of the thread that caused the
       fault if the thread released the GIL, and so this function cannot be
       used. Read the thread specific storage (TSS) instead: call
       PyGILState_GetThisThreadState(). */
    PyThreadState *tstate = PyGILState_GetThisThreadState();

    if (all_threads) {
        (void)_Py_DumpTracebackThreads(fd, NULL, tstate);
    }
    else {
        if (tstate != NULL)
            _Py_DumpTraceback(fd, tstate);
    }

    reentrant = 0;
}

static PyObject*
faulthandler_dump_traceback_py(PyObject *self,
                               PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"file", "all_threads", NULL};
    PyObject *file = NULL;
    int all_threads = 1;
    PyThreadState *tstate;
    const char *errmsg;
    int fd;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
        "|Op:dump_traceback", kwlist,
        &file, &all_threads))
        return NULL;

    fd = faulthandler_get_fileno(&file);
    if (fd < 0)
        return NULL;

    tstate = get_thread_state();
    if (tstate == NULL) {
        Py_XDECREF(file);
        return NULL;
    }

    if (all_threads) {
        PyInterpreterState *interp = PyInterpreterState_Get();
        /* gh-128400: Accessing other thread states while they're running
         * isn't safe if those threads are running. */
        _PyEval_StopTheWorld(interp);
        errmsg = _Py_DumpTracebackThreads(fd, NULL, tstate);
        _PyEval_StartTheWorld(interp);
        if (errmsg != NULL) {
            PyErr_SetString(PyExc_RuntimeError, errmsg);
            Py_XDECREF(file);
            return NULL;
        }
    }
    else {
        _Py_DumpTraceback(fd, tstate);
    }
    Py_XDECREF(file);

    if (PyErr_CheckSignals())
        return NULL;

    Py_RETURN_NONE;
}

static PyObject*
faulthandler_dump_c_stack_py(PyObject *self,
                             PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"file", NULL};
    PyObject *file = NULL;
    int fd;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
        "|O:dump_c_stack", kwlist,
        &file)) {
        return NULL;
    }

    fd = faulthandler_get_fileno(&file);
    if (fd < 0) {
        return NULL;
    }

    faulthandler_dump_c_stack(fd);
    Py_XDECREF(file);

    if (PyErr_CheckSignals()) {
        return NULL;
    }

    Py_RETURN_NONE;
}

static void
faulthandler_disable_fatal_handler(fault_handler_t *handler)
{
    if (!handler->enabled)
        return;
    handler->enabled = 0;
#ifdef HAVE_SIGACTION
    (void)sigaction(handler->signum, &handler->previous, NULL);
#else
    (void)signal(handler->signum, handler->previous);
#endif
}

/* Handler for SIGSEGV, SIGFPE, SIGABRT, SIGBUS and SIGILL signals.

   Display the current Python traceback, restore the previous handler and call
   the previous handler.

   On Windows, don't explicitly call the previous handler, because the Windows
   signal handler would not be called (for an unknown reason). The execution of
   the program continues at faulthandler_fatal_error() exit, but the same
   instruction will raise the same fault (signal), and so the previous handler
   will be called.

   This function is signal-safe and should only call signal-safe functions. */

static void
faulthandler_fatal_error(int signum)
{
    const int fd = fatal_error.fd;
    size_t i;
    fault_handler_t *handler = NULL;
    int save_errno = errno;
    int found = 0;

    if (!fatal_error.enabled)
        return;

    for (i=0; i < faulthandler_nsignals; i++) {
        handler = &faulthandler_handlers[i];
        if (handler->signum == signum) {
            found = 1;
            break;
        }
    }
    if (handler == NULL) {
        /* faulthandler_nsignals == 0 (unlikely) */
        return;
    }

    /* restore the previous handler */
    faulthandler_disable_fatal_handler(handler);

    if (found) {
        PUTS(fd, "Fatal Python error: ");
        PUTS(fd, handler->name);
        PUTS(fd, "\n\n");
    }
    else {
        char unknown_signum[23] = {0,};
        snprintf(unknown_signum, 23, "%d", signum);
        PUTS(fd, "Fatal Python error from unexpected signum: ");
        PUTS(fd, unknown_signum);
        PUTS(fd, "\n\n");
    }

    faulthandler_dump_traceback(fd, fatal_error.all_threads,
                                fatal_error.interp);

    /* Dump C stack if enabled */
    if (fatal_error.c_stack) {
        faulthandler_dump_c_stack(fd);
    }

    _Py_DumpExtensionModules(fd, fatal_error.interp);

    errno = save_errno;
#ifdef MS_WINDOWS
    if (signum == SIGSEGV) {
        /* don't explicitly call the previous handler for SIGSEGV in this signal
           handler, because the Windows signal handler would not be called */
        return;
    }
#endif
    /* call the previous signal handler: it is called immediately if we use
       sigaction() thanks to SA_NODEFER flag, otherwise it is deferred */
    raise(signum);
}

#ifdef MS_WINDOWS
static int
faulthandler_ignore_exception(DWORD code)
{
    /* bpo-30557: ignore exceptions which are not errors */
    if (!(code & 0x80000000)) {
        return 1;
    }
    /* bpo-31701: ignore MSC and COM exceptions
       E0000000 + code */
    if (code == 0xE06D7363 /* MSC exception ("Emsc") */
        || code == 0xE0434352 /* COM Callable Runtime exception ("ECCR") */) {
        return 1;
    }
    /* Interesting exception: log it with the Python traceback */
    return 0;
}

static LONG WINAPI
faulthandler_exc_handler(struct _EXCEPTION_POINTERS *exc_info)
{
    const int fd = fatal_error.fd;
    DWORD code = exc_info->ExceptionRecord->ExceptionCode;
    DWORD flags = exc_info->ExceptionRecord->ExceptionFlags;

    if (faulthandler_ignore_exception(code)) {
        /* ignore the exception: call the next exception handler */
        return EXCEPTION_CONTINUE_SEARCH;
    }

    PUTS(fd, "Windows fatal exception: ");
    switch (code)
    {
    /* only format most common errors */
    case EXCEPTION_ACCESS_VIOLATION: PUTS(fd, "access violation"); break;
    case EXCEPTION_FLT_DIVIDE_BY_ZERO: PUTS(fd, "float divide by zero"); break;
    case EXCEPTION_FLT_OVERFLOW: PUTS(fd, "float overflow"); break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO: PUTS(fd, "int divide by zero"); break;
    case EXCEPTION_INT_OVERFLOW: PUTS(fd, "integer overflow"); break;
    case EXCEPTION_IN_PAGE_ERROR: PUTS(fd, "page error"); break;
    case EXCEPTION_STACK_OVERFLOW: PUTS(fd, "stack overflow"); break;
    default:
        PUTS(fd, "code 0x");
        _Py_DumpHexadecimal(fd, code, 8);
    }
    PUTS(fd, "\n\n");

    if (code == EXCEPTION_ACCESS_VIOLATION) {
        /* disable signal handler for SIGSEGV */
        for (size_t i=0; i < faulthandler_nsignals; i++) {
            fault_handler_t *handler = &faulthandler_handlers[i];
            if (handler->signum == SIGSEGV) {
                faulthandler_disable_fatal_handler(handler);
                break;
            }
        }
    }

    faulthandler_dump_traceback(fd, fatal_error.all_threads,
                                fatal_error.interp);

    /* Dump C stack if enabled */
    if (fatal_error.c_stack) {
        faulthandler_dump_c_stack(fd);
    }

    /* call the next exception handler */
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

#ifdef CFAULTHANDLER_USE_ALT_STACK
static int
faulthandler_allocate_stack(void)
{
    if (stack.ss_sp != NULL) {
        return 0;
    }
    /* Allocate an alternate stack for faulthandler() signal handler
       to be able to execute a signal handler on a stack overflow error */
    stack.ss_sp = PyMem_Malloc(stack.ss_size);
    if (stack.ss_sp == NULL) {
        PyErr_NoMemory();
        return -1;
    }

    int err = sigaltstack(&stack, &old_stack);
    if (err) {
        PyErr_SetFromErrno(PyExc_OSError);
        /* Release the stack to retry sigaltstack() next time */
        PyMem_Free(stack.ss_sp);
        stack.ss_sp = NULL;
        return -1;
    }
    return 0;
}
#endif

/* Install the handler for fatal signals, faulthandler_fatal_error(). */
static int
faulthandler_enable(void)
{
    if (fatal_error.enabled) {
        return 0;
    }
    fatal_error.enabled = 1;

#ifdef CFAULTHANDLER_USE_ALT_STACK
    if (faulthandler_allocate_stack() < 0) {
        return -1;
    }
#endif

    for (size_t i=0; i < faulthandler_nsignals; i++) {
        fault_handler_t *handler;
        int err;

        handler = &faulthandler_handlers[i];
        assert(!handler->enabled);
#ifdef HAVE_SIGACTION
        struct sigaction action;
        action.sa_handler = faulthandler_fatal_error;
        sigemptyset(&action.sa_mask);
        /* Do not prevent the signal from being received from within
           its own signal handler */
        action.sa_flags = SA_NODEFER;
#ifdef CFAULTHANDLER_USE_ALT_STACK
        assert(stack.ss_sp != NULL);
        /* Call the signal handler on an alternate signal stack
           provided by sigaltstack() */
        action.sa_flags |= SA_ONSTACK;
#endif
        err = sigaction(handler->signum, &action, &handler->previous);
#else
        handler->previous = signal(handler->signum,
                                   faulthandler_fatal_error);
        err = (handler->previous == SIG_ERR);
#endif
        if (err) {
            PyErr_SetFromErrno(PyExc_RuntimeError);
            return -1;
        }

        handler->enabled = 1;
    }

#ifdef MS_WINDOWS
    assert(fatal_error.exc_handler == NULL);
    fatal_error.exc_handler = AddVectoredExceptionHandler(1, faulthandler_exc_handler);
#endif
    return 0;
}

static PyObject*
faulthandler_py_enable(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"file", "all_threads", "c_stack", NULL};
    PyObject *file = NULL;
    int all_threads = 1;
    int c_stack = 1;
    int fd;
    PyThreadState *tstate;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
        "|Opp:enable", kwlist, &file, &all_threads, &c_stack))
        return NULL;

    fd = faulthandler_get_fileno(&file);
    if (fd < 0)
        return NULL;

    tstate = get_thread_state();
    if (tstate == NULL) {
        Py_XDECREF(file);
        return NULL;
    }

    Py_XSETREF(fatal_error.file, file);
    fatal_error.fd = fd;
    fatal_error.all_threads = all_threads;
    fatal_error.c_stack = c_stack;
    fatal_error.interp = PyInterpreterState_Get();

    if (faulthandler_enable() < 0) {
        return NULL;
    }

    Py_RETURN_NONE;
}

static void
faulthandler_disable(void)
{
    if (fatal_error.enabled) {
        fatal_error.enabled = 0;
        for (size_t i=0; i < faulthandler_nsignals; i++) {
            fault_handler_t *handler;
            handler = &faulthandler_handlers[i];
            faulthandler_disable_fatal_handler(handler);
        }
    }
#ifdef MS_WINDOWS
    if (fatal_error.exc_handler != NULL) {
        RemoveVectoredExceptionHandler(fatal_error.exc_handler);
        fatal_error.exc_handler = NULL;
    }
#endif
    Py_CLEAR(fatal_error.file);
}

static PyObject*
faulthandler_disable_py(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    if (!fatal_error.enabled) {
        Py_RETURN_FALSE;
    }
    faulthandler_disable();
    Py_RETURN_TRUE;
}

static PyObject*
faulthandler_is_enabled(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return PyBool_FromLong(fatal_error.enabled);
}

static void
faulthandler_thread(void *unused)
{
    PyLockStatus st;
    const char* errmsg;
    int ok;
#if defined(HAVE_PTHREAD_SIGMASK) && !defined(HAVE_BROKEN_PTHREAD_SIGMASK)
    sigset_t set;

    /* we don't want to receive any signal */
    sigfillset(&set);
    pthread_sigmask(SIG_SETMASK, &set, NULL);
#endif

    do {
        st = PyThread_acquire_lock_timed(thread.cancel_event,
                                         thread.timeout_us, 0);
        if (st == PY_LOCK_ACQUIRED) {
            PyThread_release_lock(thread.cancel_event);
            break;
        }
        /* Timeout => dump traceback */
        assert(st == PY_LOCK_FAILURE);

        (void)_Py_write_noraise(thread.fd, thread.header, (int)thread.header_len);

        errmsg = _Py_DumpTracebackThreads(thread.fd, thread.interp, NULL);
        ok = (errmsg == NULL);

        if (thread.exit)
            _exit(1);
    } while (ok && thread.repeat);

    /* The only way out */
    PyThread_release_lock(thread.running);
}

static void
cancel_dump_traceback_later(void)
{
    /* If not scheduled, nothing to cancel */
    if (!thread.cancel_event) {
        return;
    }

    /* Notify cancellation */
    PyThread_release_lock(thread.cancel_event);

    /* Wait for thread to complete */
    if (thread.running) {
        PyThread_acquire_lock(thread.running, 1);
        PyThread_release_lock(thread.running);
    }

    /* The thread completed. */
    Py_CLEAR(thread.file);
    if (thread.header) {
        PyMem_Free(thread.header);
        thread.header = NULL;
    }
}

#define SEC_TO_US (1000 * 1000)

static char*
format_timeout(PyTime_t us)
{
    unsigned long sec, min, hour;
    char buffer[100];

    /* the downcast is safe: the caller check that 0 < us <= LONG_MAX */
    sec = (unsigned long)(us / SEC_TO_US);
    us %= SEC_TO_US;

    min = sec / 60;
    sec %= 60;
    hour = min / 60;
    min %= 60;

    if (us != 0) {
        PyOS_snprintf(buffer, sizeof(buffer),
                      "Timeout (%lu:%02lu:%02lu.%06u)!\n",
                      hour, min, sec, (unsigned int)us);
    }
    else {
        PyOS_snprintf(buffer, sizeof(buffer),
                      "Timeout (%lu:%02lu:%02lu)!\n",
                      hour, min, sec);
    }
    char *copy = PyMem_Malloc(strlen(buffer) + 1);
    if (copy != NULL) {
        strcpy(copy, buffer);
    }
    return copy;
}

static PyObject*
faulthandler_dump_traceback_later(PyObject *self,
                                   PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"timeout", "repeat", "file", "exit", NULL};
    PyObject *timeout_obj;
    PyTime_t timeout_us;
    int repeat = 0;
    PyObject *file = NULL;
    int fd;
    int exit = 0;
    PyThreadState *tstate;
    char *header;
    size_t header_len;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
        "O|pOp:dump_traceback_later", kwlist,
        &timeout_obj, &repeat, &file, &exit))
        return NULL;

    /* timeout is a double in Python 3.13 */
    if (PyFloat_Check(timeout_obj)) {
        double d = PyFloat_AsDouble(timeout_obj);
        if (d < 0) {
            PyErr_SetString(PyExc_ValueError, "timeout must be >= 0");
            return NULL;
        }
        /* Convert to microseconds, rounding up */
        timeout_us = (PyTime_t)(d * 1e6 + 0.999);
    } else if (PyLong_Check(timeout_obj)) {
        timeout_us = PyLong_AsLongLong(timeout_obj) * SEC_TO_US;
    } else {
        PyErr_SetString(PyExc_TypeError, "timeout must be a number");
        return NULL;
    }

    if (timeout_us <= 0) {
        PyErr_SetString(PyExc_ValueError, "timeout must be > 0");
        return NULL;
    }
    /* Limit to LONG_MAX for portability */
    if (timeout_us > (PyTime_t)PY_TIMEOUT_MAX) {
        PyErr_SetString(PyExc_OverflowError,
                        "timeout value is too large");
        return NULL;
    }

    tstate = get_thread_state();
    if (tstate == NULL) {
        return NULL;
    }

    fd = faulthandler_get_fileno(&file);
    if (fd < 0) {
        return NULL;
    }

    if (!thread.running) {
        thread.running = PyThread_allocate_lock();
        if (!thread.running) {
            Py_XDECREF(file);
            return PyErr_NoMemory();
        }
    }
    if (!thread.cancel_event) {
        thread.cancel_event = PyThread_allocate_lock();
        if (!thread.cancel_event || !thread.running) {
            Py_XDECREF(file);
            return PyErr_NoMemory();
        }

        /* cancel_event starts to be acquired: it's only released to cancel
           the thread. */
        PyThread_acquire_lock(thread.cancel_event, 1);
    }

    /* format the timeout */
    header = format_timeout(timeout_us);
    if (header == NULL) {
        Py_XDECREF(file);
        return PyErr_NoMemory();
    }
    header_len = strlen(header);

    /* Cancel previous thread, if running */
    cancel_dump_traceback_later();

    Py_XSETREF(thread.file, file);
    thread.fd = fd;
    /* the downcast is safe: we check that 0 < timeout_us < PY_TIMEOUT_MAX */
    thread.timeout_us = (PY_TIMEOUT_T)timeout_us;
    thread.repeat = repeat;
    thread.interp = PyInterpreterState_Get();
    thread.exit = exit;
    thread.header = header;
    thread.header_len = header_len;

    /* Arm these locks to serve as events when released */
    PyThread_acquire_lock(thread.running, 1);

    if (PyThread_start_new_thread(faulthandler_thread, NULL) == PYTHREAD_INVALID_THREAD_ID) {
        PyThread_release_lock(thread.running);
        Py_CLEAR(thread.file);
        PyMem_Free(header);
        thread.header = NULL;
        PyErr_SetString(PyExc_RuntimeError,
                        "unable to start watchdog thread");
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject*
faulthandler_cancel_dump_traceback_later_py(PyObject *self,
                                            PyObject *Py_UNUSED(ignored))
{
    cancel_dump_traceback_later();
    Py_RETURN_NONE;
}

#ifdef CFAULTHANDLER_USER
static int
faulthandler_register(int signum, int chain, _Py_sighandler_t *previous_p)
{
#ifdef HAVE_SIGACTION
    struct sigaction action;
    action.sa_handler = faulthandler_user;
    sigemptyset(&action.sa_mask);
    /* if the signal is received while the kernel is executing a system
       call, try to restart the system call instead of interrupting it and
       return EINTR. */
    action.sa_flags = SA_RESTART;
    if (chain) {
        /* do not prevent the signal from being received from within its
           own signal handler */
        action.sa_flags = SA_NODEFER;
    }
#ifdef CFAULTHANDLER_USE_ALT_STACK
    assert(stack.ss_sp != NULL);
    /* Call the signal handler on an alternate signal stack
       provided by sigaltstack() */
    action.sa_flags |= SA_ONSTACK;
#endif
    return sigaction(signum, &action, previous_p);
#else
    _Py_sighandler_t previous;
    previous = signal(signum, faulthandler_user);
    if (previous_p != NULL) {
        *previous_p = previous;
    }
    return (previous == SIG_ERR);
#endif
}

/* Handler of user signals (e.g. SIGUSR1).

   Dump the traceback of the current thread, or of all threads if
   thread.all_threads is true.

   This function is signal safe and should only call signal safe functions. */

static void
faulthandler_user(int signum)
{
    user_signal_t *user;
    int save_errno = errno;

    user = &user_signals[signum];
    if (!user->enabled)
        return;

    faulthandler_dump_traceback(user->fd, user->all_threads, user->interp);

#ifdef HAVE_SIGACTION
    if (user->chain) {
        (void)sigaction(signum, &user->previous, NULL);
        errno = save_errno;

        /* call the previous signal handler */
        raise(signum);

        save_errno = errno;
        (void)faulthandler_register(signum, user->chain, NULL);
        errno = save_errno;
    }
#else
    if (user->chain && user->previous != NULL) {
        errno = save_errno;
        /* call the previous signal handler */
        user->previous(signum);
    }
#endif
}

static int
check_signum(int signum)
{
    for (size_t i=0; i < faulthandler_nsignals; i++) {
        if (faulthandler_handlers[i].signum == signum) {
            PyErr_Format(PyExc_RuntimeError,
                         "signal %i cannot be registered, "
                         "use enable() instead",
                         signum);
            return 0;
        }
    }
    if (signum < 1 || Py_NSIG <= signum) {
        PyErr_SetString(PyExc_ValueError, "signal number out of range");
        return 0;
    }
    return 1;
}

static PyObject*
faulthandler_register_py(PyObject *self,
                         PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"signum", "file", "all_threads", "chain", NULL};
    int signum;
    PyObject *file = NULL;
    int all_threads = 1;
    int chain = 0;
    int fd;
    user_signal_t *user;
    _Py_sighandler_t previous;
    PyThreadState *tstate;
    int err;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
        "i|Opp:register", kwlist,
        &signum, &file, &all_threads, &chain))
        return NULL;

    if (!check_signum(signum))
        return NULL;

    tstate = get_thread_state();
    if (tstate == NULL)
        return NULL;

    fd = faulthandler_get_fileno(&file);
    if (fd < 0)
        return NULL;

    if (user_signals == NULL) {
        user_signals = PyMem_Calloc(Py_NSIG, sizeof(user_signal_t));
        if (user_signals == NULL) {
            Py_XDECREF(file);
            return PyErr_NoMemory();
        }
    }
    user = &user_signals[signum];

    if (!user->enabled) {
#ifdef CFAULTHANDLER_USE_ALT_STACK
        if (faulthandler_allocate_stack() < 0) {
            Py_XDECREF(file);
            return NULL;
        }
#endif

        err = faulthandler_register(signum, chain, &previous);
        if (err) {
            PyErr_SetFromErrno(PyExc_OSError);
            Py_XDECREF(file);
            return NULL;
        }

        user->previous = previous;
    }

    Py_XSETREF(user->file, file);
    user->fd = fd;
    user->all_threads = all_threads;
    user->chain = chain;
    user->interp = PyInterpreterState_Get();
    user->enabled = 1;

    Py_RETURN_NONE;
}

static int
faulthandler_unregister(user_signal_t *user, int signum)
{
    if (!user->enabled)
        return 0;
    user->enabled = 0;
#ifdef HAVE_SIGACTION
    (void)sigaction(signum, &user->previous, NULL);
#else
    (void)signal(signum, user->previous);
#endif
    Py_CLEAR(user->file);
    user->fd = -1;
    return 1;
}

static PyObject*
faulthandler_unregister_py(PyObject *self, PyObject *args)
{
    int signum;
    user_signal_t *user;
    int change;

    if (!PyArg_ParseTuple(args, "i:unregister", &signum))
        return NULL;

    if (!check_signum(signum))
        return NULL;

    if (user_signals == NULL)
        Py_RETURN_FALSE;

    user = &user_signals[signum];
    change = faulthandler_unregister(user, signum);
    return PyBool_FromLong(change);
}
#endif   /* CFAULTHANDLER_USER */

static void
faulthandler_suppress_crash_report(void)
{
#ifdef MS_WINDOWS_DESKTOP
    UINT mode;

    /* Configure Windows to not display the Windows Error Reporting dialog */
    mode = SetErrorMode(SEM_NOGPFAULTERRORBOX);
    SetErrorMode(mode | SEM_NOGPFAULTERRORBOX);
#endif

#ifdef HAVE_SYS_RESOURCE_H
    struct rlimit rl;
    /* Disable core dump */
    if (getrlimit(RLIMIT_CORE, &rl) == 0) {
        rl.rlim_cur = 0;
        setrlimit(RLIMIT_CORE, &rl);
    }
#endif

#ifdef _MSC_VER
    /* Visual Studio: configure abort() to not display an error message nor
       open a popup asking to report the fault. */
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
}

static PyObject* _Py_NO_SANITIZE_UNDEFINED
faulthandler_read_null(PyObject *self, PyObject *args)
{
    volatile int *x;
    volatile int y;

    faulthandler_suppress_crash_report();
    x = NULL;
    y = *x;
    return PyLong_FromLong(y);

}

static void
faulthandler_raise_sigsegv(void)
{
    faulthandler_suppress_crash_report();
#if defined(MS_WINDOWS)
    /* For SIGSEGV, faulthandler_fatal_error() restores the previous signal
       handler and then gives back the execution flow to the program (without
       explicitly calling the previous error handler). In a normal case, the
       SIGSEGV was raised by the kernel because of a fault, and so if the
       program retries to execute the same instruction, the fault will be
       raised again.

       Here the fault is simulated by a fake SIGSEGV signal raised by the
       application. We have to raise SIGSEGV at lease twice: once for
       faulthandler_fatal_error(), and one more time for the previous signal
       handler. */
    while(1)
        raise(SIGSEGV);
#else
    raise(SIGSEGV);
#endif
}

static PyObject *
faulthandler_sigsegv(PyObject *self, PyObject *args)
{
    int release_gil = 0;
    if (!PyArg_ParseTuple(args, "|i:_sigsegv", &release_gil))
        return NULL;

    if (release_gil) {
        Py_BEGIN_ALLOW_THREADS
        faulthandler_raise_sigsegv();
        Py_END_ALLOW_THREADS
    } else {
        faulthandler_raise_sigsegv();
    }
    Py_RETURN_NONE;
}

static void _Py_NO_RETURN
faulthandler_fatal_error_thread(void *plock)
{
    Py_FatalError("in new thread");
}

static PyObject *
faulthandler_fatal_error_c_thread(PyObject *self, PyObject *args)
{
    long tid;
    PyThread_type_lock lock;

    faulthandler_suppress_crash_report();

    lock = PyThread_allocate_lock();
    if (lock == NULL)
        return PyErr_NoMemory();

    PyThread_acquire_lock(lock, WAIT_LOCK);

    tid = PyThread_start_new_thread(faulthandler_fatal_error_thread, lock);
    if (tid == -1) {
        PyThread_free_lock(lock);
        PyErr_SetString(PyExc_RuntimeError, "unable to start the thread");
        return NULL;
    }

    /* wait until the thread completes: it will never occur, since Py_FatalError()
       exits the process immediately. */
    PyThread_acquire_lock(lock, WAIT_LOCK);
    PyThread_release_lock(lock);
    PyThread_free_lock(lock);

    Py_RETURN_NONE;
}

static PyObject* _Py_NO_SANITIZE_UNDEFINED
faulthandler_sigfpe(PyObject *self, PyObject *args)
{
    faulthandler_suppress_crash_report();

    /* Do an integer division by zero: raise a SIGFPE on Intel CPU, but not on
       PowerPC. Use volatile to disable compile-time optimizations. */
    volatile int x = 1, y = 0, z;
    z = x / y;

    /* If the division by zero didn't raise a SIGFPE (e.g. on PowerPC),
       raise it manually. */
    raise(SIGFPE);

    /* This line is never reached, but we pretend to make something with z
       to silence a compiler warning. */
    return PyLong_FromLong(z);
}

static PyObject *
faulthandler_sigabrt(PyObject *self, PyObject *args)
{
    faulthandler_suppress_crash_report();
    abort();
    Py_RETURN_NONE;
}

#if defined(CFAULTHANDLER_USE_ALT_STACK)
#define CFAULTHANDLER_STACK_OVERFLOW

static uintptr_t
stack_overflow(uintptr_t min_sp, uintptr_t max_sp, size_t *depth)
{
    /* Allocate (at least) 4096 bytes on the stack at each call.

       bpo-23654, bpo-38965: use volatile keyword to prevent tail call
       optimization. */
    volatile unsigned char buffer[4096];
    uintptr_t sp = (uintptr_t)&buffer;
    *depth += 1;
    if (sp < min_sp || max_sp < sp)
        return sp;
    buffer[0] = 1;
    buffer[4095] = 0;
    return stack_overflow(min_sp, max_sp, depth);
}

static PyObject *
faulthandler_stack_overflow(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    size_t depth, size;
    uintptr_t sp = (uintptr_t)&depth;
    uintptr_t stop, lower_limit, upper_limit;

    faulthandler_suppress_crash_report();
    depth = 0;

    if (STACK_OVERFLOW_MAX_SIZE <= sp) {
        lower_limit = sp - STACK_OVERFLOW_MAX_SIZE;
    }
    else {
        lower_limit = 0;
    }

    /* Reserve 4 KB at the bottom of the stack */
    if (lower_limit < 4096) {
        lower_limit = 4096;
    }

    upper_limit = sp + STACK_OVERFLOW_MAX_SIZE;
    /* bpo-23654, bpo-38965: use volatile keyword to prevent tail call
       optimization. */
    stop = stack_overflow(lower_limit, upper_limit, &depth);
    if (sp > stop)
        size = sp - stop;
    else
        size = stop - sp;
    PyErr_Format(PyExc_RuntimeError,
        "unable to raise a stack overflow (allocated %zu bytes "
        "on the stack, %zu recursive calls)",
        size, depth);
    return NULL;
}
#endif   /* defined(CFAULTHANDLER_USE_ALT_STACK) && defined(HAVE_SIGACTION) */

static int
faulthandler_traverse(PyObject *module, visitproc visit, void *arg)
{
    Py_VISIT(thread.file);
#ifdef CFAULTHANDLER_USER
    if (user_signals != NULL) {
        for (size_t signum=0; signum < Py_NSIG; signum++)
            Py_VISIT(user_signals[signum].file);
    }
#endif
    Py_VISIT(fatal_error.file);
    return 0;
}

#ifdef MS_WINDOWS
static PyObject *
faulthandler_raise_exception(PyObject *self, PyObject *args)
{
    unsigned int code, flags = 0;
    if (!PyArg_ParseTuple(args, "I|I:_raise_exception", &code, &flags))
        return NULL;
    faulthandler_suppress_crash_report();
    RaiseException(code, flags, 0, NULL);
    Py_RETURN_NONE;
}
#endif

PyDoc_STRVAR(module_doc,
"cfaulthandler module - enhanced faulthandler with C stack traces.");

static PyMethodDef module_methods[] = {
    {"enable",
     _PyCFunction_CAST(faulthandler_py_enable), METH_VARARGS|METH_KEYWORDS,
     PyDoc_STR("enable($module, /, file=sys.stderr, all_threads=True, c_stack=True)\n--\n\n"
               "Enable the fault handler.\n\n"
               "If c_stack is True, dump the C stack on crashes.")},
    {"disable", faulthandler_disable_py, METH_NOARGS,
     PyDoc_STR("disable($module, /)\n--\n\n"
               "Disable the fault handler.")},
    {"is_enabled", faulthandler_is_enabled, METH_NOARGS,
     PyDoc_STR("is_enabled($module, /)\n--\n\n"
               "Check if the handler is enabled.")},
    {"dump_traceback",
     _PyCFunction_CAST(faulthandler_dump_traceback_py), METH_VARARGS|METH_KEYWORDS,
     PyDoc_STR("dump_traceback($module, /, file=sys.stderr, all_threads=True)\n--\n\n"
               "Dump the traceback of the current thread, or of all threads "
               "if all_threads is True, into file.")},
    {"dump_c_stack",
     _PyCFunction_CAST(faulthandler_dump_c_stack_py), METH_VARARGS|METH_KEYWORDS,
     PyDoc_STR("dump_c_stack($module, /, file=sys.stderr)\n--\n\n"
               "Dump the C stack of the current thread.")},
    {"dump_traceback_later",
     _PyCFunction_CAST(faulthandler_dump_traceback_later), METH_VARARGS|METH_KEYWORDS,
     PyDoc_STR("dump_traceback_later($module, /, timeout, repeat=False, file=sys.stderr, exit=False)\n--\n\n"
               "Dump the traceback of all threads in timeout seconds,\n"
               "or each timeout seconds if repeat is True. If exit is True, "
               "call _exit(1) which is not safe.")},
    {"cancel_dump_traceback_later",
     faulthandler_cancel_dump_traceback_later_py, METH_NOARGS,
     PyDoc_STR("cancel_dump_traceback_later($module, /)\n--\n\n"
               "Cancel the previous call to dump_traceback_later().")},
#ifdef CFAULTHANDLER_USER
    {"register",
     _PyCFunction_CAST(faulthandler_register_py), METH_VARARGS|METH_KEYWORDS,
     PyDoc_STR("register($module, /, signum, file=sys.stderr, all_threads=True, chain=False)\n--\n\n"
               "Register a handler for the signal 'signum': dump the "
               "traceback of the current thread, or of all threads if "
               "all_threads is True, into file.")},
    {"unregister",
     _PyCFunction_CAST(faulthandler_unregister_py), METH_VARARGS,
     PyDoc_STR("unregister($module, signum, /)\n--\n\n"
               "Unregister the handler of the signal "
               "'signum' registered by register().")},
#endif
    {"_read_null", faulthandler_read_null, METH_NOARGS,
     PyDoc_STR("_read_null($module, /)\n--\n\n"
               "Read from NULL, raise "
               "a SIGSEGV or SIGBUS signal depending on the platform.")},
    {"_sigsegv", faulthandler_sigsegv, METH_VARARGS,
     PyDoc_STR("_sigsegv($module, release_gil=False, /)\n--\n\n"
               "Raise a SIGSEGV signal.")},
    {"_fatal_error_c_thread", faulthandler_fatal_error_c_thread, METH_NOARGS,
     PyDoc_STR("_fatal_error_c_thread($module, /)\n--\n\n"
               "Call Py_FatalError() in a new C thread.")},
    {"_sigabrt", faulthandler_sigabrt, METH_NOARGS,
     PyDoc_STR("_sigabrt($module, /)\n--\n\n"
               "Raise a SIGABRT signal.")},
    {"_sigfpe", (PyCFunction)faulthandler_sigfpe, METH_NOARGS,
     PyDoc_STR("_sigfpe($module, /)\n--\n\n"
               "Raise a SIGFPE signal.")},
#ifdef CFAULTHANDLER_STACK_OVERFLOW
    {"_stack_overflow", faulthandler_stack_overflow, METH_NOARGS,
     PyDoc_STR("_stack_overflow($module, /)\n--\n\n"
               "Recursive call to raise a stack overflow.")},
#endif
#ifdef MS_WINDOWS
    {"_raise_exception", faulthandler_raise_exception, METH_VARARGS,
     PyDoc_STR("_raise_exception($module, code, flags=0, /)\n--\n\n"
               "Call RaiseException(code, flags).")},
#endif
    {NULL, NULL}  /* sentinel */
};

static int
PyExec_cfaulthandler(PyObject *module) {
    /* Add constants for unit tests */
#ifdef MS_WINDOWS
    /* RaiseException() codes (prefixed by an underscore) */
    if (PyModule_AddIntConstant(module, "_EXCEPTION_ACCESS_VIOLATION",
                                EXCEPTION_ACCESS_VIOLATION)) {
        return -1;
    }
    if (PyModule_AddIntConstant(module, "_EXCEPTION_INT_DIVIDE_BY_ZERO",
                                EXCEPTION_INT_DIVIDE_BY_ZERO)) {
        return -1;
    }
    if (PyModule_AddIntConstant(module, "_EXCEPTION_STACK_OVERFLOW",
                                EXCEPTION_STACK_OVERFLOW)) {
        return -1;
    }
#endif

    /* Initialize module state */
    memset(&fatal_error, 0, sizeof(fatal_error));
    fatal_error.fd = -1;
    fatal_error.c_stack = 1;  /* Enable C stack by default */

    memset(&thread, 0, sizeof(thread));

#ifdef CFAULTHANDLER_USE_ALT_STACK
    memset(&stack, 0, sizeof(stack));
    stack.ss_flags = 0;
    /* bpo-21131: allocate dedicated stack of SIGSTKSZ*2 bytes, instead of just
       SIGSTKSZ bytes. Calling the previous signal handler in faulthandler
       signal handler uses more than SIGSTKSZ bytes of stack memory on some
       platforms. */
    stack.ss_size = SIGSTKSZ * 2;
#ifdef AT_MINSIGSTKSZ
    /* bpo-46968: Query Linux for minimal stack size to ensure signal delivery
       for the hardware running CPython. This OS feature is available in
       Linux kernel version >= 5.14 */
    unsigned long at_minstack_size = getauxval(AT_MINSIGSTKSZ);
    if (at_minstack_size != 0) {
        stack.ss_size = SIGSTKSZ + at_minstack_size;
    }
#endif
#endif

    return 0;
}

static PyModuleDef_Slot cfaulthandler_slots[] = {
    {Py_mod_exec, PyExec_cfaulthandler},
    {0, NULL}
};

static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    .m_name = "cfaulthandler",
    .m_doc = module_doc,
    .m_methods = module_methods,
    .m_traverse = faulthandler_traverse,
    .m_slots = cfaulthandler_slots
};

PyMODINIT_FUNC
PyInit_cfaulthandler(void)
{
    return PyModuleDef_Init(&module_def);
}