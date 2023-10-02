#include <Python.h>

#include <object.h>
#include <signal.h>
#include <signal.h>
#include <stdlib.h>               // abort()
#if defined(HAVE_PTHREAD_SIGMASK) && !defined(HAVE_BROKEN_PTHREAD_SIGMASK) && defined(HAVE_PTHREAD_H)
#  include <pthread.h>
#endif
#ifdef MS_WINDOWS
#  include <windows.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
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

#define PUTS(fd, str) _Py_write_noraise(fd, str, strlen(str))


// clang uses __attribute__((no_sanitize("undefined")))
// GCC 4.9+ uses __attribute__((no_sanitize_undefined))
#if defined(__has_feature)  // Clang
#  if __has_feature(undefined_behavior_sanitizer)
#    define _Py_NO_SANITIZE_UNDEFINED __attribute__((no_sanitize("undefined")))
#  endif
#endif
#if defined(__GNUC__) \
    && ((__GNUC__ >= 5) || (__GNUC__ == 4) && (__GNUC_MINOR__ >= 9))
#  define _Py_NO_SANITIZE_UNDEFINED __attribute__((no_sanitize_undefined))
#endif
#ifndef _Py_NO_SANITIZE_UNDEFINED
#  define _Py_NO_SANITIZE_UNDEFINED
#endif


#ifdef HAVE_SIGACTION
typedef struct sigaction _Py_sighandler_t;
#else
typedef PyOS_sighandler_t _Py_sighandler_t;
#endif

/* Py_NSIG is normally defined in pycore_signal.h, but we can't import that
header from a third-party extension module, so we copy the definition here. */
#ifdef _SIG_MAXSIG
   // gh-91145: On FreeBSD, <signal.h> defines NSIG as 32: it doesn't include
   // realtime signals: [SIGRTMIN,SIGRTMAX]. Use _SIG_MAXSIG instead. For
   // example on x86-64 FreeBSD 13, SIGRTMAX is 126 and _SIG_MAXSIG is 128.
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

/* The built-in faulthandler module uses these internal Python functions for
printing stack traces. We steal them here. */
extern void _Py_DumpExtensionModules(int fd, PyInterpreterState *interp);
extern const char* _Py_DumpTracebackThreads(
    int fd,
    PyInterpreterState *interp,
    PyThreadState *current_tstate);
extern void _Py_DumpTraceback(
    int fd,
    PyThreadState *tstate);
extern Py_ssize_t _Py_write_noraise(
    int fd,
    const void *buf,
    size_t count);

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
    PyInterpreterState *interp;
#ifdef MS_WINDOWS
    void *exc_handler;
#endif
} fatal_error = {0, NULL, -1, 0};

static struct {
    PyObject *file;
    int fd;
    PY_TIMEOUT_T timeout_us;   /* timeout in microseconds */
    int repeat;
    PyInterpreterState *interp;
    int exit;
    char *header;
    size_t header_len;
    /* The main thread always holds this lock. It is only released when
       cfaulthandler_thread() is interrupted before this thread exits, or at
       Python exit. */
    PyThread_type_lock cancel_event;
    /* released by child thread when joined */
    PyThread_type_lock running;
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

static user_signal_t *user_signals;

static void cfaulthandler_user(int signum);
#endif /* CFAULTHANDLER_USER */


static fault_handler_t cfaulthandler_handlers[] = {
#ifdef SIGBUS
    {SIGBUS, 0, "Bus error", },
#endif
#ifdef SIGILL
    {SIGILL, 0, "Illegal instruction", },
#endif
    {SIGFPE, 0, "Floating point exception", },
    {SIGABRT, 0, "Aborted", },
    /* define SIGSEGV at the end to make it the default choice if searching the
       handler fails in cfaulthandler_fatal_error() */
    {SIGSEGV, 0, "Segmentation fault", }
};
static const size_t cfaulthandler_nsignals = \
    Py_ARRAY_LENGTH(cfaulthandler_handlers);

#ifdef CFAULTHANDLER_USE_ALT_STACK
static stack_t stack;
static stack_t old_stack;
#endif


/* Get the file descriptor of a file by calling its fileno() method and then
   call its flush() method.

   If file is NULL or Py_None, use sys.stderr as the new file.
   If file is an integer, it will be treated as file descriptor.

   On success, return the file descriptor and write the new file into *file_ptr.
   On error, return -1. */

static int
cfaulthandler_get_fileno(PyObject **file_ptr)
{
    PyObject *result;
    long fd_long;
    int fd;
    PyObject *file = *file_ptr;

    if (file == NULL || file == Py_None) {
        file = PySys_GetObject("stderr");
        if (file == NULL) {
            PyErr_SetString(PyExc_RuntimeError, "unable to get sys.stderr");
            return -1;
        }
        if (file == Py_None) {
            PyErr_SetString(PyExc_RuntimeError, "sys.stderr is None");
            return -1;
        }
    }
    else if (PyLong_Check(file)) {
        fd = _PyLong_AsInt(file);
        if (fd == -1 && PyErr_Occurred())
            return -1;
        if (fd < 0) {
            PyErr_SetString(PyExc_ValueError,
                            "file is not a valid file descripter");
            return -1;
        }
        *file_ptr = NULL;
        return fd;
    }

    result = PyObject_CallMethod(file, "fileno", "");
    if (result == NULL)
        return -1;

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
        return -1;
    }

    result = PyObject_CallMethod(file, "flush", "");
    if (result != NULL)
        Py_DECREF(result);
    else {
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
    PyThreadState *tstate = _PyThreadState_UncheckedGet();
    if (tstate == NULL) {
        /* just in case but very unlikely... */
        PyErr_SetString(PyExc_RuntimeError,
                        "unable to get the current thread state");
        return NULL;
    }
    return tstate;
}

static void
cfaulthandler_dump_traceback(int fd, int all_threads,
                            PyInterpreterState *interp)
{
    static volatile int reentrant = 0;
    PyThreadState *tstate;

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
    tstate = PyGILState_GetThisThreadState();

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
cfaulthandler_dump_traceback_py(PyObject *self,
                               PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"file", "all_threads", NULL};
    PyObject *file = NULL;
    int all_threads = 1;
    PyThreadState *tstate;
    const char *errmsg;
    int fd;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
        "|Oi:dump_traceback", kwlist,
        &file, &all_threads))
        return NULL;

    fd = cfaulthandler_get_fileno(&file);
    if (fd < 0)
        return NULL;

    tstate = get_thread_state();
    if (tstate == NULL)
        return NULL;

    if (all_threads) {
        errmsg = _Py_DumpTracebackThreads(fd, NULL, tstate);
        if (errmsg != NULL) {
            PyErr_SetString(PyExc_RuntimeError, errmsg);
            return NULL;
        }
    }
    else {
        _Py_DumpTraceback(fd, tstate);
    }

    if (PyErr_CheckSignals())
        return NULL;

    Py_RETURN_NONE;
}

static void
cfaulthandler_disable_fatal_handler(fault_handler_t *handler)
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
   the program continues at cfaulthandler_fatal_error() exit, but the same
   instruction will raise the same fault (signal), and so the previous handler
   will be called.

   This function is signal-safe and should only call signal-safe functions. */

static void
cfaulthandler_fatal_error(int signum)
{
    const int fd = fatal_error.fd;
    size_t i;
    fault_handler_t *handler = NULL;
    int save_errno = errno;
    int found = 0;

    if (!fatal_error.enabled)
        return;

    for (i=0; i < cfaulthandler_nsignals; i++) {
        handler = &cfaulthandler_handlers[i];
        if (handler->signum == signum) {
            found = 1;
            break;
        }
    }
    if (handler == NULL) {
        /* cfaulthandler_nsignals == 0 (unlikely) */
        return;
    }

    /* restore the previous handler */
    cfaulthandler_disable_fatal_handler(handler);

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

    cfaulthandler_dump_traceback(fd, fatal_error.all_threads,
                                fatal_error.interp);

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
cfaulthandler_ignore_exception(DWORD code)
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
cfaulthandler_exc_handler(struct _EXCEPTION_POINTERS *exc_info)
{
    const int fd = fatal_error.fd;
    DWORD code = exc_info->ExceptionRecord->ExceptionCode;
    DWORD flags = exc_info->ExceptionRecord->ExceptionFlags;

    if (cfaulthandler_ignore_exception(code)) {
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
        for (size_t i=0; i < cfaulthandler_nsignals; i++) {
            fault_handler_t *handler = &cfaulthandler_handlers[i];
            if (handler->signum == SIGSEGV) {
                cfaulthandler_disable_fatal_handler(handler);
                break;
            }
        }
    }

    cfaulthandler_dump_traceback(fd, fatal_error.all_threads,
                                fatal_error.interp);

    /* call the next exception handler */
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif


#ifdef CFAULTHANDLER_USE_ALT_STACK
static int
cfaulthandler_allocate_stack(void)
{
    if (stack.ss_sp != NULL) {
        return 0;
    }
    /* Allocate an alternate stack for cfaulthandler() signal handler
       to be able to execute a signal handler on a stack overflow error */
    stack.ss_sp = PyMem_Malloc(stack.ss_size);
    if (stack.ss_sp == NULL) {
        PyErr_NoMemory();
        return -1;
    }

    int err = sigaltstack(&stack, &old_stack);
    if (err) {
        /* Release the stack to retry sigaltstack() next time */
        PyMem_Free(stack.ss_sp);
        stack.ss_sp = NULL;

        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }
    return 0;
}
#endif


/* Install the handler for fatal signals, cfaulthandler_fatal_error(). */

static int
cfaulthandler_enable(void)
{
    if (fatal_error.enabled) {
        return 0;
    }
    fatal_error.enabled = 1;

#ifdef CFAULTHANDLER_USE_ALT_STACK
    if (cfaulthandler_allocate_stack() < 0) {
        return -1;
    }
#endif

    for (size_t i=0; i < cfaulthandler_nsignals; i++) {
        fault_handler_t *handler;
        int err;

        handler = &cfaulthandler_handlers[i];
        assert(!handler->enabled);
#ifdef HAVE_SIGACTION
        struct sigaction action;
        action.sa_handler = cfaulthandler_fatal_error;
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
                                   cfaulthandler_fatal_error);
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
    fatal_error.exc_handler = AddVectoredExceptionHandler(1, cfaulthandler_exc_handler);
#endif
    return 0;
}

static PyObject*
cfaulthandler_py_enable(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"file", "all_threads", NULL};
    PyObject *file = NULL;
    int all_threads = 1;
    int fd;
    PyThreadState *tstate;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
        "|Oi:enable", kwlist, &file, &all_threads))
        return NULL;

    fd = cfaulthandler_get_fileno(&file);
    if (fd < 0)
        return NULL;

    tstate = get_thread_state();
    if (tstate == NULL)
        return NULL;

    Py_XINCREF(file);
    Py_XSETREF(fatal_error.file, file);
    fatal_error.fd = fd;
    fatal_error.all_threads = all_threads;
    fatal_error.interp = PyThreadState_GetInterpreter(tstate);

    if (cfaulthandler_enable() < 0) {
        return NULL;
    }

    Py_RETURN_NONE;
}

static void
cfaulthandler_disable(void)
{
    if (fatal_error.enabled) {
        fatal_error.enabled = 0;
        for (size_t i=0; i < cfaulthandler_nsignals; i++) {
            fault_handler_t *handler;
            handler = &cfaulthandler_handlers[i];
            cfaulthandler_disable_fatal_handler(handler);
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
cfaulthandler_disable_py(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    if (!fatal_error.enabled) {
        Py_RETURN_FALSE;
    }
    cfaulthandler_disable();
    Py_RETURN_TRUE;
}

static PyObject*
cfaulthandler_is_enabled(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return PyBool_FromLong(fatal_error.enabled);
}

static void
cfaulthandler_thread(void *unused)
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

        _Py_write_noraise(thread.fd, thread.header, (int)thread.header_len);

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

    /* Wait for thread to join */
    PyThread_acquire_lock(thread.running, 1);
    PyThread_release_lock(thread.running);

    /* The main thread should always hold the cancel_event lock */
    PyThread_acquire_lock(thread.cancel_event, 1);

    Py_CLEAR(thread.file);
    if (thread.header) {
        PyMem_Free(thread.header);
        thread.header = NULL;
    }
}

#define SEC_TO_US (1000 * 1000)

static char*
format_timeout(_PyTime_t us)
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
    return _PyMem_Strdup(buffer);
}

static PyObject*
cfaulthandler_dump_traceback_later(PyObject *self,
                                   PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"timeout", "repeat", "file", "exit", NULL};
    PyObject *timeout_obj;
    _PyTime_t timeout, timeout_us;
    int repeat = 0;
    PyObject *file = NULL;
    int fd;
    int exit = 0;
    PyThreadState *tstate;
    char *header;
    size_t header_len;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
        "O|iOi:dump_traceback_later", kwlist,
        &timeout_obj, &repeat, &file, &exit))
        return NULL;

    if (_PyTime_FromSecondsObject(&timeout, timeout_obj,
                                  _PyTime_ROUND_TIMEOUT) < 0) {
        return NULL;
    }
    timeout_us = _PyTime_AsMicroseconds(timeout, _PyTime_ROUND_TIMEOUT);
    if (timeout_us <= 0) {
        PyErr_SetString(PyExc_ValueError, "timeout must be greater than 0");
        return NULL;
    }
    /* Limit to LONG_MAX seconds for format_timeout() */
    if (timeout_us > PY_TIMEOUT_MAX || timeout_us / SEC_TO_US > LONG_MAX) {
        PyErr_SetString(PyExc_OverflowError,
                        "timeout value is too large");
        return NULL;
    }

    tstate = get_thread_state();
    if (tstate == NULL) {
        return NULL;
    }

    fd = cfaulthandler_get_fileno(&file);
    if (fd < 0) {
        return NULL;
    }

    if (!thread.running) {
        thread.running = PyThread_allocate_lock();
        if (!thread.running) {
            return PyErr_NoMemory();
        }
    }
    if (!thread.cancel_event) {
        thread.cancel_event = PyThread_allocate_lock();
        if (!thread.cancel_event || !thread.running) {
            return PyErr_NoMemory();
        }

        /* cancel_event starts to be acquired: it's only released to cancel
           the thread. */
        PyThread_acquire_lock(thread.cancel_event, 1);
    }

    /* format the timeout */
    header = format_timeout(timeout_us);
    if (header == NULL) {
        return PyErr_NoMemory();
    }
    header_len = strlen(header);

    /* Cancel previous thread, if running */
    cancel_dump_traceback_later();

    Py_XINCREF(file);
    Py_XSETREF(thread.file, file);
    thread.fd = fd;
    /* the downcast is safe: we check that 0 < timeout_us < PY_TIMEOUT_MAX */
    thread.timeout_us = (PY_TIMEOUT_T)timeout_us;
    thread.repeat = repeat;
    thread.interp = PyThreadState_GetInterpreter(tstate);
    thread.exit = exit;
    thread.header = header;
    thread.header_len = header_len;

    /* Arm these locks to serve as events when released */
    PyThread_acquire_lock(thread.running, 1);

    if (PyThread_start_new_thread(cfaulthandler_thread, NULL) == PYTHREAD_INVALID_THREAD_ID) {
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
cfaulthandler_cancel_dump_traceback_later_py(PyObject *self,
                                            PyObject *Py_UNUSED(ignored))
{
    cancel_dump_traceback_later();
    Py_RETURN_NONE;
}


#ifdef CFAULTHANDLER_USER
static int
cfaulthandler_register(int signum, int chain, _Py_sighandler_t *previous_p)
{
#ifdef HAVE_SIGACTION
    struct sigaction action;
    action.sa_handler = cfaulthandler_user;
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
    previous = signal(signum, cfaulthandler_user);
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
cfaulthandler_user(int signum)
{
    user_signal_t *user;
    int save_errno = errno;

    user = &user_signals[signum];
    if (!user->enabled)
        return;

    cfaulthandler_dump_traceback(user->fd, user->all_threads, user->interp);

#ifdef HAVE_SIGACTION
    if (user->chain) {
        (void)sigaction(signum, &user->previous, NULL);
        errno = save_errno;

        /* call the previous signal handler */
        raise(signum);

        save_errno = errno;
        (void)cfaulthandler_register(signum, user->chain, NULL);
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
    for (size_t i=0; i < cfaulthandler_nsignals; i++) {
        if (cfaulthandler_handlers[i].signum == signum) {
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
cfaulthandler_register_py(PyObject *self,
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
        "i|Oii:register", kwlist,
        &signum, &file, &all_threads, &chain))
        return NULL;

    if (!check_signum(signum))
        return NULL;

    tstate = get_thread_state();
    if (tstate == NULL)
        return NULL;

    fd = cfaulthandler_get_fileno(&file);
    if (fd < 0)
        return NULL;

    if (user_signals == NULL) {
        user_signals = PyMem_Calloc(Py_NSIG, sizeof(user_signal_t));
        if (user_signals == NULL)
            return PyErr_NoMemory();
    }
    user = &user_signals[signum];

    if (!user->enabled) {
#ifdef CFAULTHANDLER_USE_ALT_STACK
        if (cfaulthandler_allocate_stack() < 0) {
            return NULL;
        }
#endif

        err = cfaulthandler_register(signum, chain, &previous);
        if (err) {
            PyErr_SetFromErrno(PyExc_OSError);
            return NULL;
        }

        user->previous = previous;
    }

    Py_XINCREF(file);
    Py_XSETREF(user->file, file);
    user->fd = fd;
    user->all_threads = all_threads;
    user->chain = chain;
    user->interp = PyThreadState_GetInterpreter(tstate);
    user->enabled = 1;

    Py_RETURN_NONE;
}

static int
cfaulthandler_unregister(user_signal_t *user, int signum)
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
cfaulthandler_unregister_py(PyObject *self, PyObject *args)
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
    change = cfaulthandler_unregister(user, signum);
    return PyBool_FromLong(change);
}
#endif   /* CFAULTHANDLER_USER */


static void
cfaulthandler_suppress_crash_report(void)
{
#ifdef MS_WINDOWS
    UINT mode;

    /* Configure Windows to not display the Windows Error Reporting dialog */
    mode = SetErrorMode(SEM_NOGPFAULTERRORBOX);
    SetErrorMode(mode | SEM_NOGPFAULTERRORBOX);
#endif

#ifdef HAVE_SYS_RESOURCE_H
    struct rlimit rl;

    /* Disable creation of core dump */
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
cfaulthandler_read_null(PyObject *self, PyObject *args)
{
    volatile int *x;
    volatile int y;

    cfaulthandler_suppress_crash_report();
    x = NULL;
    y = *x;
    return PyLong_FromLong(y);

}

static void
cfaulthandler_raise_sigsegv(void)
{
    cfaulthandler_suppress_crash_report();
#if defined(MS_WINDOWS)
    /* For SIGSEGV, cfaulthandler_fatal_error() restores the previous signal
       handler and then gives back the execution flow to the program (without
       explicitly calling the previous error handler). In a normal case, the
       SIGSEGV was raised by the kernel because of a fault, and so if the
       program retries to execute the same instruction, the fault will be
       raised again.

       Here the fault is simulated by a fake SIGSEGV signal raised by the
       application. We have to raise SIGSEGV at lease twice: once for
       cfaulthandler_fatal_error(), and one more time for the previous signal
       handler. */
    while(1)
        raise(SIGSEGV);
#else
    raise(SIGSEGV);
#endif
}

static PyObject *
cfaulthandler_sigsegv(PyObject *self, PyObject *args)
{
    int release_gil = 0;
    if (!PyArg_ParseTuple(args, "|i:_sigsegv", &release_gil))
        return NULL;

    if (release_gil) {
        Py_BEGIN_ALLOW_THREADS
        cfaulthandler_raise_sigsegv();
        Py_END_ALLOW_THREADS
    } else {
        cfaulthandler_raise_sigsegv();
    }
    Py_RETURN_NONE;
}

static void _Py_NO_RETURN
cfaulthandler_fatal_error_thread(void *plock)
{
    Py_FatalError("in new thread");
}

static PyObject *
cfaulthandler_fatal_error_c_thread(PyObject *self, PyObject *args)
{
    long thread;
    PyThread_type_lock lock;

    cfaulthandler_suppress_crash_report();

    lock = PyThread_allocate_lock();
    if (lock == NULL)
        return PyErr_NoMemory();

    PyThread_acquire_lock(lock, WAIT_LOCK);

    thread = PyThread_start_new_thread(cfaulthandler_fatal_error_thread, lock);
    if (thread == -1) {
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
cfaulthandler_sigfpe(PyObject *self, PyObject *args)
{
    cfaulthandler_suppress_crash_report();

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
cfaulthandler_sigabrt(PyObject *self, PyObject *args)
{
    cfaulthandler_suppress_crash_report();
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
cfaulthandler_stack_overflow(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    size_t depth, size;
    uintptr_t sp = (uintptr_t)&depth;
    uintptr_t stop, lower_limit, upper_limit;

    cfaulthandler_suppress_crash_report();
    depth = 0;

    if (STACK_OVERFLOW_MAX_SIZE <= sp) {
        lower_limit = sp - STACK_OVERFLOW_MAX_SIZE;
    }
    else {
        lower_limit = 0;
    }

    if (UINTPTR_MAX - STACK_OVERFLOW_MAX_SIZE >= sp) {
        upper_limit = sp + STACK_OVERFLOW_MAX_SIZE;
    }
    else {
        upper_limit = UINTPTR_MAX;
    }

    stop = stack_overflow(lower_limit, upper_limit, &depth);
    if (sp < stop)
        size = stop - sp;
    else
        size = sp - stop;
    PyErr_Format(PyExc_RuntimeError,
        "unable to raise a stack overflow (allocated %zu bytes "
        "on the stack, %zu recursive calls)",
        size, depth);
    return NULL;
}
#endif   /* defined(CFAULTHANDLER_USE_ALT_STACK) && defined(HAVE_SIGACTION) */


static int
cfaulthandler_traverse(PyObject *module, visitproc visit, void *arg)
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
cfaulthandler_raise_exception(PyObject *self, PyObject *args)
{
    unsigned int code, flags = 0;
    if (!PyArg_ParseTuple(args, "I|I:_raise_exception", &code, &flags))
        return NULL;
    cfaulthandler_suppress_crash_report();
    RaiseException(code, flags, 0, NULL);
    Py_RETURN_NONE;
}
#endif

PyDoc_STRVAR(module_doc,
"cfaulthandler module.");

static PyMethodDef module_methods[] = {
    {"enable",
     _PyCFunction_CAST(cfaulthandler_py_enable), METH_VARARGS|METH_KEYWORDS,
     PyDoc_STR("enable(file=sys.stderr, all_threads=True): "
               "enable the fault handler")},
    {"disable", cfaulthandler_disable_py, METH_NOARGS,
     PyDoc_STR("disable(): disable the fault handler")},
    {"is_enabled", cfaulthandler_is_enabled, METH_NOARGS,
     PyDoc_STR("is_enabled()->bool: check if the handler is enabled")},
    {"dump_traceback",
     _PyCFunction_CAST(cfaulthandler_dump_traceback_py), METH_VARARGS|METH_KEYWORDS,
     PyDoc_STR("dump_traceback(file=sys.stderr, all_threads=True): "
               "dump the traceback of the current thread, or of all threads "
               "if all_threads is True, into file")},
    {"dump_traceback_later",
     _PyCFunction_CAST(cfaulthandler_dump_traceback_later), METH_VARARGS|METH_KEYWORDS,
     PyDoc_STR("dump_traceback_later(timeout, repeat=False, file=sys.stderrn, exit=False):\n"
               "dump the traceback of all threads in timeout seconds,\n"
               "or each timeout seconds if repeat is True. If exit is True, "
               "call _exit(1) which is not safe.")},
    {"cancel_dump_traceback_later",
     cfaulthandler_cancel_dump_traceback_later_py, METH_NOARGS,
     PyDoc_STR("cancel_dump_traceback_later():\ncancel the previous call "
               "to dump_traceback_later().")},
#ifdef CFAULTHANDLER_USER
    {"register",
     _PyCFunction_CAST(cfaulthandler_register_py), METH_VARARGS|METH_KEYWORDS,
     PyDoc_STR("register(signum, file=sys.stderr, all_threads=True, chain=False): "
               "register a handler for the signal 'signum': dump the "
               "traceback of the current thread, or of all threads if "
               "all_threads is True, into file")},
    {"unregister",
     _PyCFunction_CAST(cfaulthandler_unregister_py), METH_VARARGS|METH_KEYWORDS,
     PyDoc_STR("unregister(signum): unregister the handler of the signal "
                "'signum' registered by register()")},
#endif
    {"_read_null", cfaulthandler_read_null, METH_NOARGS,
     PyDoc_STR("_read_null(): read from NULL, raise "
               "a SIGSEGV or SIGBUS signal depending on the platform")},
    {"_sigsegv", cfaulthandler_sigsegv, METH_VARARGS,
     PyDoc_STR("_sigsegv(release_gil=False): raise a SIGSEGV signal")},
    {"_fatal_error_c_thread", cfaulthandler_fatal_error_c_thread, METH_NOARGS,
     PyDoc_STR("fatal_error_c_thread(): "
               "call Py_FatalError() in a new C thread.")},
    {"_sigabrt", cfaulthandler_sigabrt, METH_NOARGS,
     PyDoc_STR("_sigabrt(): raise a SIGABRT signal")},
    {"_sigfpe", (PyCFunction)cfaulthandler_sigfpe, METH_NOARGS,
     PyDoc_STR("_sigfpe(): raise a SIGFPE signal")},
#ifdef CFAULTHANDLER_STACK_OVERFLOW
    {"_stack_overflow", cfaulthandler_stack_overflow, METH_NOARGS,
     PyDoc_STR("_stack_overflow(): recursive call to raise a stack overflow")},
#endif
#ifdef MS_WINDOWS
    {"_raise_exception", cfaulthandler_raise_exception, METH_VARARGS,
     PyDoc_STR("raise_exception(code, flags=0): Call RaiseException(code, flags).")},
#endif
    {NULL, NULL}  /* sentinel */
};

static int cfaulthandler_module_initialized = 0;

/* Note on initialization/finalization in cfaulthandler vs faulthandler:
The builtin faulthandler module is compiled into the Python interpreter, and
the Python interpreter automatically calls a special _PyFaulthandler_Init()
function on interpreter startup. cfaulthandler isn't built into the
interpreter, so we do this initialization when the cfaulthandler module is
loaded instead. Same with finalization. */

static int
PyExec_cfaulthandler(PyObject *module) {
    /* cfaulthandler uses static globals to store state. If multiple Python
    interpreters were running in the same process, and they all imported the
    cfaulthandler module, this could lead to odd bugs. For now we just ban
    this. (The builtin faulthandler module doesn't ban this; I think this is a
    bug in the builtin faulthandler mdoule?)*/
    if (cfaulthandler_module_initialized) {
        PyErr_SetString(PyExc_ImportError,
                        "can't load cfaulthandler more than once per process");
        return -1;
    }
    cfaulthandler_module_initialized = 1;

#ifdef CFAULTHANDLER_USE_ALT_STACK
    memset(&stack, 0, sizeof(stack));
    stack.ss_flags = 0;
    /* bpo-21131: allocate dedicated stack of SIGSTKSZ*2 bytes, instead of just
       SIGSTKSZ bytes. Calling the previous signal handler in cfaulthandler
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

    memset(&thread, 0, sizeof(thread));

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

    /* RaiseException() flags (prefixed by an underscore) */
    if (PyModule_AddIntConstant(module, "_EXCEPTION_NONCONTINUABLE",
                                EXCEPTION_NONCONTINUABLE)) {
        return -1;
    }
    if (PyModule_AddIntConstant(module, "_EXCEPTION_NONCONTINUABLE_EXCEPTION",
                                EXCEPTION_NONCONTINUABLE_EXCEPTION)) {
        return -1;
    }
#endif
    return 0;
}


static void
cfaulthandler_free(void *module)
{
    (void)module;

    /* later */
    if (thread.cancel_event) {
        cancel_dump_traceback_later();
        PyThread_release_lock(thread.cancel_event);
        PyThread_free_lock(thread.cancel_event);
        thread.cancel_event = NULL;
    }
    if (thread.running) {
        PyThread_free_lock(thread.running);
        thread.running = NULL;
    }

#ifdef CFAULTHANDLER_USER
    /* user */
    if (user_signals != NULL) {
        for (size_t signum=0; signum < Py_NSIG; signum++) {
            cfaulthandler_unregister(&user_signals[signum], signum);
        }
        PyMem_Free(user_signals);
        user_signals = NULL;
    }
#endif

    /* fatal */
    cfaulthandler_disable();

#ifdef CFAULTHANDLER_USE_ALT_STACK
    if (stack.ss_sp != NULL) {
        /* Fetch the current alt stack */
        stack_t current_stack;
        memset(&current_stack, 0, sizeof(current_stack));
        if (sigaltstack(NULL, &current_stack) == 0) {
            if (current_stack.ss_sp == stack.ss_sp) {
                /* The current alt stack is the one that we installed.
                 It is safe to restore the old stack that we found when
                 we installed ours */
                sigaltstack(&old_stack, NULL);
            } else {
                /* Someone switched to a different alt stack and didn't
                   restore ours when they were done (if they're done).
                   There's not much we can do in this unlikely case */
            }
        }
        PyMem_Free(stack.ss_sp);
        stack.ss_sp = NULL;
    }
#endif

    cfaulthandler_module_initialized = 0;
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
    .m_traverse = cfaulthandler_traverse,
    .m_slots = cfaulthandler_slots,
    .m_free = cfaulthandler_free
};

PyMODINIT_FUNC
PyInit_cfaulthandler(void)
{
    return PyModuleDef_Init(&module_def);
}