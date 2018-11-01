#pragma clang diagnostic push
#pragma ide diagnostic ignored "cert-err34-c"
//
// Created by xjw on 10/20/18.
//
#include <Python.h>
#include "main.h"

static PyObject *CboxError;

static PyObject *
wrapper_func(PyObject *self, PyObject *args) {
    int a, b;
    const char *str;
    if (!PyArg_ParseTuple(args, "iis", &a, &b, &str))
        return NULL;
    c_result result;
    int code = func(a, b, str, &result);
    // a = fileno
    return Py_BuildValue("(i, {s:i,s:i,s:s})",
            code, "val1", result.val1,
            "val2", result.val2,
            "str", result.str);
};

static PyMethodDef cBoxMethods[] = {
        {"func",  wrapper_func, METH_VARARGS,
                    "a func in c box."},
        {NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef cboxmodule = {
        PyModuleDef_HEAD_INIT,
        "cbox",     /* name of module */
        NULL,       /* module documentation, may be NULL */
        -1,         /* size of per-interpreter state of the module,
                    or -1 if the module keeps state in global variables. */
        cBoxMethods
};

PyMODINIT_FUNC
PyInit_cbox(void)
{
    PyObject *m;

    m = PyModule_Create(&cboxmodule);
    if (m == NULL)
        return NULL;

    CboxError = PyErr_NewException("cbox.error", NULL, NULL);
    Py_INCREF(CboxError);
    PyModule_AddObject(m, "error", CboxError);
    return m;
}

#pragma clang diagnostic pop