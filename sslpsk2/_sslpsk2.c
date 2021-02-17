/* Copyright 2017 David R. Bild
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <openssl/ssl.h>

/* Copy PySSLObject/PySSLSocket from _ssl.c to expose the SSL*. */
#if !defined(PY_MAJOR_VERSION) || (PY_VERSION_HEX < 0x02070000)
#error Only Python 2.7 and later are supported
#endif

#define PY_VERSION_BETWEEN(start, end) ((PY_VERSION_HEX >= start) && \
                                        (PY_VERSION_HEX < end))

typedef struct {
    PyObject_HEAD
#if PY_VERSION_BETWEEN(0x02070000, 0x03000000)
    void*          PySocketSockObject;
#endif
    PyObject*      socket;
#if PY_VERSION_BETWEEN(0x03000000, 0x03020000)
    void*          SSL_CTX;
#endif
    SSL*           ssl;
    /* etc */
} PySSLSocket;

#if PY_VERSION_BETWEEN(0x02070000, 0x03000000)
#define BYTESFMT "s"
#else
#define BYTESFMT "y"
#endif

/*
 * Python function that returns the client psk and identity.
 *
 * (ssl_id, hint) => (psk, idenity)
 */
static PyObject* python_psk_client_callback;

/*
 * Python function that returns the server psk.
 *
 * (ssl_id, identity) => psk
 */
static PyObject* python_psk_server_callback;

/*
 * Returns the index for an SSL socket, used to identity the socket across the
 * C/Python interface.
 */
long ssl_id(SSL* ssl)
{
    return (long) ssl;
}

/*
 * Called from Python to set python_psk_client_callback;
 */
PyObject* sslpsk2_set_python_psk_client_callback(PyObject* self, PyObject* args)
{
    printf("[_sslpsk2.c][sslpsk2_set_python_psk_client_callback] - sslpsk_set_python_psk_client_callback \n");
    PyObject* cb;
    if (!PyArg_ParseTuple(args, "O", &cb)) {
        printf("[_sslpsk2.c][sslpsk2_set_python_psk_client_callback] - sslpsk_set_python_psk_client_callback - conditional true \n");
        return NULL;
    }
    Py_XINCREF(cb);
    Py_XDECREF(python_psk_client_callback);
    python_psk_client_callback = cb;

    Py_RETURN_NONE;
}

/*
 * Called from Python to set python_psk_server_callback;
 */
PyObject* sslpsk2_set_python_psk_server_callback(PyObject* self, PyObject* args)
{
    printf("[_sslpsk2.c][sslpsk2_set_python_psk_server_callback] - sslpsk_set_python_psk_server_callback \n");
    PyObject* cb;
    if (!PyArg_ParseTuple(args, "O", &cb)) {
        printf("[_sslpsk2.c][sslpsk2_set_python_psk_server_callback] - sslpsk_set_python_psk_server_callback - conditional true \n");
        return NULL;
    }
    Py_XINCREF(cb);
    Py_XDECREF(python_psk_server_callback);
    python_psk_server_callback = cb;

    Py_RETURN_NONE;
}

/*
 * Client callback for openSSL. Delegates to python_psk_client_callback.
 */
static unsigned int sslpsk2_psk_client_callback(SSL* ssl,
                                               const char* hint,
                                               char* identity,
                                               unsigned int max_identity_len,
                                               unsigned char* psk,
                                               unsigned int max_psk_len)
{
    /*printf("[_sslpsk2.c][sslpsk2_psk_client_callback] - sslpsk_psk_client_callback \n");
    printf("[_sslpsk2.c][sslpsk2_psk_client_callback] - Print all parameter of this function \n");
    printf("[_sslpsk2.c][sslpsk2_psk_client_callback] - hint with percent d =  %d \n", hint);
    printf("[_sslpsk2.c][sslpsk2_psk_client_callback] - hint with percent c =  %c \n", hint);
    printf("[_sslpsk2.c][sslpsk2_psk_client_callback] - hint with percent s =  %s \n", hint);
    printf("[_sslpsk2.c][sslpsk2_psk_client_callback] - identity =  %d \n", identity);
    printf("[_sslpsk2.c][sslpsk2_psk_client_callback] - max_identity_len =  %i \n", max_identity_len);
    printf("[_sslpsk2.c][sslpsk2_psk_client_callback] - psk =  %d \n", psk);
    printf("[_sslpsk2.c][sslpsk2_psk_client_callback] - max_psk_len =  %i \n", max_psk_len);*/

    int ret = 0;

    PyGILState_STATE gstate;

    PyObject* result;

    const char* psk_;
    const char* identity_;

    Py_ssize_t psk_len_;
    Py_ssize_t identity_len_;

    gstate = PyGILState_Ensure();

    if (python_psk_client_callback == NULL) {
        printf("[_sslpsk2.c][sslpsk2_psk_client_callback] - sslpsk_psk_client_callback - python_psk_client_callback == NULL \n");
        goto release;
    }

    // Call python callback
    //Disini Jalanin Callback!!!!!!!!!
    result = PyObject_CallFunction(python_psk_client_callback, "l"BYTESFMT, ssl_id(ssl), hint);

    if (result == NULL) {
        printf("[_sslpsk2.c][sslpsk2_psk_client_callback] - sslpsk_psk_client_callback - result == NULL \n");
        goto release;
    }

    // Parse result

    if (!PyArg_Parse(result, "("BYTESFMT"#"BYTESFMT"#)", &psk_, &psk_len_, &identity_, &identity_len_)) {
        printf("[_sslpsk2.c][sslpsk2_psk_client_callback] - sslpsk_psk_client_callback - conditional false \n");
        goto decref;
    }

    // Copy to caller
    if (psk_len_ > max_psk_len) {
        printf("[_sslpsk2.c][sslpsk2_psk_client_callback] - sslpsk_psk_client_callback - psk_len_ > max_psk_len \n");
        goto decref;
    }
    memcpy(psk, psk_, psk_len_);

    if (identity_len_ + 1 > max_identity_len) {
        printf("[_sslpsk2.c][sslpsk2_psk_client_callback] - sslpsk_psk_client_callback - identity_len_ + 1 > max_identity_len \n");
        goto decref;
    }
    memcpy(identity, identity_, identity_len_);
    identity[identity_len_] = 0;

    ret = psk_len_;
    printf("ret dari client = %i \n", ret);
 decref:
    printf("[_sslpsk2.c][sslpsk2_psk_client_callback] - sslpsk_psk_client_callback - in decref \n");
    Py_DECREF(result);

 release:
    printf("[_sslpsk2.c][sslpsk2_psk_client_callback] - sslpsk_psk_client_callback - in release \n");
    PyGILState_Release(gstate);

    return ret;
}

/*
 * Server callback for openSSL. Delegates to python_psk_server_callback.
 */
static unsigned int sslpsk2_psk_server_callback(SSL* ssl,
                                               const char* identity,
                                               unsigned char* psk,
                                               unsigned int max_psk_len)
{
    /*printf("[_sslpsk2.c][sslpsk2_psk_server_callback] - sslpsk_psk_server_callback \n");
    printf("[_sslpsk2.c][sslpsk2_psk_server_callback] - Print all parameter of this function \n");
    printf("[_sslpsk2.c][sslpsk2_psk_server_callback] - identity = %p \n", (void *) identity);
    printf("[_sslpsk2.c][sslpsk2_psk_server_callback] - psk = %p \n", (void *) psk);
    printf("[_sslpsk2.c][sslpsk2_psk_server_callback] - max_psk_len = %i \n", max_psk_len);*/
    int ret = 0;

    PyGILState_STATE gstate;

    PyObject* result;

    const char* psk_;
    Py_ssize_t psk_len_;

    gstate = PyGILState_Ensure();

    if (python_psk_server_callback == NULL) {
        printf("[_sslpsk2.c][sslpsk2_psk_server_callback] - sslpsk_psk_server_callback - python_psk_server_callback == NULL \n");
        goto release;
    }

    // Call python callback
    result = PyObject_CallFunction(python_psk_server_callback, "l"BYTESFMT, ssl_id(ssl), identity);
    if (result == NULL) {
        printf("[_sslpsk2.c][sslpsk2_psk_server_callback] - sslpsk_psk_server_callback - result == NULL \n");
        goto release;
    }

    // Parse result
    if (!PyArg_Parse(result, BYTESFMT"#", &psk_, &psk_len_)) {
        printf("[_sslpsk2.c][sslpsk2_psk_server_callback] - sslpsk_psk_server_callback - conditional false \n");
        goto decref;
    }

    // Copy to caller/home/seslab/PycharmProjects/sslpsk2
    if (psk_len_ > max_psk_len) {
        printf("[_sslpsk2.c][sslpsk2_psk_server_callback] - sslpsk_psk_server_callback - psk_len_ > max_psk_len \n");
        goto decref;
    }
    memcpy(psk, psk_, psk_len_);

    printf("Ngajar Pelajaran Apa - Apa ? %s \n", psk_);

    ret = psk_len_;
    printf("What is ref ? %i \n", ret);

 decref:
    printf("[_sslpsk2.c][sslpsk2_psk_server_callback] - sslpsk_psk_server_callback - in decref \n");
    Py_DECREF(result);

 release:
    printf("[_sslpsk2.c][sslpsk2_psk_server_callback] - sslpsk_psk_server_callback - in release \n");
    PyGILState_Release(gstate);

    return ret;
}

/*
 * Called from Python to set the client psk callback.
 */
PyObject* sslpsk2_set_psk_client_callback(PyObject* self, PyObject* args)
{
    printf("[_sslpsk2.c][sslpsk2_set_psk_client_callback] - sslpsk_set_psk_client_callback \n");
    PyObject* socket;
    SSL* ssl;

    if (!PyArg_ParseTuple(args, "O", &socket))
    {
        printf("[_sslpsk2.c] - conditional false \n");
        return NULL;
    }

    ssl = ((PySSLSocket*) socket)->ssl;

    //OpenSSL syntax
    SSL_set_psk_client_callback(ssl, sslpsk2_psk_client_callback);

    /*int myResult = SSL_set_psk_client_callback(ssl, sslpsk2_psk_client_callback);
    printf("Halooo %i", myResult); */

    printf("[_sslpsk2.c][sslpsk2_set_psk_client_callback] - sslpsk_set_psk_client_callback - return \n");
    return Py_BuildValue("l", ssl_id(ssl));

}

/*
 * Called from Python to set the server psk callback.
 */
PyObject* sslpsk2_set_psk_server_callback(PyObject* self, PyObject* args)
{
    printf("[_sslpsk2.c][sslpsk2_set_psk_server_callback] - sslpsk_set_psk_server_callback \n");
    PyObject* socket;
    SSL* ssl;

    if (!PyArg_ParseTuple(args, "O", &socket))
    {
        printf("[_sslpsk2.c][sslpsk2_set_psk_server_callback] - sslpsk_set_psk_server_callback - conditional false \n");
        return NULL;
    }

    ssl = ((PySSLSocket*) socket)->ssl;

    //OpenSSL syntax
    SSL_set_psk_server_callback(ssl, sslpsk2_psk_server_callback);

    printf("[_sslpsk2.c][sslpsk2_set_psk_server_callback] - sslpsk_set_psk_server_callback - return \n");
    return Py_BuildValue("l", ssl_id(ssl));
}

/*
 * Called from Python to set the server identity hint.
 */
PyObject* sslpsk2_use_psk_identity_hint(PyObject* self, PyObject* args)
{
    printf("[_sslpsk2.c][sslpsk2_use_psk_identity_hint] - sslpsk_use_psk_identity_hint \n");
    PyObject* socket;
    const char *hint;
    SSL* ssl;

    if (!PyArg_ParseTuple(args, "O"BYTESFMT, &socket, &hint))
    {
        printf("[_sslpsk2.c][sslpsk2_use_psk_identity_hint] - sslpsk_use_psk_identity_hint - condtional false \n");
        return NULL;
    }

    ssl = ((PySSLSocket*) socket) ->ssl;

    //OpenSSL Syntax
    SSL_use_psk_identity_hint(ssl, hint);

    printf("[_sslpsk2.c][sslpsk2_use_psk_identity_hint] - sslpsk_use_psk_identity_hint - return\n");
    return Py_BuildValue("l", ssl_id(ssl));
}

/*
 * Called from Python to place the socket into server mode
 */
PyObject* sslpsk2_set_accept_state(PyObject* self, PyObject* args)
{
    printf("[_sslpsk2.c][sslpsk2_set_accept_state] - sslpsk_set_accept_state \n");
    PyObject* socket;
    SSL* ssl;

    if (!PyArg_ParseTuple(args, "O", &socket))
    {
        printf("[_sslpsk2.c][sslpsk2_set_accept_state] - sslpsk_set_accept_state - conditional false \n");
        return NULL;
    }

    ssl = ((PySSLSocket*) socket) ->ssl;

    //OpenSSL syntax
    SSL_set_accept_state(ssl);

    printf("[_sslpsk2.c][sslpsk2_set_accept_state] - sslpsk_set_accept_state - return \n");
    return Py_BuildValue("l", ssl_id(ssl));
}

static PyMethodDef sslpsk2_methods[] =
{
    {"sslpsk2_set_python_psk_client_callback", sslpsk2_set_python_psk_client_callback, METH_VARARGS, ""},
    {"sslpsk2_set_python_psk_server_callback", sslpsk2_set_python_psk_server_callback, METH_VARARGS, ""},
    {"sslpsk2_set_psk_client_callback", sslpsk2_set_psk_client_callback, METH_VARARGS, ""},
    {"sslpsk2_set_psk_server_callback", sslpsk2_set_psk_server_callback, METH_VARARGS, ""},
    {"sslpsk2_use_psk_identity_hint", sslpsk2_use_psk_identity_hint, METH_VARARGS, ""},
    {"sslpsk2_set_accept_state", sslpsk2_set_accept_state, METH_VARARGS, ""},
    {NULL, NULL, 0, NULL}
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef sslpsk2_moduledef = {
    PyModuleDef_HEAD_INIT,
    "sslpsk2",
    NULL,
    0,
    sslpsk2_methods,
    NULL,
    NULL,
    NULL,
    NULL
};
#endif

#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC PyInit__sslpsk2(void)
#else
void init_sslpsk2(void)
#endif
{
#if PY_MAJOR_VERSION >= 3
    PyObject* m = PyModule_Create(&sslpsk2_moduledef);
#else
    PyObject* m = Py_InitModule("_sslpsk2", sslpsk2_methods);
#endif

    if (m == NULL) {
#if PY_MAJOR_VERSION >= 3
        return NULL;
#else
        return ;
#endif
    }

#if PY_MAJOR_VERSION >= 3
    return m;
#endif
}
