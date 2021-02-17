# Copyright 2017 David R. Bild
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License

from __future__ import absolute_import

import ssl
import _ssl
import weakref
import datetime

from sslpsk2 import _sslpsk2

_callbacks = {}

class FinalizerRef(weakref.ref):
    """subclass weakref.ref so that attributes can be added"""
    pass

def _register_callback(sock, ssl_id, callback):
    print("[sslpsk2.py][_register_callback] - _register_callback")
    print("[sslpsk2.py][_register_callback] - call back type = ", type(callback))
    print("Type of _callback = ", type(_callbacks))
    print("Type of _callback pass argument = ", type(callback))

    _callbacks[ssl_id] = callback
    callback.unregister = FinalizerRef(sock, _unregister_callback)
    callback.unregister.ssl_id = ssl_id

def _unregister_callback(ref):
    print("[sslpsk2.py][_unregister_callback] - _unregister_callback - delete _callbacks[ref.ssl_id]")
    print("Type of ref = ", type(ref))
    print("This is ref.ssl_id = ", ref.ssl_id)
    del _callbacks[ref.ssl_id]

def _python_psk_client_callback(ssl_id, hint):
    #Called by _sslpsk2.c to return the (psk, identity) tuple for the socket with the specified ssl socket.
    
    print("[sslpsk2.py][_python_psk_client_callback] - _python_psk_client_callback")
    print("[sslpsk2.py][_python_psk_client_callback] - ssl_id = ", ssl_id)
    print("[sslpsk2.py][_python_psk_client_callback] - hint = ", hint)
    print("[sslpsk2.py][_python_psk_client_callback] - _callbacks = ", _callbacks)

    if ssl_id not in _callbacks:
        print("[sslpsk2.py][_python_psk_client_callback] - ssl_id not in callbacks. It will return (b'', b'')")
        return (b"", b"")
    else:
        print("[sslpsk2.py][_python_psk_client_callback] - ssl_id in callbacks. It will return res")
        print("Time when thread reached this client callback = ", datetime.datetime.now().time())
        res = _callbacks[ssl_id](hint)

        hint = res[1].decode("utf-8")
        print("Hint value = ", hint)
        #hint = hint.decode("utf-8")
        client_identity = _callbacks[ssl_id](b'identity')[0].decode("utf-8")
        client_value = _callbacks[ssl_id](b'value')[0].decode("utf-8")

        print("Value dari client_identity = ", client_identity)
        print("Type dari client_identity = ", type(client_identity))

        concated_hint = client_value+"*"+client_identity+"*"+hint
        concated_hint = concated_hint.encode()
        print("[sslpsk2.py][_python_psk_client_callback] - res before = ", res)
        res_2 = (res[0], concated_hint)
        print("[sslpsk2.py][_python_psk_client_callback] - res after= ", res_2)
        res = res_2
        return res if isinstance(res, tuple) else (res, b"")

#original code of _python_psk_client_callback
"""
def _python_psk_client_callback(ssl_id, hint):
    #Called by _sslpsk2.c to return the (psk, identity) tuple for the socket with the specified ssl socket.
    print("[sslpsk2.py][_python_psk_client_callback] - _python_psk_client_callback")
    print("[sslpsk2.py][_python_psk_client_callback] - ssl_id = ", ssl_id)
    print("[sslpsk2.py][_python_psk_client_callback] - hint = ", hint)
    print("[sslpsk2.py][_python_psk_client_callback] - _callbacks = ", _callbacks)

    if ssl_id not in _callbacks:
        print("[sslpsk2.py][_python_psk_client_callback] - ssl_id not in callbacks. It will return (b'', b'')")
        return (b"", b"")
    else:
        print("[sslpsk2.py][_python_psk_client_callback] - ssl_id in callbacks. It will return res")
        res = _callbacks[ssl_id](hint)
        print("[sslpsk2.py][_python_psk_client_callback] - res = ", res)
        return res if isinstance(res, tuple) else (res, b"")
"""
def _sslobj(sock):
    print("[sslpsk2.py][_sslobj]- _sslobj")
    """Returns the underlying PySLLSocket object with which the C extension
    functions interface.

    """
    pass
    if isinstance(sock._sslobj, _ssl._SSLSocket):
        print("[sslpsk2.py][_sslobj] - _sslobj - conditional true")
        return sock._sslobj
    else:
        return sock._sslobj._sslobj
        print("[sslpsk2.py][_sslobj] - _sslobj - conditional false")

    print("[sslpsk2.py][_sslobj] - _sslobj (in the end of _sslobj)")

def _python_psk_server_callback(ssl_id, identity):
    print("[sslpsk2.py][_python_psk_server_callback] - _python_psk_server_callback")
    print("[sslpsk2.py][_python_psk_server_callback] - ssl_id = ", ssl_id)
    print("[sslpsk2.py][_python_psk_server_callback] - identity = ", identity)
    print("[sslpsk2.py][_python_psk_server_callback] - _callbacks = ", _callbacks)
    #print("[sslpsk2.py][_python_psk_server_callback] - client_identity = ", client_identity)
    #print("[sslpsk2.py][_python_psk_server_callback] - client_value = ", client_value)

    #Called by _sslpsk2.c to return the psk for the socket with the specified ssl socket.

    if ssl_id not in _callbacks:
        print("[sslpsk2.py][_python_psk_server_callback] - ssl_id not in _callbacks")
        return b""
    else:
        print("[sslpsk2.py][_python_psk_server_callback] - ssl_id in _callbacks, it will return _callbacks")
        print("Time when thread reached this client callback = ", datetime.datetime.now().time())
        parsed_identity = identity.decode("utf-8").split("*")
        print("parsed identity = ", parsed_identity)
        client_value = parsed_identity[0]
        client_identity = parsed_identity[1]
        print("client value = ", client_value)
        print("client identity = ", client_identity)
        identity = parsed_identity[2].encode()

        result = _callbacks[ssl_id](identity)
        print("Result = ", result)
        print("identity bytes form = ", identity)
        result_mock = "false".encode()
        print("After encode = ", result_mock)
        #return _callbacks[ssl_id](identity)
        return result_mock

#original code of _python_psk_server_callback

"""
def _python_psk_server_callback(ssl_id, identity):
    print("[sslpsk2.py][_python_psk_server_callback] - _python_psk_server_callback")
    print("[sslpsk2.py][_python_psk_server_callback] - ssl_id = ", ssl_id)
    print("[sslpsk2.py][_python_psk_server_callback] - identity = ", identity)
    print("[sslpsk2.py][_python_psk_server_callback] - _callbacks = ", _callbacks)

    #Called by _sslpsk2.c to return the psk for the socket with the specified ssl socket.
    if ssl_id not in _callbacks:
        print("[sslpsk2.py][_python_psk_server_callback] - ssl_id not in _callbacks")
        return b""
    else:
        print("[sslpsk2.py][_python_psk_server_callback] - ssl_id in _callbacks, it will return _callbacks")
        print("Result --->>>>>>>>>>>>> = ", _callbacks[ssl_id](identity))
        return _callbacks[ssl_id](identity)
"""
print("[sslpsk2.py] --------------------------------------")
print(
    "[sslpsk2.py] NOT IN ANY METHOD - Call _sslpsk2 object to set python psk client callback and server client callback")

_sslpsk2.sslpsk2_set_python_psk_client_callback(_python_psk_client_callback)
_sslpsk2.sslpsk2_set_python_psk_server_callback(_python_psk_server_callback)
print("[sslpsk2.py] --------------------------------------")


def _ssl_set_psk_client_callback(sock, psk_cb):
    print("[sslpsk2.py][_ssl_set_psk_client_callback] - _ssl_set_psk_client_callback 1")
    ssl_id = _sslpsk2.sslpsk2_set_psk_client_callback(_sslobj(sock))
    print("[sslpsk2.py][_ssl_set_psk_client_callback] - ssl_id = ", ssl_id)
    print("[sslpsk2.py][_ssl_set_psk_client_callback] - psk_cb = ", psk_cb)
    _register_callback(sock, ssl_id, psk_cb)


def _ssl_set_psk_server_callback(sock, psk_cb, hint):
    print("[sslpsk2.py][_ssl_set_psk_server_callback] - _ssl_set_psk_server_callback 2")

    ssl_id = _sslpsk2.sslpsk2_set_accept_state(_sslobj(sock))
    _ = _sslpsk2.sslpsk2_set_psk_server_callback(_sslobj(sock))
    _ = _sslpsk2.sslpsk2_use_psk_identity_hint(_sslobj(sock), hint if hint else b"")
    _register_callback(sock, ssl_id, psk_cb)


def wrap_socket(*args, **kwargs):
    """
    """
    print("[sslpsk2.py] --------------------------------------")
    print("[sslpsk2.py][wrap_socket] - wrap_socket")
    # print("[sslpsk2.py][wrap_socket] - args = ", args)
    # print("[sslpsk2.py][wrap_socket] - kwargs = ", args)

    do_handshake_on_connect = kwargs.get('do_handshake_on_connect', True)
    kwargs['do_handshake_on_connect'] = False

    psk = kwargs.setdefault('psk', None)
    del kwargs['psk']

    hint = kwargs.setdefault('hint', None)
    del kwargs['hint']

    print("[sslpsk2.py][wrap_socket] - psk = ", psk)
    print("[sslpsk2.py][wrap_socket] - [If it is CLIENT, then it will be none] - hint = ", hint)

    server_side = kwargs.setdefault('server_side', False)
    if psk:
        print("[sslpsk2.py][wrap_socket] - wrap_socket - server_side false")
        del kwargs['server_side']  # bypass need for cert

    sock = ssl.wrap_socket(*args, **kwargs)

    print("[sslpsk2.py][wrap_socket] - psk = ", psk)
    print("[sslpsk2.py][wrap_socket] - [If it is CLIENT, then it will be none] - hint = ", hint)

    if psk:
        if server_side:
            print("[sslpsk2.py][wrap_socket] - server_side true")
            cb = psk if callable(psk) else lambda _identity: psk
            print("cb server = ", cb)
            _ssl_set_psk_server_callback(sock, cb, hint)
        else:
            print("[sslpsk2.py][wrap_socket] - server_side false")

            if callable(psk):
                print("[sslpsk2.py][wrap_socket] - PSK is callable!!!")
            else:
                print("[sslpsk2.py][wrap_socket] - PSK is not callable")
                print(lambda _hint: psk if isinstance(psk, tuple) else (psk, b""))

            cb = psk if callable(psk) else lambda _hint: psk if isinstance(psk, tuple) else (psk, b"")
            print("[sslpsk2.py][wrap_socket] - cb client = ", cb)
            _ssl_set_psk_client_callback(sock, cb)

    if do_handshake_on_connect:
        print("[sslpsk2.py][wrap_socket] - do_handshake_on_connect - true")
        sock.do_handshake()

    return sock

def make_sound():
    print("Bisa sukses, bisa berhasil ngecrack, insya Allah!")

