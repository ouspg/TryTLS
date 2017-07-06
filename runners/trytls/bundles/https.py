from __future__ import absolute_import, unicode_literals

import ssl
import sys
import socket
import threading
import contextlib
try:
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
except ImportError:
    from http.server import HTTPServer, BaseHTTPRequestHandler

from .. import results
from ..utils import tmpfiles
from ..gencert import gencert
from ..testenv import testenv, testgroup, Test


BADTLS_CA_DATA = b"""
-----BEGIN CERTIFICATE-----
MIIDlTCCAn+gAwIBAgIIVvpPzLyqk+0wCwYJKoZIhvcNAQELMGoxaDAJBgNVBAYT
AlVTMBQGA1UECAwNTWFzc2FjaHVzZXR0czAOBgNVBAcMB05ld2J1cnkwFgYDVQQK
DA9CYWQgVExTIExpbWl0ZWQwHQYDVQQDDBZCYWQgVExTIExpbWl0ZWQgUlNBIENB
MB4XDTE2MDEwMTAwMDAwMFoXDTI2MDEwMTAwMDAwMFowajFoMAkGA1UEBhMCVVMw
FAYDVQQIDA1NYXNzYWNodXNldHRzMA4GA1UEBwwHTmV3YnVyeTAWBgNVBAoMD0Jh
ZCBUTFMgTGltaXRlZDAdBgNVBAMMFkJhZCBUTFMgTGltaXRlZCBSU0EgQ0EwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDSHu3OR1RS0D2xLKGK2Ts5eLoO
/P+IXst5WPdaD9UwGI8edfAy3U8wcMFDoXNhBQM+ZW69Z5uOZVxs704+j5cgCEAT
LbtyIrF2X8BixXFzrJFd+kpojURheyxML20GbZsznJgKzYvGqFqWa/1lYwy/v0SP
RNGPEkjFXb/tItDwrDxcuDzY6zjNlW5MwqvS11P1H8eg0idUrANY2MzT8+oyH3Sn
JLCsmulnmj1b6IZZDN4i8rKXEbH14jIsANHIgTqvS+kJf3Z1PqHAOUqVGlO3SDZd
KIqZ8olS6ty9/pco6cxvX2Te9m1z5f1fSrdxAtx7lHM3pdvs9DhML+8FAewDAgMB
AAGjQzBBMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFGEbxkZbhgwiZRAMx7Vs
VCRXl/tkMA8GA1UdDwEB/wQFAwMHBgAwCwYJKoZIhvcNAQELA4IBAQBKv0TJoRhd
wg7dPOFDVuKaLtuVzXEeUWfsA86iW4wjXFO/npI+1exSBX92MhsWk5Gjn9dO/Hq4
EZ1pMJ8hFdrOXoEHlvhnZSavtoy25ZvEoxJ9XWYPqWCmwdfB3xhT4hoEaIlu5Azf
Fw/QV5oFV8SYgwClQ+fTStxdW7CBKEX55KPUn4FOOXV5TfbLOJj3w/1V2pBTKn2f
2safgWyIpNw7OyvYVICdW5/NvD+VTBp+4PfWkTfRD5LEAxqvaGXupBaI2qGYVibJ
WQ77yy6bOvcJh4heqtIJuYg5F3vhvSGo4i5Bkx+daRKFzFwsoiexgRNTdlPCEGsQ
15WBlk3X/9bt
-----END CERTIFICATE-----
"""


@testenv
def badtls(accept, host, port, description):
    with tmpfiles(BADTLS_CA_DATA) as cafile:
        yield Test(
            accept=accept,
            description=description,
            host=host,
            port=port,
            cafile=cafile
        )


@testenv
def badssl(accept, name, description, forced_result=None):
    yield Test(
        accept=accept,
        description=description,
        host=name + ".badssl.com",
        port=443,
        forced_result=forced_result
    )


@testenv
def badssl_onlymyca(description):
    _, _, cadata = gencert("localhost")

    with tmpfiles(cadata) as cafile:
        yield Test(
            accept=False,
            description=description,
            host="sha256.badssl.com",
            port=443,
            cafile=cafile
        )


@testenv
def ssllabs(accept, port, description):
    yield Test(
        accept=accept,
        description=description,
        host="www.ssllabs.com",
        port=port
    )


@contextlib.contextmanager
def http_server(ssl_context, host="localhost", port=0):
    class Timeout(Exception):
        pass

    class Server(HTTPServer):
        ALLOWED_EXCEPTIONS = (socket.error,)

        def handle_timeout(self):
            raise Timeout()

        def handle_error(self, request, client_address):
            exc_type, _, _ = sys.exc_info()
            if isinstance(exc_type, type) and issubclass(exc_type, self.ALLOWED_EXCEPTIONS):
                return
            HTTPServer.handle_error(self, request, client_address)

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            self.request = ssl_context.wrap_socket(self.request, server_side=True)
            return BaseHTTPRequestHandler.setup(self)

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "0")
            self.end_headers()

        def log_message(self, format, *args):
            pass

    def serve(server, done):
        while not done.is_set():
            try:
                server.handle_request()
            except Timeout:
                continue
            break

    server = Server((host, port), Handler)
    try:
        server.timeout = 0.1

        done = threading.Event()
        thread = threading.Thread(target=serve, args=[server, done])
        thread.start()
        try:
            yield host, server.server_port
        finally:
            done.set()
            thread.join()
    finally:
        server.server_close()


@testenv
def local(accept, cn, description):
    certdata, keydata, cadata = gencert(cn)

    with tmpfiles(certdata, keydata, cadata) as (certfile, keyfile, cafile):
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.load_cert_chain(certfile, keyfile)

        with http_server(context) as (host, port):
            yield Test(
                accept=accept,
                description=description,
                host=host,
                port=port,
                cafile=cafile,
                name="{}:<temp port>".format(host)
            )


@testenv
def local_cipher_suites(accept, suites, note=None):
    description = "obsolete {} cipher suites".format(suites)
    if note:
        description += " ({})".format(note)

    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    try:
        context.set_ciphers(suites)
    except ssl.SSLError:
        yield Test(
            accept=accept,
            description=description,
            host="localhost",
            port=0,
            forced_result=results.Skip("TryTLS does not support {} cipher suites".format(suites))
        )
        return

    certdata, keydata, cadata = gencert("localhost")
    with tmpfiles(certdata, keydata, cadata) as (certfile, keyfile, cafile):
        context.load_cert_chain(certfile, keyfile)

        with http_server(context) as (host, port):
            yield Test(
                accept=accept,
                description=description,
                host=host,
                port=port,
                cafile=cafile
            )


@testgroup
def badssl_tests():
    forced_result = None

    res = yield Test(
        accept=True,
        description="support for TLS server name indication (SNI)",
        host="badssl.com",
        port=443
    )
    if res.type != results.Pass:
        forced_result = results.Skip("could not detect SNI support")

    res = yield Test(
        accept=False,
        description="self-signed certificate",
        host="self-signed.badssl.com",
        port=443,
        forced_result=forced_result
    )
    if res.type != results.Pass and not forced_result:
        forced_result = results.Skip("stub didn't reject a self-signed certificate")

    yield testgroup(
        badssl(False, "expired", "expired certificate", forced_result),
        badssl(False, "wrong.host", "wrong hostname in certificate", forced_result),
        badssl(True, "sha256", "SHA-256 signature algorithm", forced_result),
        badssl(True, "1000-sans", "certificate with 1000 different Subject Alternative Names", forced_result),
        badssl(False, "incomplete-chain", "incomplete chain of trust", forced_result),
        badssl(False, "superfish", "Superfish CA", forced_result),
        badssl(False, "edellroot", "eDellRoot CA", forced_result),
        badssl(False, "dsdtestprovider", "DSDTestProvider CA", forced_result),
        badssl(False, "untrusted-root", "untrusted root certificate", forced_result),
        badssl(False, "rc4", "denies use of RC4 ciphers (RFC 7465)", forced_result),
        badssl(False, "rc4-md5", "denies use of RC4 with MD5 ciphers", forced_result),
        badssl(False, "null", "denies use of null cipher", forced_result),
        badssl(False, "dh480", "denies use of 480 bit Diffie-Hellman (DH)", forced_result),
        badssl(False, "dh512", "denies use of 512 bit Diffie-Hellman (DH)", forced_result)
    )


ssllabs_tests = testgroup(
    ssllabs(False, 10443, "protect against Apple's TLS vulnerability CVE-2014-1266"),
    ssllabs(False, 10444, "protect against the FREAK attack"),
    ssllabs(False, 10445, "protect against the Logjam attack")
)

badtls_tests = testgroup(
    badtls(True, "domain-match.badtls.io", 10000, "valid certificate Common Name"),
    badtls(True, "wildcard-match.badtls.io", 10001, "valid wildcard certificate Common Name"),
    badtls(True, "san-match.badtls.io", 10002, "support for Subject Alternative Name (SAN)"),
    badtls(True, "dh1024.badtls.io", 10005, "TLS handshake with 1024 bit Diffie-Hellman (DH)"),
    badtls(False, "expired-1963.badtls.io", 11000, "certificate expired in year 1963"),
    badtls(False, "future.badtls.io", 11001, "certificate validity starts in future"),
    badtls(False, "domain-mismatch.badtls.io", 11002, "mismatch in certificate's Common Name"),
    badtls(False, "san-mismatch.badtls.io", 11003, "Subject Alternative Name (SAN) mismatch"),
    badtls(False, "bad-key-usage.badtls.io", 11005, "certificate has invalid key usage for HTTPS connection"),
    badtls(False, "expired.badtls.io", 11006, "expired certificate"),
    badtls(False, "wildcard.mismatch.badtls.io", 11007, "invalid wildcard certificate Common Name"),
    badtls(False, "rc4.badtls.io", 11008, "denies use of RC4 ciphers (RFC 7465)"),
    badtls(False, "weak-sig.badtls.io", 11004, "denies use of MD5 signature algorithm (RFC 6151)"),
    badtls(False, "rc4-md5.badtls.io", 11009, "denies use of RC4 with MD5 ciphers")
)

local_tests = testgroup(
    local(True, "localhost", "valid localhost certificate"),
    local(False, "nothing", "invalid localhost certificate"),
    badssl_onlymyca("use only the given CA bundle, not system's"),
    local_cipher_suites(False, "NULL"),
    local_cipher_suites(False, "EXPORT"),
    local_cipher_suites(False, "DES"),
    local_cipher_suites(False, "3DES", "vulnerable to Sweet32")
)

all_tests = testgroup(
    ssllabs_tests,
    badssl_tests,
    badtls_tests,
    local_tests
)
