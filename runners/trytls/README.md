# trytls runner

## Quick Start

```
$ trytls https -- python stubs/python-urllib2/run.py
```

## Detailed Usage

The `trytls` tool is a *runner*, meant for testing how well different libraries implement their TLS certificate verification. This is done by feeding the libraries collections of pre-canned certificates and observing their output. The basic usage pattern of the tool is the following:

```
trytls BUNDLE -- COMMAND [ARG ...]
```

The first command line parameter `BUNDLE` is used to tell which test *bundle* should be run. A bundle is a collection of TLS tests specialized for some protocol/situation. Launching the runner without any arguments lists the available bundles:

```
$ trytls
usage: trytls BUNDLE -- COMMAND [ARG ...]
trytls: error: missing the bundle argument

Valid bundle options:
  https
  imap
```

For example, when testing a HTTP(S) library you'd want to use the `https` bundle. That specific bundle knows to answer to the library's requests with proper HTTP responses, making testing easier.

The parameters following the bundle are `COMMAND` and 0-n `ARG` arguments for the command. These describe how the *stub* - a piece of code for testing some library - should be launched. The [`stubs/`](../stubs) directory in this repository contains multiple example stubs. As an example the included stub for testing Python's `urllib2` library can be run with:

```
$ trytls https -- python stubs/python-urllib2/run.py
  PASS badssl(False, 'expired')
  PASS badssl(False, 'wrong.host')
  ...
```

That runs the command `python stubs/python-urllib2/run.py HOST PORT [CAFILE]` several times with different `HOST`, `PORT` and optional `CAFILE` arguments to test out various aspects of `urllib2`'s TLS certificate verification. For more information on writing stubs please refer to the relevant documentation. Bundle and command should be separated with `--` so that any following parameters are passed to *stub* itself and not handled by `trytls` command.

## Exit codes

The runner exits with a non-zero exit code when there is at least one `FAIL` or `ERROR` result. This feature is useful e.g. when using `trytls` as a part of a Continuous Integration setup.

The specific exit code in such situations is 3, to distinguish it from other common situations: The CPython interpreter exits with 1 when an unhandled exception occurs, and with 2 when there is a problem with a command line parameter (see Py_Main which CPython's main uses in versions 2.7 and 3.5). The argparse module also uses the code 2 for the same purpose.

## Bundles

A test bundle is a collection of tests specialized for some protocol/situation ("an HTTPS server", "an IMAP server", ...). In practice a test bundle is just a named list of tests to be run. As an example see [`bundles/https.py`](./bundles/https.py).

The bundles are registered as `setuptools` entrypoints.

## Technical Tidbits

### On-the-fly Certificate Generation

Function `trytls.gencert.gencert(cn="...")` can be used for generating a PEM encoded server certificate + private key pair and a PEM ca bundle against which the server certificate verifies. The function basically just wraps the `openssl` command and generates a server certificate for the given Common Name. To save time the private server key and the private CA key are generated once per process.

As an example you can generate `cert.pem`, `cert.key` and `ca.pem` like this:
  ```python
from trytls.gencert import gencert


def writefile(filename, data):
    with open(filename, "wb") as f:
        f.write(data)


cert, key, ca = gencert("localhost")
writefile("cert.pem", cert)
writefile("cert.key", key)
writefile("ca.pem", ca)
```
Now launching a HTTP server on localhost with the `cert.pem` and `cert.key` files allows clients to create a verified connection to it using the `ca.pem` CA file.
