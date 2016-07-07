# TryTLS

TryTLS verifies the certificate verification behavior of programming languages and libraries. TryTLS exists because
broken certificate checks seems to be an overlooked issue. Handling certificates is surprisingly complex, and calls for extra attention. Few basic tests are just not enough.

TryTLS is a tool for the:
 * software and library developers,
 * vulnerability researchers, and
 * software end-users, who are interested about the security of the implementation.

 They use TryTLS because it handles solves the following problems for them:

  * *What should be tested?*
    * TryTLS ships with bundle of readily planned tests
    * Ofcourse we are always interested in feedback/contributions <fixme link> in that front as well!
  * *Against what I will run the tests?*
    * Backends come and go. For example BadSSL is great today, it may disappear any given day
  * *How do I set up my tests?*
   * TryTLS runner just requires you to write a stub to run the test. Everything else is handled by TryTLS.
   

We invite people to contribute. Right now we are working hard to make it as simple as possible for you, see our work-in-progress [HOWTO](CONTRIBUTING.md).

---

## What

 * Check the behavior of a software library - does it properly check the certificates?
 * Test the TLS client code, do not address possible client certificate check problems in server code
 * Test against specialized backends, do not require a man in the middle setup
 * Drive the tests with code, do not worry about smart TVs, IoT toasters and other such devices

---

## How

 * "Checking of checks" -> how libraries handle signatures, domain names, time, SNI etc.
 * Use ports and virtual hosts to provide falsified/broken certificate checks
 * Provide both end results and the source material used to get those results -> enable reproduction
 * Open public project created with scalability in mind -> anyone can contibute
 * Document use cases -> ease of access
 * Utilize docker -> encapsulate dependencies for the examples and the backends
 * Support multiple backends -> use hosted backends or run your own on the host or in the cloud

---

## Architecture

![Architecture](https://raw.githubusercontent.com/ouspg/trytls/master/doc/architecture-scaled.jpg)

---

## Stubs

Example code (stubs) using TLS in different languages and libraries live in
the [stubs/](stubs/) directory. You can contribute your stub here or just BYOR (Bring Your Own Repository).

These stubs should attempt to use the chosen language and library
properly to establish a secure TLS connection to the given destination.

---

### Calling convention

All stubs should have a standalone program that takes up to three command
line arguments (`<host> <port> [ca-bundle]`):

 * `<host>` is the DNS name or IP-address of the service to connect to
 * `<port>` is the port to connect to
 * `[ca-bundle]` is optional location of the CA certificate bundle to be used
 instead of the built-in default

---

### Return values

Stubs should attempt to establish a **secure** connection to the given
service and catch possible errors and exceptions to determine if it was successful.

All stubs should return one of the following strings to the standard output:

 * `VERIFY SUCCESS` when connection was established in a secure way
 * `VERIFY FAILURE` when connection failed to establish in a secure way
 * `UNSUPPORTED` if the example has not implemented the requested behaviour (e.g. setting
   CA certificate bundle)

If anything else is returned, then the test has erred.

Unless a fatal error occurs, examples should always return with process exit value 0.

---

### Packaging

A stub should be confined to a directory named in a way that describes the
chosen target language and library or service: in stubs/language-library/,  
named as `run` / `Run` with the appropriate file extension (run.lua, run.py etc.)

A stub should have a top level `README.md` that describes how to run the example. The stubs should have a `run` command.

Optionally a stub can have a `Dockerfile` that encapsulates the environment
and the dependancies needed to run the example.

---

## Test runners

We currently have one [python based test runner](showrunner/) implemented.

Installation:

```console
$ python setup.py install --user
```

Example usage:

```console
$ ~/.local/bin/trytls python3 stubs/python3-urllib/run.py
PASS badssl(True, 'sha1-2016')
PASS badssl(False, 'expired')
...
```

We have also one [bash based test runner](runners/bashtls/data/shared/simplerunner) [WIP]

---

## Backends

We currently are working to support following backends implementing the tests:

 * Local backend in the test runner itself (aka `localhost` backend) [WIP]
 * [Trytls backend](backends/trytls) both as docker based "run-it-yourself" packaging and as a
 hosted service provided by us [WIP]
 * [BadSSL](https://badssl.com)

Test runners should should allow user to test against all or any of these backends.

---

## Found issues

 * [Wreq connection to HTTPS site with invalid hostname · Issue #84 · bos/wreq GitHub](https://github.com/bos/wreq/issues/84)
  * See also [Is Wreq suitable for HTTPS applications? · Issue #82 · bos/wreq · GitHub](https://github.com/bos/wreq/issues/82)

## TryTLS Team

 * Mauri Miettinen ([@Mamietti](https://github.com/Mamietti))
 * Aleksi Klasila ([@aleksiklasila](https://github.com/aleksiklasila))
