# TryTLS shootouts

**goto** ([0.3](#shootout-03) | [**0.2**](#shootout-02))

---

## Shootout 0.3

We ran the TryTLS tests against the same target OS distributions and
languages as in the previous shootout, but used newer versions of
both the stubs and the runner. We used Docker for repeatibility
and ease of reproduction.

Our main observations were:

* OS distributions have issues with their Python version policies. Proper
  certificate checks are either not back ported from the fixed Python
  versions or changes have to be made either to the configuration or
  the code that works in safe manner in up to date environments. This
  is a hazard where neither software developers or users
  realize that code that works well for the developer may be
  unsafe for the user using different OS distribution than
  the developer. In a nutshell, there are many cases where the
  python based software may fail to check certificates in
  OS distributions currently still in wide use.

* Support of RC4 and MD5 is the in Python stubs is the most common
  crypto weakness identified in this shootout.

* Python versions and back ports vary wildly between the OS distributions.
  This leads to a lot of variation in how python based software behaves
  with TLS.

* Conflicting results where go stub accepts one SNI test but declines
  another in Ubuntu 14.04 requires further investigation
  (see [#239](https://github.com/ouspg/trytls/issues/239)).

* After previous shootout we
  [contacted Python developers](https://mail.python.org/pipermail/python-dev/2016-August/145815.html).
  TLS certificate verification failures in some OS distributions is a known
  problem to them. Some distributions have chosen not to enable this by default
  for backward compatibility. In some cases administrators have the possibility
  to add support per-case. More information can be found from our
  [discussion tracking](/doc/discussion-tracking.md#python-dev).
  Next we will try to reach out to the OS distribution maintainers for
  clarifications and further pointers.

We split up the results to study the state of Server Name indication
(SNI) support, proper certificate checks and crypto weaknesses
separately. Summarized results are in the
tables below. Detailed results are available in the subdirectories.

### Shootout 0.3 - SNI support results

<!-- markdownlint-disable MD013 -->

| OS                             | python2-requests | python2-urllib2 | python3-urllib | go-nethttp   | java-https | java-net | php-file-get-contents  |
|------------------------------- | ---------------- | --------------- | -------------- | ------------ | ---------- | -------- | ---------------------- |
|[Alpine 3.1](alpine-3.1)        | YES              | YES             | N/A            | YES          | NO         | NO       | NO                     |
|[Alpine Edge](alpine-edge)      | YES              | YES             | YES            | YES          | YES        | YES      | NO                     |
|[CentOS 5.11](centos5)          | N/A              | N/A             | N/A            | N/A          | N/A        | N/A      | NO                     |
|[CentOS 6.8](centos6)           | NO               | N/A             | YES            | YES          | YES        | YES      | NO                     |
|[CentOS 7.2](centos7)           | YES              | YES             | YES            | YES          | YES        | YES      | NO                     |
|[Debian 7.11](debian-7)         | NO               | N/A             | YES            | NO           | YES        | YES      | NO                     |
|[Debian 8.5](debian-8)          | YES              | YES             | YES            | YES          | YES        | YES      | YES                    |
|[Fedora 24](fedora24)           | YES              | YES             | YES            | YES          | YES        | YES      | YES                    |
|[Ubuntu 12.04.5](ubuntu-12.04)  | N/A              | N/A             | YES            | N/A          | N/A        | N/A      | NO                     |
|[Ubuntu 14.04.5](ubuntu-14.04)  | NO               | N/A             | YES            | N/A          | YES        | YES      | NO                     |
|[Ubuntu 16.04.1](ubuntu-16.04)  | YES              | YES             | YES            | YES          | YES        | YES      | YES                    |

<!-- markdownlint-enable MD013 -->

Legend:

* YES: SNI supported
* NO: SNI not supported
* N/A: test subject was not available in target distribution, or stub behavior
  requires investigation

## Shootout 0.3 - certificate check results

Failures to check certificates are noted in the table.
Considerably less tests were performed in cases where SNI support or
CA support were not available.

<!-- markdownlint-disable MD013 -->

| OS                             | python2-requests | python2-urllib2 | python3-urllib | go-nethttp   | java-https | java-net | php-file-get-contents  |
|------------------------------- | ---------------- | --------------- | -------------- | ------------ | ---------- | -------- | ---------------------- |
|[Alpine 3.1](alpine-3.1)        | PASS             | PASS            | N/A            | PASS         | PASS       | PASS     | PASS                   |
|[Alpine Edge](alpine-edge)      | PASS             | PASS            | PASS           | PASS         | PASS       | PASS     | PASS                   |
|[CentOS 5.11](centos5)          | N/A              | N/A             | N/A            | N/A          | N/A        | N/A      | PASS                   |
|[CentOS 6.8](centos6)           | PASS             | N/A             | PASS           | PASS         | PASS       | PASS     | PASS                   |
|[CentOS 7.2](centos7)           | PASS             | FAIL            | PASS           | PASS         | PASS       | PASS     | PASS                   |
|[Debian 7.11](debian-7)         | PASS             | N/A             | FAIL           | PASS         | PASS       | PASS     | PASS                   |
|[Debian 8.5](debian-8)          | PASS             | PASS            | FAIL           | PASS         | PASS       | PASS     | PASS                   |
|[Fedora 24](fedora24)           | PASS             | PASS            | PASS           | PASS         | PASS       | PASS     | PASS                   |
|[Ubuntu 12.04.5](ubuntu-12.04)  | N/A              | N/A             | FAIL           | N/A          | N/A        | N/A      | PASS                   |
|[Ubuntu 14.04.5](ubuntu-14.04)  | PASS             | N/A             | FAIL           | N/A          | PASS       | PASS     | PASS                   |
|[Ubuntu 16.04.1](ubuntu-16.04)  | PASS             | PASS            | PASS           | PASS         | PASS       | PASS     | PASS                   |

<!-- markdownlint-enable MD013 -->

Legend:

* PASS: Certificates are checked properly, this is safe
* FAIL: Certificates are NOT checked properly, this is NOT safe
* N/A: test subject was not available in target distribution, or stub behavior
  requires investigation

## Shootout 0.3 - crypto weakness results

Potential crypto weakness identified by the tests are listed below. Abbreviations
can be mapped to the original tests from the results in the subdirectories.
Considerably less tests were performed in cases where SNI support or
CA support were not available.

<!-- markdownlint-disable MD013 -->

| OS                             | python2-requests  | python2-urllib2 | python3-urllib            | go-nethttp   | java-https | java-net | php-file-get-contents  |
|------------------------------- | ----------------- | --------------- | ------------------------- | ------------ | ---------- | -------- | ---------------------- |
|[Alpine 3.1](alpine-3.1)        | MD5               | MD5             | N/A                       |              |            |          |                        |
|[Alpine Edge](alpine-edge)      | MD5               | MD5             | MD5                       |              |            |          |                        |
|[CentOS 5.11](centos5)          | N/A               | N/A             | N/A                       | N/A          | N/A        | N/A      |                        |
|[CentOS 6.8](centos6)           | RC4, MD5, RC4+MD5 | N/A             | RC4, MD5                  |              |            |          |                        |
|[CentOS 7.2](centos7)           | RC4               | POODLE, RC4     |                           |              |            |          |                        |
|[Debian 7.11](debian-7)         | RC4, MD5, RC4+MD5 | N/A             | POODLE, RC4, MD5, RC4+MD5 |              |            |          |                        |
|[Debian 8.5](debian-8)          | MD5               | RC4, MD5        | RC4, MD5                  |              |            |          |                        |
|[Fedora 24](fedora24)           |                   |                 |                           |              |            |          |                        |
|[Ubuntu 12.04.5](ubuntu-12.04)  | N/A               | N/A             | POODLE                    | N/A          | N/A        | N/A      |                        |
|[Ubuntu 14.04.5](ubuntu-14.04)  | RC4, MD5, RC4+MD5 | N/A             | RC4, MD5                  | N/A          |            |          |                        |
|[Ubuntu 16.04.1](ubuntu-16.04)  | MD5               | MD5             | MD5                       |              |            |          |                        |

<!-- markdownlint-enable MD013 -->

Legend:

* _text_: Crypto weakness warnings detected
* _empty_: No warnings about crypto weaknesses detected
* N/A: test subject was not available in target distribution, or stub behavior
  requires investigation

## Shootout 0.2

We ran TryTLS tests on major and still supported distributions.
For this shootout we limited ourselves to the official Docker images
of the distributions. Our objective was to check that the bundled
languages and libraries are safe to use with TLS. TryTLS focuses
on making sure that the certificates are checked properly.

Our main observattions were:

* The same Python code produced different results in different distributions.
  Due to this, we should reach out Python gurus, are we doing something wrong
  or is running apparently correct Python code in some major distributions
  actually dangerous.

* Java stubs had issues we need to investigate and possibly fix before next
  shootout. Due to this, some Java results are not available.

* We were surprised to see the lack of SNI support in many of the still
  supported distributions. In next study we might investigate SNI support
  separately to get more directly security related results.

### Results

Detailed results are available in subdirectories. Summarised results are in the
table below.

<!-- markdownlint-disable MD013 -->

| OS                             | python-requests | python-urllib2 | python3-urllib | (python3) python-requests | go-nethttp   | java-https | java-net | php-file-get-contents  |
|------------------------------- | --------------- | -------------- | -------------- | --------------------------| ------------ | ---------- | ---------|------------------------|
|[Alpine 3.1](alpine-3.1)        | PASS            | PASS           | N/A            | N/A                       | PASS         | N/A        | N/A      | NO SNI |
|[Alpine Edge](alpine-edge)      | PASS            | PASS           | PASS           | PASS                      | PASS         | PASS       | PASS     | NO SNI |
|[CentOS 5.11](centos5)          | N/A             | N/A            | N/A            | N/A                       | N/A          | N/A        | N/A      | N/A    |
|[CentOS 6.8](centos6)           | NO SNI          | N/A            | PASS           | N/A                       | PASS         | N/A        | N/A      | NO SNI |
|[CentOS 7.2](centos7)           | PASS            | FAIL           | PASS           | N/A                       | PASS         | N/A        | N/A      | NO SNI |
|[Debian 7.11](debian-7)         | NO SNI          | N/A            | FAIL           | NO SNI                    | N/A          | N/A        | N/A      | NO SNI |
|[Debian 8.5](debian-8)          | PASS            | PASS           | FAIL           | PASS                      | PASS          | N/A        | N/A      | PASS   |
|[Fedora 24](fedora24)           | PASS            | PASS           | N/A            | PASS                      | PASS         | PASS       | PASS     | PASS   |
|[Ubuntu 12.04.5](ubuntu-12.04)  | NO SNI          | N/A            | FAIL           | N/A                       | NO SNI       | N/A        | N/A      | NO SNI |
|[Ubuntu 14.04.5](ubuntu-14.04)  | NO SNI          | N/A            | FAIL           | N/A                       | NO SNI       | N/A        | N/A      | NO SNI |
|[Ubuntu 16.04.1](ubuntu-16.04)  | PASS            | PASS           | PASS           | N/A                       | PASS         | PASS       | PASS     | PASS   |

<!-- markdownlint-enable MD013 -->

Legend:

* PASS: None of the verdicts belong to any of the other categories
* FAIL: One or more tests failed, e.g. the implementation acted against
  expectation. For example the library establishes connection, even though
   it should not.
* NO SNI: SNI not supported
* N/A: test subject was not available in target distribution, or stub behavior
  requires investigation

---
