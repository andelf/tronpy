.. TronPy documentation master file, created by
   sphinx-quickstart on Thu Jun 18 21:00:15 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to TronPy's documentation!
==================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   quickstart.rst
   keys.rst
   client.rst
   trx.rst
   contract.rst
   exceptions.rst


TronPy is an easy-to-use TRON HTTP API client. It supports most of the java-tron 3.7 APIs, and with an experimental 4.0
Shielded TRC20 Contract API support.

.. note::

   This project is under active development. The APIs may change often.

Key principles:

* Never use unsafe API (TronPy always sign offline)
* Always use base58check address (API response, ABI decode/encode, ...)
* Construct transactions offline (more control of ref_block, expiration)

Now, :ref:`click here to start your tour with TronPy <quickstart>`.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
