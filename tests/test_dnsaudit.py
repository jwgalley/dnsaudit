#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_dnsaudit
----------------------------------

Tests for `dnsaudit` module.
"""

import unittest

import dnsaudit


class TestDnsaudit(unittest.TestCase):

    def setUp(self):
        pass

    def test_something(self):
        assert(dnsaudit.__version__)

    def tearDown(self):
        pass
