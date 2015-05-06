# vim: set fileencoding=utf-8 :
"""Test auth_yubico.py"""

from __future__ import (division, absolute_import, print_function,
                        unicode_literals)

from nose.tools import raises

from auth_yubico import *


def initial_test():
    pass


@raises(NginxAuthYubicoError)
def test_bad_get_yubikey_id():
    __ = get_yubikey_id('foo')


def test_good_get_yubikey_id():
    ykid = get_yubikey_id('cccccccckhtunvveujbhcljnjccjknvhdduclbkkuubc')
    assert ykid == 'cccccccckhtu'
