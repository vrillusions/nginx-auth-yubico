#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tornado app that handles ngx_http_auth_request."""
from __future__ import (division, absolute_import, print_function,
                        unicode_literals)
import os
import base64
import logging
import cPickle as pickle
import time

from tornado.ioloop import IOLoop
from tornado.web import RequestHandler, Application, url
from tornado.options import (define, options, parse_command_line,
                             parse_config_file)
#from tornado import gen
from yubico_client import Yubico
from yubico_client.yubico_exceptions import YubicoError


__version__ = '0.1.0-dev'


class NginxAuthYubicoError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


def get_yubikey_id(otp):
    """Verify the OTP is in the correct format and return id.

    :param string otp: the one time password from yubikey
    :return: 11 character yubikey id

    """
    # TODO:2014-10-06:teddy: verify the string only contains modhex
    if len(otp) != 44:
        raise NginxAuthYubicoError("not a valid yubikey otp")
    yubikey_id = otp[:12]
    return yubikey_id


# src (with some tweaks):
# http://kevinsayscode.tumblr.com/post/7362319243/easy-basic-http-authentication-with-tornado
def require_basic_auth(handler_class):
    def wrap_execute(handler_execute):
        def require_basic_auth(handler, kwargs):
            auth_header = handler.request.headers.get('Authorization')
            if auth_header is None or not auth_header.startswith('Basic '):
                logging.info("Did not receive an authorization header")
                handler.set_status(401)
                handler.set_header('WWW-Authenticate', 'Basic realm=Restricted')
                handler._transforms = []
                handler.finish()
                return False
            auth_decoded = base64.decodestring(auth_header[6:])
            kwargs['basicauth_user'], kwargs['basicauth_pass'] = auth_decoded.split(':', 2)
            return True

        def _execute(self, transforms, *args, **kwargs):
            if not require_basic_auth(self, kwargs):
                return False
            return handler_execute(self, transforms, *args, **kwargs)
        return _execute
    handler_class._execute = wrap_execute(handler_class._execute)
    return handler_class


class BaseRequestHandler(RequestHandler):
    def prepare(self):
        self.yubico = Yubico(options.yubico_api_id, options.yubico_api_key)

    def get(self, **kwargs):
        raise NotImplementedError()

    def response_invalid_login(self):
        self.set_status(401)
        self.set_header('WWW-Authenticate', 'Basic realm=Restricted')
        self._transforms = []
        self.finish()

    def set_session_cookie(self, cookie_name=None):
        """Set the session cookies."""
        # Note that secure cookie implements it's own timestamp checking but
        # does so by days. check yubicoauth date so we can be more specific
        if not cookie_name:
            cookie_name = options.session_cookie_name
        cookiedata = {
            "nonce": base64.b64encode(os.urandom(12)),
            "timestamp": time.time()
            }
        self.set_secure_cookie(cookie_name, pickle.dumps(cookiedata))

    def get_session_cookie(self, cookie_name=None):
        """Get the cookie data if exists.

        Typically depickling a cookie received from client is a bad idea. This
        is a special case as get_secure_cookie() contains a HMAC that is
        verified before returning anything.

        :return: Returns the contents of session cookie in whatever type it was
            when saved (ie dictionary)

        """
        if not cookie_name:
            cookie_name = options.session_cookie_name
        if not self.get_secure_cookie(cookie_name):
            return None
        else:
            return pickle.loads(self.get_secure_cookie(cookie_name))

    def clear_session_cookie(self, cookie_name=None):
        """Clear session cookie

        While there is an existing clear_cookie() it doesn't seem to work so
        instead set it to blank value
        """
        if not cookie_name:
            cookie_name = options.session_cookie_name
        self.set_secure_cookie(cookie_name, pickle.dumps({}))

    def verify_yubikey(self, yubikey_otp):
        """Verify a given OTP is valid."""
        yubikey_id = get_yubikey_id(yubikey_otp)
        if yubikey_id not in options.yubikeys:
            logging.info(
                "yubikey id not specified in auth_yubico options: %s"
                % yubikey_id)
            result = False
        else:
            try:
                result = self.yubico.verify(yubikey_otp)
            except YubicoError as exc:
                logging.error("YubicoError: %s" % exc)
                result = False
            else:
                self.set_header("X-Yubikey-Id", yubikey_id)
        return result

    def verify_session_cookie(self):
        session_cookie = self.get_session_cookie()
        if session_cookie:
            if 'timestamp' in session_cookie:
                timedelta = time.time() - session_cookie['timestamp']
                if timedelta < options.session_timeout:
                    logging.info("Previously logged in, not checking again")
                    result = True
                else:
                    logging.info("expired session (age: %f)" % timedelta)
            else:
                logging.warn("session cookie missing timestamp param")
                result = False
        else:
            result = False
        return result

    def authenticate(self, username, password):
        """Do actual authentication."""
        logging.info("authenticate: user=%s password=HIDDEN" % username)
        # This was used to test thread concurrency
        #time.sleep(5)
        auth_ok = None
        if self.verify_session_cookie():
            auth_ok = True
        elif self.verify_yubikey(password):
            auth_ok = True
        if auth_ok:
            logging.info("successful authentication, setting session cookie")
            self.set_session_cookie()
        else:
            logging.info("unsuccessful authentication, send back to login")
            self.response_invalid_login()
        return auth_ok


@require_basic_auth
class MainHandler(BaseRequestHandler):
    def get(self, basicauth_user, basicauth_pass):
        try:
            auth = self.authenticate(basicauth_user, basicauth_pass)
        except NginxAuthYubicoError as exc:
            logging.error(exc)
            self.response_invalid_login()
        else:
            if auth:
                self.write("OK")


def make_app():
    return Application([
        url(r"/", MainHandler),
        ], **options.group_dict("application"))


if __name__ == "__main__":
    define(
        "config", type=str, help="path to config file", metavar="PATH",
        callback=lambda path: parse_config_file(path, final=False))
    define(
        "cookie_secret", type=str, group="application",
        help="secret used for secure cookies")
    define(
        "debug", default=False, group="application", help="enable debug mode")
    define("listen_address", default=b"127.0.0.1", help="listen address")
    define("listen_port", default=5000, help="listen port")
    define(
        "session_cookie_name", default=b"authyubico_sess",
        help="name of session cookie")
    define(
        "session_timeout", default=3600,
        help="expire authentication after this many seconds of inactivity")
    define(
        "yubikeys", multiple=True,
        help="comma-sepparated list of yubikey ids that are allowed")
    define(
        "yubico_api_id", default=b"0",
        help="api id for yubico.com auth service")
    define(
        "yubico_api_key", default=b"0",
        help="api key for yubico.com auth service")
    parse_command_line()
    logging.getLogger('requests').setLevel(logging.ERROR)
    app = make_app()
    app.listen(address=options.listen_address, port=options.listen_port, xheaders=True)
    logging.info('Starting server on %s:%s' % (
        options.listen_address, options.listen_port))
    IOLoop.current().start()
