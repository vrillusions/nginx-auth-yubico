# vim:fileencoding=utf-8
from __future__ import absolute_import, print_function, unicode_literals
import os
import hashlib
from contextlib import contextmanager
from random import SystemRandom
from base64 import b64encode

from fabric.api import env, task, local, lcd


env.colorize_errors = True
#env.use_ssh_config = True


# wrap in another dirname() if using a fabfile module directory
BASE_DIR = os.path.dirname(__file__)


# Context manager to change to base directory
@contextmanager
def local_basedir():
    """Run commands relative to base directory."""
    with lcd(BASE_DIR):
        yield


@task
def test():
    """runs through all tests"""
    with local_basedir():
        local("flake8")
        local("nosetests")


@task
def coverage():
    """run coverage report on just our project"""
    with local_basedir():
        local("nosetests --with-coverage --cover-package=auth_yubico")


@task
def clean():
    """cleans .pyc and other temporary files."""
    with local_basedir():
        local('find . -name "*.pyc" -delete')


@task
def secret():
    """generate a random value that can be used for cookie_secret."""
    randbits = SystemRandom().getrandbits(512)
    secret = b64encode(hashlib.sha384(str(randbits)).digest())
    print(secret)


@task
def upgrade_packages():
    """check for updates on local packages (requires pip-tools)"""
    with local_basedir():
        local('pip-review --auto')
    print('Remember to update requirements.txt file')
