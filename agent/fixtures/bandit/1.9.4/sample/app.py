"""Sample module with deliberate Bandit findings for the recorded fixture."""

import hashlib
import pickle
import random
import subprocess


def check(value):
    assert value > 0
    return value


def run(command):
    subprocess.run(command, shell=True)


def load(data):
    return pickle.loads(data)


def digest(data):
    return hashlib.md5(data)


def token():
    return random.random()


def connect():
    password = "hunter2"
    return password
