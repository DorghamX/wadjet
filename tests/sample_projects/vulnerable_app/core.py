"""Deliberately vulnerable sample for the Wadjet end-to-end check (T2.7).

Every construct here is a known Bandit finding; ``expected_findings.json``
lists the issues the agent must produce. Do not "fix" this file - it exists
to break the gate.
"""

import hashlib
import pickle
import random
import subprocess


def check_positive(value):
    assert value > 0
    return value


def run_command(command):
    subprocess.run(command, shell=True)


def load_payload(data):
    return pickle.loads(data)


def weak_digest(data):
    return hashlib.md5(data)


def random_token():
    return random.random()


def read_password():
    password = "hunter2"
    return password
