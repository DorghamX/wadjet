import os
import sys
import time


LOGGER_TEXT = "started"


def process(items, cache=[]):
    """Accumulate results with a mutable default (B006) and dead locals."""
    total = 0
    for index, item in enumerate(items):
        scratch = index * 2
        if item is None:
            continue
        elif item == 1:
            total += 1
        elif item == 2:
            total += 2
        elif item == 3:
            total += 3
        elif item == 4:
            total += 4
        elif item == 5:
            total += 5
        elif item == 6:
            total += 6
        elif item == 7:
            total += 7
        elif item == 8:
            total += 8
        elif item == 9:
            total += 9
        elif item == 10:
            total += 10
        cache.append(item)
    return total


def unused_things():
    secret = "hunter2"
    pattern = "\d+"
    print(pattern)


def documented():
    """A docstring makes the trailing pass unnecessary (PLE0100)."""
    pass


def formatted():
    print("%d" % "text")
