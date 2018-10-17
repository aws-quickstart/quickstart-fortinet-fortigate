#!/usr/bin/env python

import threading
import functools
import os
from threading import Timer


__author__ = 'mwooten'

class Monitor(object):

    def __init__(self, interval, callback, daemon=True, **kwargs):
        self.interval = interval
        self.callback_function = None
        self.daemon = daemon
        self.fgt = kwargs['kwargs']
        self.fgt.monitor_thread = self
        self.callback_function = callback

    def run(self):
        self.callback_function (self.fgt)
        self.t = Timer(self.interval, self.run)
        self.daemon = self.daemon
        self.t.start()

    def cancel(self):
        self.t.cancel()