#!/usr/bin/env python2

from apscheduler.schedulers.background import BackgroundScheduler
from .main import dns_query, pretty_log
from time import sleep
import itertools


class heartbeat():

    def __init__(self, config):
        self.configuration = config
        self.config_nameservers = self.configuration['nameservers']['default']
        self.nameservers = itertools.cycle([])

    def nameserver_check(self):
        serverlist = self.configuration['nameservers']['default']
        for server in serverlist:
            check = dns_query(self.configuration['heartbeat']['default']['record'],
                              self.configuration['heartbeat']['default']['type'],
                              server)
            if check:
                pretty_log("[Heartbeat]     %s    [ OK ]" % server)
                self.config_nameservers.append(server)
            else:
                pretty_log("[Heartbeat]     %s    [ ERROR ]" % server)
        self.nameservers = itertools.cycle(self.config_nameservers)
        return True


def nameserver_check_scheduler(heartbeat_obj):
    sched = BackgroundScheduler()
    sched.add_job(heartbeat_obj.nameserver_check,
                  'interval',
                  seconds=int(heartbeat_obj.configuration['heartbeat']['default']['interval']))
    sched.start()

    retries_check = int(heartbeat_obj.configuration['heartbeat']['default']['init_retries'])
    retry_wait = int(10)

    while(retries_check != 0):
        try:
            heartbeat_obj.nameservers.next()
        except StopIteration:
            pretty_log("Heartbeat scheduler not initialized yet... Will retry %s times..." % retries_check)
            pretty_log("Will retry in %s seconds" % retry_wait)
            retries_check -= 1
            sleep(retry_wait)
        else:
            pretty_log("Heartbeat scheduler initalized...")
            return True
    else:
        pretty_log("Heartbeat scheduler error!")
        return False