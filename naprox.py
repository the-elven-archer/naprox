#!/usr/bin/env python2

from twisted.internet import protocol, reactor, threads
from twisted.python import threadable
threadable.init(1)
from threading import Thread

from modules import *
from dnslib import *
import sys

import argparse

parser = argparse.ArgumentParser(description="Authoritative DNS proxy.")
parser.add_argument("-c", help="config file")
args = parser.parse_args()

configuration = load_config(config_file=args.c)
if configuration is False:
    pretty_log("Config file not found... Bye")
    sys.exit(1)


heartbeat = scheduler.heartbeat(configuration)
if not scheduler.nameserver_check_scheduler(heartbeat):
    pretty_log("Heartbeat scheduler not initialized... Bye")
    sys.exit(1)

reactor.suggestThreadPoolSize(32)


class DNSEcho(protocol.DatagramProtocol):

    def requestProcess(self, data, (host, port)):
        request = DNSRecord.parse(data)
        id = request.header.id
        qname = request.q.qname
        qtype = request.q.qtype
        #
        pretty_log("Request (%s): %r (%s)" % (str(host), qname.label, QTYPE[qtype]))
        reply = DNSRecord(DNSHeader(id=id, qr=1, aa=1, ra=0, rd=0), q=request.q)

        backend_query_fetch = dns_query(qname, qtype, heartbeat.nameservers.next())
        while backend_query_fetch.__len__() > 0:
            record = backend_query_fetch.pop(0)
            #####
            # SOA
            #####
            if (qtype == QTYPE.SOA or qtype == QTYPE.ANY) and record['qtype'] == "SOA":
                pretty_log("SOA")
                soa_data = dns_soa_parse(record['content'])
                pretty_log(soa_data)
                reply.add_answer(RR(qname, QTYPE.SOA, ttl=record['ttl'], rdata=SOA(mname=soa_data['ns'],
                                                                                   rname=soa_data['owner'],
                                                                                   times=(soa_data['serial'],
                                                                                          soa_data['refresh'],
                                                                                          soa_data['retry'],
                                                                                          soa_data['expiry'],
                                                                                          soa_data['nxdomain'])
                                                                                   )
                                    )
                                 )
            #####
            # NS
            #####
            if (qtype == QTYPE.NS or qtype == QTYPE.ANY) and record['qtype'] == "NS":
                reply.add_answer(RR(qname,
                                    QTYPE.NS,
                                    ttl=record['ttl'],
                                    rdata=NS(label=record['content'])))
            #####
            # A
            #####
            if (qtype == QTYPE.A or qtype == QTYPE.ANY) and record['qtype'] == "A":
                reply.add_answer(RR(qname,
                                    QTYPE.A,
                                    ttl=record['ttl'],
                                    rdata=A(record['content'])))
            #####
            # CNAME
            #####
            if (qtype == QTYPE.CNAME or qtype == QTYPE.ANY) and record['qtype'] == "CNAME":
                reply.add_answer(RR(qname,
                                    QTYPE.CNAME,
                                    ttl=record['ttl'],
                                    rdata=CNAME(label=record['content'])))
            #####
            # MX
            #####
            if (qtype == QTYPE.MX or qtype == QTYPE.ANY) and record['qtype'] == "MX":
                mx_data = dns_mx_parse(record['content'])
                reply.add_answer(RR(qname,
                                    QTYPE.MX,
                                    ttl=record['ttl'],
                                    rdata=MX(mx_data['mx'],
                                             preference=mx_data['weight'])))
            #####
            # TXT
            ####
            if (qtype == QTYPE.TXT or qtype == QTYPE.ANY) and record['qtype'] == "TXT":
                txt_data = dns_txt_clean(record['content'])
                reply.add_answer(RR(qname,
                                    QTYPE.TXT,
                                    ttl=record['ttl'],
                                    rdata=TXT(txt_data)))
            #####
            # SRV
            #####
            if (qtype == QTYPE.SRV or qtype == QTYPE.ANY) and record['qtype'] == "SRV":
                srv_data = dns_srv_parse(record['content'])
                reply.add_answer(RR(qname,
                                    QTYPE.SRV,
                                    ttl=record['ttl'],
                                    rdata=SRV(priority=srv_data['priority'],
                                              weight=srv_data['weight'],
                                              port=srv_data['port'],
                                              target=srv_data['target'])))

            ############
            # DNSSEC
            ############

            #####
            # RRSIG
            #####
            if (qtype == QTYPE.RRSIG or qtype == QTYPE.ANY) and record['qtype'] == "RRSIG":
                rrsig_data = dns_rrsig_parse(record['content'])
                reply.add_answer(RR(qname,
                                    QTYPE.RRSIG,
                                    ttl=record['ttl'],
                                    rdata=RRSIG(rrsig_data['covered'],
                                                rrsig_data['algorithm'],
                                                rrsig_data['labels'],
                                                rrsig_data['orig_ttl'],
                                                rrsig_data['sig_expiration'],
                                                rrsig_data['sig_inception'],
                                                rrsig_data['key_id'],
                                                rrsig_data['signer'],
                                                rrsig_data['sig'])))

            ####
            # DNSKEY
            ####
            if (qtype == QTYPE.DNSKEY or qtype == QTYPE.ANY) and record['qtype'] == "DNSKEY":
                dnskey_data = dns_dnskey_parse(record['content'])
                reply.add_answer(RR(qname,
                                    QTYPE.DNSKEY,
                                    ttl=record['ttl'],
                                    rdata=DNSKEY(dnskey_data['flags'],
                                                 dnskey_data['protocol'],
                                                 dnskey_data['algorithm'],
                                                 dnskey_data['key'])))

        if not reply.rr:
            reply.header.set_rcode(3)

        self.transport.write(reply.pack(), (host, port))

    def datagramReceived(self, data, address):
        reactor.callInThread(self.requestProcess, data, address)

# Bind DNS Port
reactor.listenUDP(int(configuration['port']), DNSEcho(), interface=str(configuration['bind']))
Thread(target=reactor.run, args=(False,)).start()

# Starting Flask status page
if configuration['status']:
    app.config['heartbeat'] = heartbeat
    try:
        if configuration['status']['username'] and configuration['status']['password']:
            pretty_log("HTTP Status Auth Enabled")
            app.config['username'] = configuration['status']['username']
            app.config['password'] = configuration['status']['password']
    except KeyError:
        app.config['username'] = None
        app.config['password'] = None
    app.run(host=str(configuration['status']['bind']),
            port=int(configuration['status']['port']))
