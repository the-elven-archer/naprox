#!/usr/bin/env python2

import gevent
from gevent import socket

from gevent import monkey
monkey.patch_socket()

from modules import *
from dnslib import *

import itertools

configuration = load_config()
nameservers = itertools.cycle(configuration['nameservers']['default'])

AF_INET = 2
SOCK_DGRAM = 2

s = socket.socket(AF_INET, SOCK_DGRAM)
s.bind((configuration['bind'], int(configuration['port'])))

def dns_handler(s, peer, data):
    #
    request = DNSRecord.parse(data)
    id = request.header.id
    qname = request.q.qname
    qtype = request.q.qtype
    #
    pretty_log("Request (%s): %r (%s)" % (str(peer), qname.label, QTYPE[qtype]))
    reply = DNSRecord(DNSHeader(id=id, qr=1, aa=1, ra=1), q=request.q)

    backend_query_fetch = dns_query(qname, qtype, nameservers.next())
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
    if not reply.rr:
        reply.header.set_rcode(3)

    s.sendto(reply.pack(), peer)

while True:
    data, peer = s.recvfrom(8192)
    gevent.spawn(dns_handler, s, peer, data)
