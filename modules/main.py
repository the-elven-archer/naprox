#!/usr/bin/env python2

import re
import time
import calendar
import base64
# import uuid

import dns
import dns.name
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver

#

from configobj import ConfigObj
import os

import logging

# DEBUG
import pprint
pp = pprint.PrettyPrinter(indent=4)
#


def load_config(config_file=None):
    """ Load config from file """
    if config_file is None:
        config_file = "%s/etc/naprox.conf" % str(os.getcwd())
    if not os.path.isfile(config_file):
        return False
    config = ConfigObj(config_file)
    print "Loading config from %s... " % config_file
    logging.basicConfig(filename=config['logfile'],
                        format='%(asctime)s %(message)s',
                        level=logging.INFO)
    logging.getLogger('apscheduler.scheduler').setLevel('WARNING')

    return config


def pretty_log(message):
    """ Return a message using pretty print """
    if message is not None:
        logging.info(message)
        return pp.pprint(message)


def dns_query(record_body, record_type, nameserver):
    """ Query the AUTH DNS servers """
    if record_body is not None or record_type is not None or nameserver is not None:
        query_record = dns.name.from_text(str(record_body))
        if type(record_type) is not int:
            record_type = dns.rdatatype.from_text(record_type)

        query_request = dns.message.make_query(query_record, record_type)

        result = []

        try:
            response = dns.query.udp(query_request, nameserver, one_rr_per_rrset=True, timeout=5)
        except:
            return result

        # if record_type == "ANY":
        for rrset in response.answer:
            parse_array = re.split('\s+', rrset.to_text())
            record_reply_r = parse_array[0]
            record_ttl_r = parse_array[1]
            # record_class = parse_array[2]
            record_type_r = parse_array[3]
            record_data_r = " ".join(parse_array[4:])
            result.append({"qtype": record_type_r,
                           "qname": record_reply_r,
                           "content": record_data_r,
                           "ttl": int(record_ttl_r),
                           "domain_id": "-1"})
        # pretty_log(result)
        return result


def dns_soa_parse(soa_data):
    """ Parse SOA data in str in a fashionable way """
    if soa_data is not None or soa_data is str:
        soa_data_explode = re.split('\s+', soa_data)
        if soa_data_explode.__len__() != 7:
            return {}
        else:
            parsed_data = {'ns': soa_data_explode[0],
                           'owner': soa_data_explode[1],
                           'serial': int(soa_data_explode[2]),
                           'refresh': int(soa_data_explode[3]),
                           'retry': int(soa_data_explode[4]),
                           'expiry': int(soa_data_explode[5]),
                           'nxdomain': int(soa_data_explode[6])}
            return parsed_data


def dns_mx_parse(mx_data):
    """ Parse MX data in str in a fashionable way """
    if mx_data is not None or mx_data is str:
        mx_data_explode = re.split('\s+', mx_data)
        if mx_data_explode.__len__() != 2:
            return {}
        else:
            parsed_data = {'mx': mx_data_explode[1],
                           'weight': int(mx_data_explode[0])}
            return parsed_data


def dns_srv_parse(srv_data):
    """ Parse SRV data in str in a fashionable way """
    if srv_data is not None or srv_data is str:
        srv_data_explode = re.split('\s+', srv_data)
        if srv_data_explode.__len__() != 4:
            return {}
        else:
            parsed_data = {'priority': int(srv_data_explode[0]),
                           'weight': int(srv_data_explode[1]),
                           'port': int(srv_data_explode[2]),
                           'target': srv_data_explode[3]}
            return parsed_data


def dns_txt_clean(txt_data):
    """ Clean TXT record searching for quotes et al """
    if txt_data is not None or txt_data is str:
        # txt_data_clean = re.sub('"', '', txt_data)
        if re.search("spf", txt_data, flags=re.IGNORECASE):
            txt_data_clean = re.sub('"', '', txt_data)
        elif re.search("v=DKIM1", txt_data, flags=re.IGNORECASE):
            txt_data_clean = re.split('\s+', re.sub('"', '', txt_data))
        else:
            txt_data_clean = re.sub('"', '', txt_data)
        return txt_data_clean


# DNSSEC
def dns_rrsig_parse(rrsig_data):
    """ Parse RRSIGN data in str in a fashionable way """
    if rrsig_data is not None or rrsig_data is str:
        rrsig_data_explode = re.split("\s+", rrsig_data)
        if rrsig_data_explode.__len__() < 8:
            return {}
        else:
            sig_data = "".join(rrsig_data_explode[8:])
            time_format = "%Y%m%d%H%M%S"
            parsed_data = {'covered': dns.rdatatype.from_text(rrsig_data_explode[0]),
                           'algorithm': int(rrsig_data_explode[1]),
                           'labels': int(rrsig_data_explode[2]),
                           'orig_ttl': int(rrsig_data_explode[3]),
                           'sig_expiration': int(calendar.timegm(time.strptime(rrsig_data_explode[4], time_format))),
                           'sig_inception': int(calendar.timegm(time.strptime(rrsig_data_explode[5], time_format))),
                           'key_id': int(rrsig_data_explode[6]),
                           'signer': rrsig_data_explode[7],
                           'sig': base64.b64decode(sig_data)}
        return parsed_data


def dns_dnskey_parse(dnskey_data):
    """ Parse DNSKEY data in str in a fashionable way """
    if dnskey_data is not None or dnskey_data is str:
        dnskey_data_explode = re.split("\s+", dnskey_data)
        if dnskey_data_explode.__len__() < 4:
            return {}
        else:
            key_data = "".join(dnskey_data_explode[3:])
            parsed_data = {'flags': int(dnskey_data_explode[0]),
                           'protocol': int(dnskey_data_explode[1]),
                           'algorithm': int(dnskey_data_explode[2]),
                           'key': base64.b64decode(key_data)}
            print parsed_data
        return parsed_data
