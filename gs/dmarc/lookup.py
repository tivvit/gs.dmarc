# -*- coding: utf-8 -*-
############################################################################
#
# Copyright © 2014 OnlineGroups.net and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
############################################################################
from __future__ import absolute_import, unicode_literals
from __builtin__ import getattr
from enum import Enum
from os.path import join as path_join
from dns.resolver import query as dns_query, NXDOMAIN, NoAnswer
from publicsuffix import PublicSuffixList
import random


class ReceiverPolicy(Enum):
    '''An enumeration of the different receiver policies in DMARC.'''
    __order__ = 'noDmarc none quarantine reject'  # only needed in 2.x

    #: No published DMARC receiver-policy could be found. Often interpreted
    #: the same way as :attr:`gs.dmarc.ReceiverPolicy.none`.
    noDmarc = 0

    #: The published policy is ``none``. Recieving parties are supposed to
    #: skip the verification of the DMARC signature.
    none = 1

    #: Generally causes the message to be marked as *spam* if verification
    #: fails.
    quarantine = 2

    #: Causes the system that is receiving the message to reject the
    #: message if the verification fails.
    reject = 3


class AlignmentMode(Enum):
    # TODO doc
    __order__ = 'relaxed strict'  # only needed in 2.x
    relaxed = 0
    strict = 1

class FailureReporting(Enum):
    # TODO doc
    __order__ = 'all any dkim spf'  # only needed in 2.x
    all = 0
    any = 1
    dkim = 2
    spf = 3


class ReportAddress():
    def __init__(self, address):
        self._plain_address = address
        chunks = address.split("!")
        self.address = chunks[0]
        self.size_limit = None
        if len(chunks) == 2:
            self.size_limit = chunks[1]

    def __repr__(self):
        if self.size_limit:
            return "%s!%s" % (self.address, self.size_limit)
        else:
            return self.address

class Dmarc:
    def __init__(self):
        # TODO all variables should be private and have getters
        # TODO document variable meaning

        # TODO rua and ruf may declare aggregation - should be parsed
        self.record = None
        self.version = None
        self.policy = None
        self.subdomain_policy = None
        self.adkim = AlignmentMode["relaxed"]
        self.aspf = AlignmentMode["relaxed"]
        self.percent = None
        self.rua = None
        self.ri = 86400
        self.rf = "afrf"
        self.ruf = None
        self.failure_reporting = FailureReporting["all"]
        self.__parsed_record = {}
        self.__psl = None

    def should_check(self):
        if not self.percent:
            return True

        return random.randint(0, 99) < self.percent

    def set_public_suffix_list(self, psl):
        self.__psl = psl

    def __answer_to_dict(self, answer):
        '''Turn the DNS DMARC answer into a dict of tag:value pairs.'''
        a = answer.strip('"').strip(' ')
        rawTags = [t.split('=') for t in a.split(';') if t]
        tags = [(t[0].strip(), t[1].strip()) for t in rawTags]
        retval = dict(tags)
        return retval

    def __map_record_fields(self, record_dict):
        mapping = {
            "v": "version",
            "p": "policy",
            "sp": "subdomain_policy",
            "adkim": "adkim",
            "aspf": "aspf",
            "pct": "percent",
            "rua": "rua",
            "ri": "ri",
            "rf": "rf",
            "ruf": "ruf",
            "fo": "failure_reporting"
        }

        for key, value in record_dict.items():
            if key == "p" or key == "sp":
                if hasattr(ReceiverPolicy, value):
                    value = ReceiverPolicy[value]
                else:
                    value = ReceiverPolicy["noDmarc"]
            if key == "pct" or key == "ri":
                value = int(value)
            if key == "rua" or key == "ruf":
                value = [ReportAddress(i) for i in value.split(",")]
            if key == "aspf" or key == "adkim" and hasattr(AlignmentMode, value):
                    value = AlignmentMode[value]
            if key == "fo" and hasattr(FailureReporting, value):
                    value = FailureReporting[value]

            setattr(self, mapping[key], value)

    def lookup_receiver_policy(self, host):
        '''Lookup the reciever policy for a host. Returns a ReceiverPolicy.

    :param str host: The host to query. The *actual* host that is queried has
                     ``_dmarc.`` prepended to it.
    :returns: The DMARC receiver policy for the host. If there is no published
              policy then :attr:`gs.dmarc.ReceiverPolicy.noDmarc` is returned.
    :rtype: A member of the :class:`gs.dmarc.ReceiverPolicy` enumeration.
    '''
        dmarcHost = '_dmarc.{0}'.format(host)
        retval = ReceiverPolicy.noDmarc
        try:
            dnsAnswer = dns_query(dmarcHost, 'TXT')
        except (NXDOMAIN, NoAnswer):
            pass  # retval = ReceiverPolicy.noDmarc
        else:
            self.record = str(dnsAnswer[0])
            # Check that v= field is the first one in the answer (which is in
            # double quotes) as per Section 7.1 (5):
            #     In particular, the "v=DMARC1" tag is mandatory and MUST appear
            #     first in the list. Discard any that do not pass this test.
            # http://tools.ietf.org/html/draft-kucherawy-dmarc-base-04#section-7.1

            if self.record.startswith('"v=DMARC1'):
                self.__parsed_record = self.__answer_to_dict(self.record)
                self.__map_record_fields(self.__parsed_record)

                # policy field is mandatory
                if not self.policy:
                    raise Exception("DMARC policy not set")

                retval = self.policy
            else:
                raise Exception('Unknown DMARC version in record (%s)' % self.record)

        assert isinstance(retval, ReceiverPolicy)
        return retval


    def __receiver_policy(self, host):
        '''Get the DMARC receiver policy for a host.

    :param str host: The host to lookup.
    :returns: The DMARC reciever policy for the host.
    :rtype:  A member of the :class:`gs.dmarc.ReceiverPolicy` enumeration.

    The :func:`receiver_policy` function looks up the DMARC reciever polciy
    for ``host``. If the host does not have a pubished policy
    `the organizational domain`_ is determined and the DMARC policy for this is
    returned. Internally the :func:`gs.dmarc.lookup.lookup_receiver_policy` is
    used to perform the query.

    .. _the organizational domain:
       http://tools.ietf.org/html/draft-kucherawy-dmarc-base-04#section-3.2'''
        hostSansDmarc = host if host[:7] != '_dmarc.' else host[7:]

        retval = self.lookup_receiver_policy(hostSansDmarc)
        if retval == ReceiverPolicy.noDmarc:
            # TODO: automatically update the suffix list data file
            # <https://publicsuffix.org/list/effective_tld_names.dat>
            if not self.__psl:
                fn = get_suffix_list_file_name()
                with open(fn, 'r') as suffixList:
                    self.__psl = PublicSuffixList(suffixList)
            newHost = self.__psl.get_public_suffix(hostSansDmarc)
            # TODO: Look up the subdomain policy
            retval = self.lookup_receiver_policy(newHost)
        return retval

    def __repr__(self):
        return str(dict((key, value) for key, value in vars(self).iteritems() if not key.startswith("_Dmarc__")))


def get_suffix_list_file_name():
    '''Get the file name for the public-suffix list data file

:returns: The filename for the datafile in this module.
:rtype: ``str``
'''
    import gs.dmarc
    modulePath = gs.dmarc.__path__[0]
    retval = path_join(modulePath, 'suffixlist.txt')
    return retval
