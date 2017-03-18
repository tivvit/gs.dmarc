__author__ = 'tivvit'

import gs.dmarc

dmarc = gs.dmarc.Dmarc()
for i in ["google.com", "yahoo.com", "ebay.com", "paypal.com", "microsoft.com", "facebook.com"]:
    print "=" * 20
    print i
    print "=" * 20
    print dmarc
    print dmarc.__lookup_receiver_policy(i)
    print dmarc.record
    print dmarc.should_check()
    print dmarc.rua
    print dmarc.ruf
    print "DKIM: %s" % dmarc.adkim
    print "SPF: %s" % dmarc.aspf
    print "subdomain: %s" % dmarc.subdomain_policy
    print "=" * 20
