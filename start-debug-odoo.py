#!/usr/bin/env python

import sys
import openerp

if sys.gettrace() != None:
    # we are in debug mode ensure that odoo don't try to start gevent
    print 'Odoo started in debug mode. Prevents from running evented server'
    openerp.evented = False

if __name__ == "__main__":
    openerp.cli.main()
