# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_snmpwalk
# Purpose:      Get SystemOS from SNMPWalk.
#
# Author:      Xavie J. Sierra Moreu <xavie.sierra@gmail.com>
#
# Created:     17/02/2022
# Copyright:   (c) Xavie J. Sierra Moreu 2022
# Licence:     GPL
# -------------------------------------------------------------------------------

import os
import subprocess
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_snmpwalk(SpiderFootPlugin):

    meta = {
        'name': "snmpwalk",
        'summary': "Get SystemOS from SNMPWalk.",
        'flags': [""],
        'useCases': ["snmp"],
        'categories': ["snmp"]
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["OPERATING_SYSTEM"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        try:
            data = None

            self.sf.debug(f"We use the data: {eventData}")
            print(f"We use the data: {eventData}")

            resultado = subprocess.run(["snmpwalk","-v2c", "-c", "public", eventData, ".1.3.6.1.2.1.1.1.0"], stdout=subprocess.PIPE)
            resultado = resultado.stdout.decode("utf-8") 
            resultado = resultado.split(" ") 
            #print(resultado[6])

        #    if not data:
        #        self.sf.error("Unable to perform <ACTION MODULE> on " + eventData)
        #        return
        except Exception as e:
            self.sf.error("Unable to perform the <ACTION MODULE> on " + eventData + ": " + str(e))
            return

        typ = "OPERATING_SYSTEM"
        data = resultado[5]

        evt = SpiderFootEvent(typ, data, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_snmpwalk class
