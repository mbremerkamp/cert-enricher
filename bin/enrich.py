#!/usr/bin/env python
# coding=utf-8

import os
import sys
import logging
import requests
import concurrent.futures

from config import *
from datetime import timedelta

SPLUNK_HOME = os.getenv("SPLUNK_HOME", DEFAULT_SPLUNK_HOME)

sys.path.insert(0, os.path.join(SPLUNK_HOME, SPLUNK_LIB_PATH))
logging.basicConfig(filename=LOGFILE_PATH,level=LOGGING_LEVEL)

from splunklib.searchcommands import \
        dispatch, EventingCommand, Configuration, Option, validators


@Configuration()
class EnrichCommand(EventingCommand):
    """Implements the transform function for enriching cert events"""

    def transform(self, records):
        """
        Modifies certs and yields them back to the splunk pipeline

        Receives cert events from the Splunk pipeline, segments them
        into chunks of 50 (Censys API max bulk size), and calls the
        cert enriching functions in a separate thread. Upon return of
        all threads, the certs are then yielded back to the Splunk pipeline
        """
        shas = {"fingerprints": []}
        certs = []
        ftrs = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKER_THREADS) as executor:
            for i, record in enumerate(records, 1):
                shas["fingerprints"].append(record["entity.sha256"])
                certs.append(record)

                if i > 1 and i % 50 == 0:
                    ftrs.append(executor.submit(self._attachBulkCertsData, shas, certs))
                    shas = {"fingerprints": []}
                    certs = []

            ftrs.append(executor.submit(self._attachBulkCertsData, shas, certs))
            concurrent.futures.wait(ftrs, return_when=concurrent.futures.ALL_COMPLETED)

            for ftr in ftrs:
                for cert in ftr.result():
                    yield cert


    def _attachBulkCertsData(self, shas, certs):
        """Modifies certs with fetched cert data and returns them"""
        certsData = self._getCertsData(shas)

        if certsData:
            for cert in certs:
                if "error" not in certsData[cert["entity.sha256"]]:
                    data = certsData[cert["entity.sha256"]]["parsed"]
                    validity = data["validity"]
                    keyInfo = data["subject_key_info"]
                    keyInfo = data["subject_key_info"]
                    browserTrust = certsData[cert["entity.sha256"]]["validation"]

                    cert["is_known"] = "True"
                    cert["subject_dn"] = data["subject_dn"]
                    cert["issuer_dn"] = data["issuer_dn"]
                    cert["serial_number"] = data["serial_number"]

                    cert["validity"] = self._formatTime(validity)
                    cert["subject_alt_names"] = data["names"]
                    cert["key_info"] = self._formatKeyInfo(keyInfo)
                    cert["sig_algorithm"] = data["signature_algorithm"]["name"]

                    cert["apple_trusted"] = str(browserTrust["apple"]["valid"])
                    cert["google_trusted"] = str(browserTrust["google_ct_primary"]["valid"])
                    cert["microsoft_trusted"] = str(browserTrust["microsoft"]["valid"])
                    cert["mozilla_trusted"] = str(browserTrust["nss"]["valid"])
                else:
                    cert["is_known"] = "False"
        return certs


    def _getCertsData(self, shas):
        """returns cert's data for each cert in shas"""
        try:
            res = requests.post(API_URL, auth=(API_ID, API_SECRET), json=shas, timeout=API_TIMEOUT)
            res.raise_for_status()
        except requests.exceptions.RequestException as e:
            logging.error(e)
            return {}
        return res.json()


    def _formatTime(self, validity):
        """Return formatted time validity"""
        formattedTime = \
            f"{str(validity['start'])[:-1]} to " \
            f"{str(validity['end'])[:-1]} " \
            f"({str(timedelta(seconds=validity['length']))[:-1]})"

        return formattedTime.replace("T", " ")


    def _formatKeyInfo(self, keyInfo):
        """Return formatted public key info"""
        keyType = f"{keyInfo['key_algorithm']['name'].lower()}_public_key"

        if keyType == "rsa_public_key":
            formattedKeyInfo = \
                f"{str(keyInfo[keyType]['length'])}-bit " \
                f"{keyInfo['key_algorithm']['name']}" \
                f", e={str(keyInfo['rsa_public_key']['exponent'])}"
        else:
            formattedKeyInfo = \
                f"{keyInfo['key_algorithm']['name']}" \
                f" ({keyInfo[keyType]['curve']})"

        return formattedKeyInfo


dispatch(EnrichCommand, sys.argv, sys.stdin, sys.stdout, __name__)
