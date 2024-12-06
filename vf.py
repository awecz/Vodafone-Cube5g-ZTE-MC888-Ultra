#!/usr/bin/python3

#
# VF Cube5g / ZTE MC888 Ultra
#
# Reads signal status from the device and passes the data
# to Telegraf instance running in docker
#

import json
import time
from hashlib import sha256
import urllib.parse
import requests

debug = False

influx_url = "http://localhost:8086/write"
router = "192.168.0.1"
password = "***PASSWORD***"
timeout = (4);

network = "network_type,rssi,rscp,lte_rsrp,lte_rsrq,Z5g_snr,Z5g_rsrp,Z5g_rsrq,ZCELLINFO_band,Z5g_dlEarfcn,lte_ca_pcell_arfcn,lte_ca_pcell_band,lte_ca_scell_band,lte_ca_pcell_bandwidth,lte_ca_scell_info,lte_ca_scell_bandwidth,wan_lte_ca,lte_pci,Z5g_CELL_ID,Z5g_SINR,cell_id,wan_lte_ca,lte_ca_pcell_band,lte_ca_pcell_bandwidth,lte_ca_scell_band,lte_ca_scell_bandwidth,lte_ca_pcell_arfcn,lte_ca_scell_arfcn,lte_multi_ca_scell_info,wan_active_band,nr5g_pci,nr5g_action_band,nr5g_cell_id,lte_snr,ecio,wan_active_channel,nr5g_action_channel"

def cmd(cmd):
    return "http://" + router + "/goform/goform_get_cmd_process?isTest=false&cmd=" + urllib.parse.quote_plus(cmd) + "&_=" + str(int(time.time() * 1000))

def sha256upper(plain):
    s = sha256()
    s.update(plain.encode('utf-8'))
    return s.hexdigest().upper()

def hash(plain, suffix):
    first = sha256upper(plain)
    second = sha256upper(first + suffix)
    return second

def read():
    result = []
    base = "http://" + router
    session = requests.Session()
    login = json.loads(session.get(cmd("LD"), headers = { "Referer": base + "/index.html" }, timeout = timeout).content)
    if ("LD" in login):
        salt = login["LD"]
        headers = { "Referer": base + "/", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8" }
        response = json.loads(session.post(base + "/goform/goform_set_cmd_process", data = { "isTest": "false", "goformId": "LOGIN", "password": hash(password, salt) }, headers = headers, timeout = timeout).content)
        if (response["result"] == "0"):
            response = json.loads(session.get(cmd(network) + "&multi_data=1", headers = { "Referer": base + "/" }).content)
            for k in response:
                v = response[k]
                if (len(v) > 0):
                    try:
                        f = float(v)
                        result.append("vodafone,variable=" + k.lower() + " value=" + v)
                    except:
                        result.append("vodafone,variable=" + k.lower() + " text=\"" + v + "\"")

    session.close()
    return "\n".join(result)

def send(data):
    if (debug):
        print("-------------------------------------")
        print(data)
    else:
        requests.post(influx_url, data = data, timeout = timeout)

send(read())
