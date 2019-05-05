SAP Message Server research
---------------------------

Copyright (c) 2018-2019 by Mathieu Geli, Dmitry Chastuhin

Proof of concept code for two new attacks on the SAP Message Server component:

- Logon Group (transparent) Hijacking : `sap_ms_dispatcher_mitm.py`
- BeTrusted: `sap_ms_betrusted.py`

with an utility for SAP MS storage monitoring.

## Presentation

### OPCDE 2019 Dubai:

The slides of the presentation are available [here](https://github.com/comaeio/OPCDE/blob/master/2019/Emirates/(SAP)%20Gateway%20to%20Heaven%20-%20Dmitry%20Chastuhin%2C%20Mathieu%20Geli/(SAP)%20Gateway%20to%20Heaven.pdf)

## Threat analysis

Recent news coverage can be misleading for non SAP-savvy IT
responsible and is missing some threat analysis on our publication.

### Gateway issue

This is issue is known publicly since 2007, and securing guidelines
were published by SAP since 2009. From our experience this issue has
mostly disappeared as servers are updated, and old one are being
secured.

When the issue is present, with the code released by my ex-colleague
Dmitry Chastuhin [here](https://github.com/chipik/SAP_GW_RCE_exploit),
it is possible to run OS commands on the remote server via anonymous
network access.

In order to get access to business data, the attacker need to have
specific SAP internals knowledge. A script kiddie/automated tool will
barely launch a cryptocurrency miner.

### Message Server issue

This is the enabler for bypassing the secure Gateway configuration.

The issue relies on the Message Server ACL file that is too open
(`HOST=*`) by default. SAP first published in 2005 guideline on
building secure ACL files (basically writing your AS names instead of
`*`).

Published PoC `sap_ms_betrusted.py` is not reliable and highly
dependant on SAP kernel version. It means success is not ensured even
if the proper version is implemented. Having something stable will
require a good amount of SAP and reverse engineering expertise.

As we explained in our presentation, lab testing was done using full
SAP server as the attacker's host, so an attacker do not need our
python script to gain successful exploitation.

## Exploitation detection

Those measures allow to track sign of exploitation.

### Gateway activity

- Monitor gateway access and transactions executed: SAPXPG is the
  transaction program to look for, used in our `SAPanonGW` PoC to run
  OS command. Gateway developer logs are stored in the `dev_rd` file
  and application logs can be configured via transaction SMGW.
- Network traffic analysis for discovering untrusted sources
  connecting to gateway port (tcp/33NN)

Security firms already published
[signatures](https://go.onapsis.com/l/127021/2019-05-01/3rjysj/127021/123429/10KBLAZE_snort_rules.zip)
to detect this specific attack. As any signature-based measure it
could be bypassed and should not be taken as a silver bullet for
detection, but still is better than nothing.

### Message server activity

- The `dev_ms` developer log file stores connection information on the Message
  Server
- You can have a real-time view by using transaction `SMMS` via SAP
  GUI
- Network traffic analysis for discovering untrusted sources
  connecting to the Message Server internal port tcp/39NN

As for the gateway, NIDS signatures could be built by matching the
string `_SEND_NILIST` with:

- src host: SAP server
- src port: 39NN
- dest host: not SAP server VLAN

## Remediation

### Gateway
- Secure your Gateway ACL pointed by profile parameter `gw/sec_info`
  with help of SAP note 1408081
- Filter out access from untrusted sources to the Gateway (port tcp/33NN)

### Message Server

- Implement secure Message Server ACL in the file pointed by the
  profile parameter `ms/acl_info`, that will help you restrict within
  the SAP server VLAN only those authorized to connect to. See SAP
  notes 821875 and 1421005
- Filter out access from untrusted sources to the Message Server
  **internal** port (tcp/39NN) of all your SAP instances

## Assessment

You should make sure you know all your assets, especially those that
are internet exposed.

### Gateway threat

You can check all your landscape with the [anonGW
code](https://github.com/chipik/SAP_GW_RCE_exploit) by trying to
execute for instance OS command `whoami`

### Message Server threat

Assessing this one is a bit more tricky, as the "be_trusted" PoC is
not 100% reliable and may have side effects on Logon Group
availability. We strongly do not advise testing on production systems.

If you really want to showcase that during a blackbox assessment, you
better choose a landscape that is not user-facing.

For whitebox, you can assume the issue exists if both condition are
met:

- The file pointed by the `ms/acl_info` profile parameter contains
  `HOST=*`
- The MS internal port tcp/39NN is available from the user VLAN
- The Gateway port tcp/33NN is available from the user VLAN

Moreover you can use scripts from SecureAuth's Martin Gallo
`ms_dump_info.py` and `ms_dump_param.py` to remotely check profile
parameters against the Message Server internal port, as described in
this thread
https://twitter.com/MartinGalloAr/status/1124347630555938820


## Internet

What about those world maps with scary numbers?

That is SAP specialized TCP SYN scans to detect presence of a specific
SAP service (here SAP Gateway, SAP Router, SAP Message Server) behind
a certain port. That DOES NOT imply that the services are affected by
the discussed vulnerabilities. It is here to help quantify the
"external threat" and show that backend servers holding usually
sensitive data can be exposed via internet.

That is specialized in a way that usual search scan engines like
[shodan](http://shodan.io), [censys](http://censys.io),
[zoomeye](http://zoomeye.org) or [onyphe](http://onyphe.io) does not
**yet** fully provide this information.



## Greetz

- [Martin Gallo](https://twitter.com/MartinGalloAr/) for all his
  [pysap](https://github.com/SecureAuthCorp/pysap) work and advices
- [Joris van de Vis](https://twitter.com/jvis/) for feedback on testing
- Onapsis for spreading FUD and the `10KBLAZE` name that does not link
  back to this research
