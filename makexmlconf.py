#!/bin/python3

# MMSGate, a MMS gateway between Flexisip and VoIP.ms for use by Linphone clients.
# Copyright (C) 2024 by RVgo4it, https://github.com/RVgo4it
# Permission to use, copy, modify, and/or distribute this software for any purpose with or without
# fee is hereby granted.
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
# SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.

import os
import requests
import hashlib
from base64 import b64decode, b64encode
import configparser
doqrcode = True
try:
  import qrcode
except ImportError:
  doqrcode = False
  print("Warning: The qrcode import failed.  Please install it via \"sudo apt install python3-qrcode\".")
import argparse
from pathlib import Path

# command args for this script
args = [("--add-path",{"default":"conf","type":str,"help":"Add this path to the local and web paths.  Default is \"conf\"."}),
  ("--web-path",{"type":str,"help":"Use this URL path for the locations.  Default is the settings in mmsgate.conf."}),
  ("--local-path",{"type":str,"help":"Use this local path for the file locations.  Default is the setting in mmsgate.conf."}),
  ("--no-password",{"action":"store_true","help":"Do not store the password in the XML config file."}),
  ("--debug",{"action":"store_true","help":"Turn on debug messages."})]

from mmsgate import config_class
cfg = config_class(args)

fcfg = configparser.ConfigParser()
fcfg.read("/etc/flexisip/flexisip.conf")
maxexp = fcfg["module::Registrar"]["max-expires"]

# need the API id/pw
apiid = cfg.get("api","apiid")
apipw = cfg.get("api","apipw")
# proxy and webdns same name
proxy = cfg.get("web","webdns")
# path to put files
destdir = cfg.get("web","localmedia")+"/"
# url path to get files
webpath = cfg.get("web","protocol")+"://"+proxy+":"+str(cfg.get("web","webport"))+cfg.get("web","pathget")+"/"
if cfg.args.web_path:
  webpath = args.web_path+"/"
if cfg.args.local_path:
  destdir = args.local_path+"/"
destdir = os.path.expanduser(destdir)
if cfg.args.add_path != '':
  destdir = destdir+cfg.args.add_path+"/"
  webpath = webpath+cfg.args.add_path+"/"
Path(destdir).mkdir(parents=True, exist_ok=True)

print("destdir",destdir)
print("webpath",webpath)

# the template for the xml config file
xmltemplate = '''<config xmlns="http://www.linphone.org/xsds/lpconfig.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.linphone.org/xsds/lpconfig.xsd lpconfig.xsd">
<section name="sip">
<entry name="default_proxy" overwrite="true">0</entry>
<entry name="media_encryption" overwrite="true">{menc}</entry>
</section>
<section name="net">
<entry name="nat_policy_ref" overwrite="true">~OuCpkaPzCwyvMo</entry>
</section>
<section name="misc">
<!--  apply remote provisioning only once -->
<entry name="transient_provisioning" overwrite="true">1</entry>
<entry name="hide_chat_rooms_from_removed_proxies" overwrite="true">0</entry>
<entry name="file_transfer_server_url" overwrite="true">{fileserver}</entry>
</section>
<section name="app">
<entry name="keep_service_alive" overwrite="true">1</entry>
<entry name="auto_start" overwrite="true">1</entry>
<entry name="publish_presence" overwrite="true">0</entry>
</section>
<section name="nat_policy_default_values">
<entry name="stun_server">{proxy}</entry>
<entry name="protocols">stun,ice</entry>
</section>
<section name="nat_policy_0">
<entry name="ref" overwrite="true">~OuCpkaPzCwyvMo</entry>
<entry name="stun_server" overwrite="true">{proxy}</entry>
<entry name="protocols" overwrite="true">stun,ice</entry>
</section>
<section name="auth_info_0" overwrite="true">
<entry name="username" overwrite="true">{user}</entry>
<entry name="ha1" overwrite="true">{ha1}</entry>
<entry name="realm" overwrite="true">{dom}</entry>
<entry name="domain" overwrite="true">{dom}</entry>
<entry name="algorithm" overwrite="true">MD5</entry>
</section>
<section name="proxy_0" overwrite="true">
<entry name="reg_proxy" overwrite="true">&lt;{proto}:{proxy};transport={tran}&gt;</entry>
<entry name="reg_route" overwrite="true">&lt;{proto}:{proxy};transport={tran}&gt;</entry>
<entry name="reg_identity" overwrite="true">"{user}" &lt;{proto}:{user}@{dom}&gt;</entry>
<entry name="realm" overwrite="true">{dom}</entry>
<entry name="quality_reporting_collector" overwrite="true">{proto}:voip-metrics@{proxy};transport={tran}</entry>
<entry name="quality_reporting_enabled" overwrite="true">1</entry>
<entry name="quality_reporting_interval" overwrite="true">180</entry>
<entry name="reg_expires" overwrite="true">{regexp}</entry>
<entry name="reg_sendregister" overwrite="true">1</entry>
<entry name="publish" overwrite="true">1</entry>
<entry name="avpf" overwrite="true">1</entry>
<entry name="avpf_rr_interval" overwrite="true">1</entry>
<entry name="nat_policy_ref" overwrite="true">~OuCpkaPzCwyvMo</entry>
</section>
</config>
'''

input_subacct = input("Enter subaccount (* for all): ")
if input_subacct == "": exit()

# get the list of servers
url="https://voip.ms/api/v1/rest.php?api_username={}&api_password={}&method=getServersInfo"
r = requests.get(url.format(apiid,apipw))
rslts = r.json()
if cfg.args.debug: print("DEBUG: getServersInfo:",rslts)
if rslts["status"] != "success":
  print("Server search failure.")
  exit()

servers = {}
for srv in rslts["servers"]:
  servers[srv["server_pop"]] = srv["server_hostname"]

# get a list of DIDs
url="https://voip.ms/api/v1/rest.php?api_username={}&api_password={}&method=getDIDsInfo"
r = requests.get(url.format(apiid,apipw))
rsltd = r.json()
if cfg.args.debug: print("DEBUG: getDIDsInfo:",rsltd)
if rsltd["status"] != "success":
  print("DID search failure.")
  exit()

dids = {}
for did in rsltd["dids"]:
  print(did["did"],did["description"], servers[did["pop"]])
  dids[did["did"]] = servers[did["pop"]]

# get a list of sub accounts
if input_subacct == "*":
  url="https://voip.ms/api/v1/rest.php?api_username={}&api_password={}&method=getSubAccounts"
else:
  url="https://voip.ms/api/v1/rest.php?api_username={}&api_password={}&method=getSubAccounts&account="+input_subacct
r = requests.get(url.format(apiid,apipw))
rslta = r.json()
if cfg.args.debug: print("DEBUG: getSubAccounts:",rslta)
if rslta["status"] != "success":
  print("Subaccount search failure.")
  exit()

# generate xml and maybe qrcode png for each account found
for acct in rslta["accounts"]:
  if acct["callerid_number"] == "":
    print(acct["account"],"Skipped...  No caller ID.")
  else:
    print(acct["account"],acct["password"],acct["callerid_number"],dids[acct["callerid_number"]])
    if acct["sip_traffic"] == 0:
      proto = "sip"
      tran = "udp"
      menc = ""
    else:
      proto = "sips"
      tran = "tls"
      menc = "srtp"
    fileserver = cfg.get("web","protocol")+"://"+proxy+":"+str(cfg.get("web","webport"))+cfg.get("web","pathfile")
    dom = dids[acct["callerid_number"]]
    user = acct["account"]
    regexp = acct["max_expiry"]
    pw = acct["password"]
    m = hashlib.md5()
    if cfg.args.no_password:
      m.update(("no password").encode('utf-8'))
    else:
      m.update((user+":"+dom+":"+pw).encode('utf-8'))
    ha1 = m.hexdigest()
    xml = xmltemplate.format(proxy = proxy, user = user, dom = dom, ha1 = ha1, tran = tran, proto = proto, menc = menc, regexp = regexp, fileserver = fileserver)
    xmlfile = destdir+user+".xml"
    print("Creating XML file at:",xmlfile)
    with open(xmlfile, "w") as f:
      f.write(xml)
    url=webpath+user+".xml"
    print("XML config file available at:", url)
    if doqrcode:
      img = qrcode.make(url)
      imgfile = destdir+user+".png"
      print("Creating QRCode image file at:",imgfile)
      img.save(imgfile)
      iurl=webpath+user+".png"
      print("PNG QRCode image file available at:", iurl)
