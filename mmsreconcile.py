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
from datetime import timedelta, datetime, date

# command args for this script
args = [("--look-back",{"default":7,"type":int,"help":"Number of days to reconcile.  Default is 7."}),
  ("--debug",{"action":"store_true","help":"Display debug data to console."})]

from mmsgate import config_class
cfg = config_class(args)

if cfg.args.debug: print("DEBUG: Look back days:",cfg.args.look_back)
days_td = timedelta(days=cfg.args.look_back)

# need the API id/pw
apiid = cfg.get("api","apiid")
apipw = cfg.get("api","apipw")

startdate = (date.today() - days_td).isoformat()
print("Reconcile since:",startdate)
webpath = cfg.get("web","protocol")+"://"+cfg.get("web","webdns")+":"+str(cfg.get("web","webport"))+cfg.get("web","pathpost")+"/"
if cfg.args.debug: print("DEBUG: Web Path:",webpath)

url="https://voip.ms/api/v1/rest.php?api_username={}&api_password={}&method=getMMS&type=1&from={}&all_messages=1"
r = requests.get(url.format(apiid,apipw,startdate))
rslt = r.json()
if rslt["status"] != "success":
  print("Error: GetMMS/SMS search failure.")
  exit()

if cfg.args.debug: print("DEBUG: getMMS query result:",rslt)

import sqlite3
try:
  dbfile = os.path.expanduser(cfg.get("mmsgate","dbfile"))
  conn = sqlite3.connect(dbfile)
except:
  Print("Error: Opening DB file:",dbfile)
  exit()

for msg in rslt["sms"]:
  print(msg["id"],msg["date"],msg["type"],msg["did"],msg["contact"],msg["message"])
  if cfg.args.debug: print("DEBUG: sms element:",msg)
  pmedia = []
  for media in msg["media"]:
    print(" ",media)
    pmedia += [{"url":media}]
  if cfg.args.debug: print("DEBUG: POST media:",pmedia)
  cnt, = conn.execute("SELECT COUNT(rowid) as msg_count FROM send_msgs WHERE msgid = ?;",(msg["id"],)).fetchone()
  if cfg.args.debug: print("DEBUG: SQLite3 DB query:",cnt)
  if cnt == 0:
    print("  Reconsiling...")
    json = {"data":{"payload":{"id":msg["id"],"from":{"phone_number":msg["contact"]},"to":[{"phone_number":msg["did"]}],"type":"MMS","text":msg["message"],"media":pmedia}}}
    if cfg.args.debug: print("DEBUG: JSON:",json)
    r = requests.post(webpath, json=json)
    if cfg.args.debug: print("DEBUG: POST result:",r)
    print("    Result:",r.status_code)
  else:
    print("  Looks fine.")
