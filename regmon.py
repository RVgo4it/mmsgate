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
import sys
import requests
import time
from datetime import timedelta, datetime, date
import configparser

# command args for this script
args = [("--refresh-seconds",{"default":30,"type":int,"help":"Number of seconds between refreshs when registration expiring.  Default is 30."}),
  ("--check-seconds",{"default":120,"type":int,"help":"Number of seconds before expiring to check registration.  Default is 120."}),
  ("--forget-seconds",{"default":120,"type":int,"help":"Number of seconds after expiring to forget registration.  Default is 120."}),
  ("--max-seconds",{"default":3600,"type":int,"help":"Number of seconds a registration can age.  Default is 3600."}),
  ("--push-notification",{"action":"store_true","help":"Once expired, try a push notification.  Android only."}),
  ("--debug",{"action":"store_true","help":"Display debug data to console."})]

from mmsgate import config_class
cfg = config_class(args)
fcfg = configparser.ConfigParser()
fcfg.read("/etc/flexisip/flexisip.conf")

fbcfg = fcfg["module::PushNotification"]["firebase-service-accounts"]
fbdic = {}
for fb in fbcfg.split():
  proj,file = fb.split(":")
  fbdic[proj] = file
if cfg.args.debug: print("DEBUG: Firebase keys:",fbdic)

if cfg.args.debug: print("DEBUG: Refresh Seconds:",cfg.args.refresh_seconds)
refresh_seconds_td = timedelta(seconds=cfg.args.refresh_seconds)
if cfg.args.debug: print("DEBUG: Check Seconds:",cfg.args.check_seconds)
check_seconds_td = timedelta(seconds=cfg.args.check_seconds)
if cfg.args.debug: print("DEBUG: Max Seconds:",cfg.args.max_seconds)
max_td = timedelta(seconds=cfg.args.max_seconds)

flexisippath = cfg.get("mmsgate","flexisippath")
pusherpath = flexisippath+"/flexisip_pusher"

# used for generic catch all exceptions
def PrintException():
    import linecache
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    print("EXCEPTION IN ({}, LINE {} \"{}\"): {}".format(filename, lineno, line.strip(), exc_obj))

# format timedelta
def tdfmt(td):
  if cfg.args.debug: print("DEBUG: tdfmt: td:",td)
  try:
    if td.total_seconds() < 0:
      sgn = "-"
    else:
      sgn = "+"
    s = abs(td).total_seconds()
    hours, remainder = divmod(s, 3600)
    minutes, seconds = divmod(remainder, 60)
    return sgn+'{:02d}:{:02d}:{:02d}'.format(int(hours), int(minutes), int(seconds))
  except:
    print("ERROR: In tdfmt()")
    PrintException()

registar = {}

# get registar
try:
    from io import StringIO
    from contextlib import redirect_stdout
    from flexisip_cli import sendMessage, getpid
    from urllib.parse import urlparse, parse_qs
    import subprocess
    # socket setup for AOR query
    server = "flexisip-proxy"
    pid = getpid(server)
    socket = "/tmp/{}-{}".format(server, pid)
    # collect stdout and place in string
    while True:
      print("\nCurrent time:",datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
      next_exp = datetime.now() + max_td
      next_cnt = {}
      next_addr = ""
      with StringIO("") as s:
        with redirect_stdout(s):
          # get the AOR address list
          rslt = sendMessage(socket,"REGISTRAR_DUMP")
        s.seek(0)
        rsltstr = s.read()
      # got a good AOR dump
      if rslt == 0:
        aors = eval(rsltstr)
        if cfg.args.debug: print("DEBUG: AOR:",aors)
        # check each address
        for addr in aors["aors"]:
            # collect stdout and place in string
            with StringIO("") as s:
              with redirect_stdout(s):
                # query the AOR details, including contact
                rslt = sendMessage(socket,"REGISTRAR_GET sip:"+addr)
              s.seek(0)
              rsltstr = s.read()
            # we got the contact for addr
            if rslt == 0:
              cnts = eval(rsltstr)
              if cfg.args.debug: print("DEBUG: AOR Contact:",cnts)
              registar[addr] = cnts["contacts"]
            else:
              print("Error: Registar get:",rslt,"for", addr)
      else:
        print("Error: Registar dump:",rslt)
      for addr,cnts in sorted(registar.items()):
            if cfg.args.debug: print("DEBUG: addr,cnts:", addr, cnts)
            # check each contact
            for cnt in cnts:
                # check the age
                exp = datetime.fromtimestamp(cnt['expires-at'])
                if exp <= next_exp:
                  next_exp = exp
                  next_cnt = cnt
                  next_addr = addr
                exp_td = exp-datetime.now()
                exp_sec = exp_td.total_seconds()
                print("  {:<50}".format(addr),'expires-at',exp,"in",tdfmt(exp_td),"or",int(exp_sec),"seconds")
                # try push notification to wake it up?
                if cfg.args.push_notification:
                  # parse the contact and it's query params
                  c = cnt['contact']
                  cp = urlparse(c)
                  cpq = parse_qs(cp.params,separator=';')
                  if cfg.args.debug: print("DEBUG: Contact Parsed:",cpq)
                  # is it a push notification client? and expired?
                  if "pn-provider" in cpq and exp_sec < 0:
                    # is it firebase reg?
                    if cpq["pn-provider"][0] == "fcm":
                      # do pn to wake up client so it can register
                      if cfg.args.debug:
                        r = subprocess.run([pusherpath, "--pn-provider", cpq["pn-provider"][0], 
                          "--pn-param", cpq["pn-param"][0] , "--pn-prid", cpq["pn-prid"][0], 
                          "--key", fbdic[cpq["pn-param"][0]], "--debug"],capture_output=True)
                      else:
                        r = subprocess.run([pusherpath, "--pn-provider", cpq["pn-provider"][0], 
                          "--pn-param", cpq["pn-param"][0] , "--pn-prid", cpq["pn-prid"][0], 
                          "--key", fbdic[cpq["pn-param"][0]]],capture_output=True)
                      print("  Pusher return code:",r.returncode)
                      if cfg.args.debug: print("DEBUG: Run returned:",r)
      # get the next to expire
      print("Next:",next_addr,"expires-at",next_exp)
      exp_td = next_exp - datetime.now()
      sleep_td = exp_td - check_seconds_td
      if cfg.args.debug: print("DEBUG: exp_td,sleep_td:",exp_td,sleep_td)
      # old registration to forget about?  must be expired more then forget_seconds
      if exp_td.total_seconds() < 0 - cfg.args.forget_seconds: del registar[next_addr]
      # don't sleep less then refresh seconds, includes negative
      if sleep_td.total_seconds() < cfg.args.refresh_seconds: sleep_td = refresh_seconds_td
      print("Sleeping for:", tdfmt(sleep_td), "until", (datetime.now()+sleep_td).strftime("%Y-%m-%d %H:%M:%S"))
      time.sleep(sleep_td.total_seconds())

except:
  print("ERROR: In loop.")
  PrintException()


