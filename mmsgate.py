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

# v0.5.2 5/7/2024 Minor bug
# v0.5.1 5/6/2024 Minor bug fix
# v0.5.0 5/5/2024 New "to" url param for http file server and proxy support
# v0.4.1 4/22/2024 Minor bug
# v0.4.0 4/21/2024 Memory optimized and thread improvements
# v0.3.2 4/17/2024 Minor bug
# v0.3.1 4/16/2024 Added file server support, added Gunicorn and fixes
# v0.2.1 4/6/2024 Added internal extension support and bug fixes.
# v0.1.4 4/5/2024 Fixed makexmlconf.py, added regmon.py and mmsgate.py retry delay
# v0.1.3 4/2/2024 Fixed makexmlconf.py and added log details to README
# v0.1.2 4/1/2024 Fixed timezone and added log details to README
# v0.1.1 3/31/2024 Added mmsreconcile.py and other DB tools
# v0.1.0 3/30/2024 Added tracking of VoIP.ms message id and flex args
# v0.0.1 3/29/2024 Initial

# some of the usual imports
import time
import sys
import os

# This class handles SIP communication via PJSUA2 API from PJSIP
class pjsip_class():
  pjsip_q = None
  db_q = None

  # Prep the new object
  def __init__(self):
    import threading
    import queue
    self.t = threading.Thread(name="PJSUA-THREAD", target=self.pjsua2_start, daemon=True)
    self.pjsip_q = queue.Queue()

  # start the thread
  def start(self):
    self.t.start()

  # pjsua2 start of thread
  def pjsua2_start(self):
    import queue
    # need PJSIP for SIP communications
    import pjsua2 as pj
    # Subclass to extend the pjsua2 Account class and get notifications like message received
    class Account(pj.Account):
      # reference to the pjsip_class parent object
      pjsip = None
      # SIP registration event
      def onRegState(self, prm):
        _logger.debug("onRegState event: "+str(prm.code)+" "+prm.reason)
      # SIP message status event
      def onInstantMessageStatus(self, prm):
        _logger.debug("onInstantMessageStatus event: "+str(prm.code)+" "+prm.toUri+" "+prm.msgBody)
        toname,todom = self.pjsip.uri2name(prm.toUri)
        # tell the DB thread the result
        self.pjsip.db_q.put_nowait(("MsgStatus",prm.code,toname,todom,prm.msgBody))
      # got a message from the flexisip proxy event
      def onInstantMessage(self, prm):
        # ignore if not an SMS/MMS message
        if prm.contentType != "text/plain" and prm.contentType != "application/vnd.gsma.rcs-ft-http+xml": return
        _logger.debug("onInstantMessage msgBody: "+str(prm.msgBody))
        # collect info from header
        fromname,fromdom = self.pjsip.uri2name(prm.fromUri)
        toname,todom = self.pjsip.uri2name(prm.toUri)
        # queue it up in the DB for forwarding
        if prm.contentType == "text/plain":
          self.pjsip.db_q.put_nowait(("MsgNew",fromname,fromdom,toname,todom,prm.msgBody,"OUT",None,"SMS",None))
        if prm.contentType == "application/vnd.gsma.rcs-ft-http+xml":
          self.pjsip.db_q.put_nowait(("MsgNew",fromname,fromdom,toname,todom,prm.msgBody,"OUT",None,"MMS",None))

    try:
      # Create and initialize the library
      ep_cfg = pj.EpConfig()
      ep_cfg.logConfig.level = cfg.get("sip","siploglevel")
      ep_cfg.logConfig.consoleLevel = cfg.get("sip","sipconsoleloglevel")
      if cfg.exists("sip","siplogfile"):
        ep_cfg.logConfig.filename = os.path.expanduser(cfg.get("sip","siplogfile"))
      ep = pj.Endpoint()
      ep.libCreate()
      ep.libInit(ep_cfg)
      _logger.debug("PJSUA2 Endpoint initilized")

      # Create SIP UDP transport.
      sipTpConfig = pj.TransportConfig()
      sipTpConfig.boundAddress = cfg.get("sip","sipboundaddress")
      sipTpConfig.port = cfg.get("sip","sipport")
      ep.transportCreate(pj.PJSIP_TRANSPORT_UDP, sipTpConfig)

      # Create SIP UDP transport.
      sipTpConfigt = pj.TransportConfig()
      sipTpConfigt.boundAddress = cfg.get("sip","sipboundaddress")
      sipTpConfigt.port = cfg.get("sip","sipport")
      ep.transportCreate(pj.PJSIP_TRANSPORT_TCP, sipTpConfigt)

      # Create SIP TLS transport.
      sipTpConfigs = pj.TransportConfig()
      sipTpConfigs.boundAddress = cfg.get("sip","sipboundaddress")
      sipTpConfigs.port = cfg.get("sip","sipport")
      sipTpConfigs.tlsConfig.certFile = cfg.get("sip","sipcert")
      sipTpConfigs.tlsConfig.privKeyFile = cfg.get("sip","sipkey")
      sipTpConfigs.tlsConfig.verifyServer = False
      sipTpConfigs.tlsConfig.verifyClient = False
      ep.transportCreate(pj.PJSIP_TRANSPORT_TLS, sipTpConfigs)

      # Start the library
      ep.libStart()
      _logger.debug("PJSUA2 Endpoint started")

      # account configuration
      acfg = pj.AccountConfig()
      acfg.idUri = cfg.get("sip","sipid")
      acfg.sipConfig.proxies.append("<sip:"+cfg.get("sip","sipproxy")+">")
      acfg.sipConfig.proxies.append("<sips:"+cfg.get("sip","sipproxy")+">")
      # authentication?
      if cfg.exists("sip","authid") and cfg.exists("sip","authpw"):
        acfg.regConfig.registrarUri = "<sip:"+cfg.get("sip","sippop")+">"
        cred = pj.AuthCredInfo("digest", "*", cfg.get("sip","authid"), 0, cfg.get("sip","authpw"))
        acfg.sipConfig.authCreds.append(cred)
        _logger.debug("PJSUA2 Account configured for authentication: "+cfg.get("sip","authid"))
        # Create the account from custom class for events
        acc = Account();
        acc.pjsip = self
        acc.create(acfg);
        for i in range(10):
          if acc.getInfo().regIsActive: break
          _logger.debug("========== registering...")
          time.sleep(1)
        if i == 9:
          _logger.warning("PJSUA2 reg timeout: "+str(acc.getInfo().regStatus))
        else:
          _logger.debug("PJSUA2 registered: "+str(acc.getInfo().regStatus))
      else:
        # Create the account from custom class for events.  no logon/register.
        acc = Account()
        acc.pjsip = self
        acc.create(acfg)
      _logger.debug("PJSUA2 Account created")
    except:
      PrintException()
      exit()

    try:
      # loop forever...  or until unexpected error
      while True:
        # get requests from queue, if any
        try:
          item = self.pjsip_q.get(timeout=1)
          _logger.debug("Received item from pjsip_q: "+str(item))
          # request to stop?
          if item[0] == "Done":
            _logger.debug("Done via pjsip_q")
            break
          # request to send message?
          if item[0] == "MsgSend":
            mtype,fromuri,touri,did,msg,contact,mtype = item
            _logger.debug("Sending message to: "+touri)
            self.send_im(pj,acc,fromuri,touri,did,msg,contact,mtype)
        except queue.Empty:
          pass
    except:
      PrintException()
    # Destroy the library
    ep.libDestroy()
    _logger.warning("pjsip_q exiting thread")

  # send an instant message via pjsua2.
  def send_im(self,pj,acc,fromuri,touri,did,msg,contact,mtype):
    _logger.debug("send_im: "+str((fromuri,touri,did,msg,contact,mtype)))
    try:
      # need a buddy
      bCfg = pj.BuddyConfig();
      if contact[0:5] == "sips:":
        bCfg.uri = "sips:"+touri
      else:
        bCfg.uri = "sip:"+touri
      _logger.debug("PJSUA2 buddy config: "+bCfg.uri)
      bCfg.Subscribe = False
      myBuddy = pj.Buddy()
      myBuddy.create(acc, bCfg);
      _logger.debug("PJSUA2 buddy created")

      # the message
      prm = pj.SendInstantMessageParam()
      # need a did in the header?
      if did:
        sh = pj.SipHeader()
        sh.hName = 'X-SMS-To'
        sh.hValue = did
        prm.txOption.headers.append(sh)
      # content type
      if mtype:
        prm.contentType = mtype
      # masquerading as the pstn source?
      if fromuri:
        prm.txOption.localUri = fromuri
      # contact from aor?
      if contact:
        prm.txOption.targetUri = contact
      # create the message
      prm.content = msg
      # and send
      myBuddy.sendInstantMessage(prm);
      _logger.debug("PJSUA2 after send IM")
    except:
      PrintException()

  # this function will pull the name and domain from a uri
  def uri2name(self,uri):
    uri2 = uri.strip("<>")
    s = uri2.find(":")
    e = uri2.find("@")
    return (uri2[s+1:e],uri2[e+1:])

# this class handles the voip.ms API calls
class api_class():
  did_accts = {}
  db_q = None
  api_q = None

  # setup API client
  def __init__(self):
    # need for VoIP.ms API
    from suds.xsd.doctor import Import, ImportDoctor
    from suds.client import Client
    import threading
    import queue
    # soap config
    url = "https://voip.ms/api/v1/server.wsdl"
    imp=Import("http://schemas.xmlsoap.org/soap/encoding/")
    imp.filter.add("https://voip.ms/api/schema")
    doc = ImportDoctor(imp)
    self.clnt = Client(url,headers={"User-Agent": "Mozilla"},doctor=doc)
    self.clnt.set_options(headers={"User-Agent": "Mozilla"})
    self.t = threading.Thread(name="API-THREAD", target=self.api_thread, daemon=True)
    self.api_q = queue.Queue()

  def start(self):
    self.t.start()

  # thread for API process: sending MMS messages and collecting account DID settings
  def api_thread(self):
    from datetime import datetime, timedelta
    import queue
    import requests
    # sub account refresh settings
    last_dt = datetime(2020,1,1)
    refresh_td = timedelta(minutes=60)

    # loop forever, updating the dictionaries with voip.ms accounts and DIDs, and also send messages via API
    while True:
      if datetime.now() - last_dt > refresh_td:
        # get list of accounts and their caller ids
        caller_ids = {}
        did_accts_tmp = {}
        int_ext = {}
        int_ext_id = {}
        url="https://voip.ms/api/v1/rest.php?api_username={}&api_password={}&method=getSubAccounts"
        r = requests.get(url.format(cfg.get('api','apiid'),cfg.get('api','apipw')))
        rslt = r.json()
        for acct in rslt["accounts"]:
          caller_ids[acct["account"]] = acct["callerid_number"]
          if acct["callerid_number"] != "":
            if acct["callerid_number"] not in did_accts_tmp.keys():
              did_accts_tmp[acct["callerid_number"]] = []
            did_accts_tmp[acct["callerid_number"]].append(acct["account"])
          if acct["internal_extension"] != "":
            int_ext["10"+acct["internal_extension"]] = acct["account"]
            int_ext_id[acct["account"]] = "10"+acct["internal_extension"]
        self.did_accts = did_accts_tmp
        _logger.debug(str(("Caller IDs updated:",caller_ids)))
        _logger.debug(str(("DID Accounts updated:",self.did_accts)))
        _logger.debug(str(("internal extensions updated:",int_ext)))
        _logger.debug(str(("internal extensions by id updated:",int_ext_id)))
        if self.db_q:
          self.db_q.put_nowait(("IntExt",int_ext,int_ext_id))
        last_dt = datetime.now()

      try:
        # get a request from the queue if available
        item = self.api_q.get(timeout=10)
        _logger.debug("From queue "+str(item))
        # send a message via API?
        if item[0] == "MsgSend":
          mtype,fromid,fromdom,toid,todom,msg,msgtype = item
          toaddr = toid+"@"+todom
          # we know this sub account?
          if fromid in caller_ids.keys():
            did = caller_ids[fromid]
            if did != "":
              # send as from the DID selected as the CID for this account
              self.send_msg_api(self.clnt,toid,todom,msgtype,msg,did)
            else:
              # forgot to select CID for that voip.ms account
              _logger.warning("No caller id defined for: "+fromid)
              db_q.put_nowait(("MsgStatus","CID empty",toid,todom,msg))
          # this odd to happen
          else:
            _logger.warning("Sub account not found: "+fromid)
            db_q.put_nowait(("MsgStatus","CID empty",toid,todom,msg))
      # no requests
      except queue.Empty:
        pass

  # send the message via the voip.ms API
  def send_msg_api(self,client,toid,todom,msgtype,msg,did):
    try:
      toaddr=toid+"@"+todom
      _logger.debug("send_msg_api called with: "+str((toid,todom,msgtype,msg,did)))
      if msgtype == "MMS":
        # Send an MMS with the media URL via SOAP API
        mmsmsg = client.factory.create("ns1:sendMMSInput")
        mmsmsg.api_username = cfg.get("api","apiid")
        mmsmsg.api_password = cfg.get("api","apipw")
        mmsmsg.dst = toid
        mmsmsg.media1 = msg
        mmsmsg.did = did
        # going to send it
        _logger.debug("sendMMS to "+mmsmsg.dst+" from "+mmsmsg.did+" via API")
        rslt = client.service.sendMMS(mmsmsg)
        _logger.debug(str(("rslt",rslt)))
        if rslt[0][0][1][0] == "success":
          _logger.debug("sendMMS returned: "+rslt[0][0][1][0]+" MMS ID "+str(rslt[0][1][1][0]))
          self.db_q.put_nowait(("MsgStatus",200,toid,todom,msg))
        else:
          _logger.error("sendMMS did not return success: "+str(rslt))
          self.db_q.put_nowait(("MsgStatus","API ERR",toid,todom,msg))
      else:
        # send message as SMS via the API
        smsmsg = client.factory.create("ns1:sendSMSInput")
        smsmsg.api_username = cfg.get("api","apiid")
        smsmsg.api_password = cfg.get("api","apipw")
        smsmsg.dst = toid
        smsmsg.message = msg
        smsmsg.did = did
        # going to send it
        _logger.debug("sendSMS to "+smsmsg.dst+" from "+smsmsg.did+" via API")
        rslt = client.service.sendSMS(smsmsg)
        _logger.debug(str(("rslt",rslt)))
        if rslt[0][0][1][0] == "success":
          _logger.debug("sendSMS returned: "+rslt[0][0][1][0]+" SMS ID "+str(rslt[0][1][1][0]))
          self.db_q.put_nowait(("MsgStatus",200,toid,todom,msg))
        else:
          _logger.error("sendSMS did not return success: "+str(rslt))
          self.db_q.put_nowait(("MsgStatus","API ERR",toid,todom,msg))

    except:
      PrintException()

# this thread runs the httpd/wsgi thread for receiving http(s) requests
class web_class():
  import gunicorn.app.base

  # this is the standard class for starting gunicorn
  class StandaloneApplication(gunicorn.app.base.BaseApplication):
    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()
    def load_config(self):
        config = {key: value for key, value in self.options.items()
                  if key in self.cfg.settings and value is not None}
        for key, value in config.items():
            self.cfg.set(key.lower(), value)
    def load(self):
        return self.application

  # init for web class
  def __init__(self,ask_q,resp_q):
    import threading
    import multiprocessing
    # return calc for number of processes for gunicorn
    def number_of_workers():
      return (multiprocessing.cpu_count() * 2) + 1
    # prevents error message when worker ends
    def post_worker_init(worker):
      import atexit
      from multiprocessing.util import _exit_function
      atexit.unregister(_exit_function)
      _logger.debug("worker post_worker_init done, (pid: {})".format(worker.pid))
    # gunicorn options
    options = {
        'timeout': 0,
        'workers': number_of_workers(),
        'post_worker_init':post_worker_init
    }
    # bind override to allow proxy like nginx?
    if cfg.exists("web","bindoverride"):
      options["bind"] = cfg.get("web","bindoverride")
    else:
      # ok, bind per config and maybe tls
      options["bind"] = '%s:%s' % (cfg.get("web","webbind"), str(cfg.get("web","webport")))
      # tls?
      if cfg.get("web","protocol") == "https":
        if cfg.exists("web","cert") and cfg.exists("web","cert"):
          cert = cfg.get("web","cert")
          key = cfg.get("web","key")
          options["certfile"] = cert
          options["keyfile"] = key
        else:
          raise ValueError("For https protocol, section/option of web/cert and web/key are required in config file.  Please correct.")
    # init for web request/answer queues
    self.resp_q = resp_q
    self.ask_q = ask_q
    # prep the gunicorn app and web thread
    self.app = web_class.StandaloneApplication(self.webhook_app, options)

  # start the http server thread and gunicorn processes
  def start(self):
    self.app.run()

  # process the webhook POST or the MMS media GET or file upload
  def webhook_app(self, environ, start_response):
      from wsgiref import util
      from datetime import datetime, timezone, timedelta
      import mimetypes
      import multipart
      import requests
      import json
      import uuid
      from urllib.parse import urlparse
      # template for sending MMS to linphone clients
      mms_template = '''<?xml version="1.0" encoding="UTF-8"?>
<file xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp" xmlns:am="urn:gsma:params:xml:ns:rcs:rcs:rram">
<file-info type="file">
<file-size>{}</file-size>
<file-name>{}</file-name>
<content-type>{}</content-type>
<data url="{}" until="{}"/>
</file-info>
</file>'''
      # get the httpd request params
      path    = environ["PATH_INFO"]
      method  = environ["REQUEST_METHOD"]
      _logger.debug("WEB App: "+method+" "+path)
      # maybe a POST for file server?
      if method == "POST" and path.startswith(cfg.get("web","pathfile")):
            try:
                # content length will tell us if initial conect or file upload
                _logger.debug("POST to fileserver:"+str(environ))
                if "CONTENT_LENGTH" in environ and environ["CONTENT_LENGTH"] != "":
                  request_body_size = int(environ["CONTENT_LENGTH"])
                else:
                  request_body_size = 0
                # just init contact
                if request_body_size == 0:
                  # return 204
                  status = "204 No Content"
                  response_body = b""
                # return 200 if got file POST
                else:
                  multipart_headers = {'Content-Type': environ['CONTENT_TYPE']}
                  multipart_headers['Content-Length'] = environ['CONTENT_LENGTH']
                  web_class.webhook_app.resp = ""
                  # this is called from parse_form
                  def on_file(file):
                    _logger.debug(str(("file:",file,file.field_name,file.file_name,file.file_object)))
                    # get the local file name
                    fileext = os.path.splitext(file.file_name.decode('utf-8'))[1].lower()
                    fname = str(uuid.uuid4())+fileext
                    path = os.path.expanduser(cfg.get("web","localmedia"))
                    fpath = os.path.join(path,fname)
                    _logger.debug("Local path: "+fpath)
                    # write the POST-ed file to local file
                    file.file_object.seek(0)
                    with open(fpath, "wb") as f:
                        f.write(file.file_object.read())
                    # get info for XML file
                    filesize = os.path.getsize(fpath)
                    filetype = mimetypes.guess_type(fpath)[0]
                    furl = cfg.get("web","protocol") + "://" + cfg.get("web","webdns") + ":" + str(cfg.get("web","webport")) + cfg.get("web","pathget") + "/" + fname
                    _logger.debug("url: "+furl)
                    until = (datetime.now(tz=timezone.utc)+timedelta(days=365)).isoformat()[:19]+"Z"
                    # got XML file to return
                    web_class.webhook_app.resp += mms_template.format(filesize,file.file_name.decode('utf-8'),filetype,furl,until)
                  # parse the POST-ed file
                  multipart.parse_form(multipart_headers, environ['wsgi.input'],
                    lambda field:
                      _logger.warning(str("field:",field,field.field_name,field.value)),
                    on_file, chunk_size=1024 * 8 )
                  # no file POST found?
                  if web_class.webhook_app.resp == "":
                    raise ValueError("No POST-ed file found.")
                  else:
                    status = "200 OK"
                    response_body = str.encode(web_class.webhook_app.resp)
                  # check for "to" url param
                  if environ['QUERY_STRING'] != "":
                    import urllib
                    qs = urllib.parse.parse_qs(environ['QUERY_STRING'])
                    if "to" in qs:
                      # send image/video uploaded to the client soecified
                      self.ask_q.put_nowait(("MsgNew","1099",None,qs["to"][0],None,web_class.webhook_app.resp,"IN",None,"MMS",0))
            except:
                PrintException()
                status = "500 Error"
                response_body = b"Internal error"
            else:
                pass
            finally:
                _logger.debug("Returning: "+status)
                headers = [("Content-type", "text/plain"),
                    ("Content-Length", str(len(response_body)))]
                start_response(status, headers)
                return [response_body]
      # maybe web hook POST from voip.ms
      if method == "POST" and path.startswith(cfg.get("web","pathpost")):
            try:
                # the web hook data is in JSON format
                request_body_size = int(environ["CONTENT_LENGTH"])
                request_body = environ["wsgi.input"].read(request_body_size)
                str_body = request_body.decode("utf-8")
                _logger.debug("Web hook Body: "+str_body)
                j = json.loads(str_body)
                payload = j["data"]["payload"]
                _logger.debug("Object payload: "+str(payload))
                # array of MMS messages
                mms_msaages = []
                # download each media to make available as GET later
                for media in payload["media"]:
                  _logger.debug("URL: "+media["url"])
                  fileext = os.path.splitext(urlparse(media["url"]).path)[1].lower()
                  r = requests.get(media["url"], stream=True)
                  if r.ok:
                    # the new media file will be a UUID with the original extension
                    fname = str(uuid.uuid4())+fileext
                    path = os.path.expanduser(cfg.get("web","localmedia"))
                    fpath = os.path.join(path,fname)
                    _logger.debug("Local path: "+fpath)
                    with open(fpath, "wb") as f:
                      for chunk in r.iter_content(chunk_size=1024 * 8):
                        if chunk:
                          f.write(chunk)
                          f.flush()
                          os.fsync(f.fileno())
                    # fill in the XML template for the MMS message
                    filesize = os.path.getsize(fpath)
                    filename = "media"+fileext
                    filetype = r.headers["Content-Type"]
                    furl = cfg.get("web","protocol") + "://" + cfg.get("web","webdns") + ":" + str(cfg.get("web","webport")) + cfg.get("web","pathget") + "/" + fname
                    _logger.debug("New URL: "+furl)
                    # assume one year
                    until = (datetime.now(tz=timezone.utc)+timedelta(days=365)).isoformat()[:19]+"Z"
                    mms_msaages.append(mms_template.format(filesize,filename,filetype,furl,until))
                    _logger.debug("MMS Message: "+mms_msaages[-1])
                  else:
                    _logger.error("URL download failed: "+media["url"])
                # need the did_accts to find who gets a copy of the message
                _logger.debug("Requesting did_accts from API process-thread: "+str(self.ask_q))
                self.ask_q.put(("GetAccts",))
                _logger.debug("Getting did_accts from API process-thread: "+str(self.resp_q))
                did_accts = self.resp_q.get()
                _logger.debug("Got did_accts from API process-thread"+str(did_accts))
                # the to (destination) is a DID. we'll use the CID setting from voip.ms for the sub account to receive.
                for todid in payload["to"]:
                  if did_accts and todid["phone_number"] in did_accts.keys():
                    # send it (SMS or MMS) to every sub account using the DID as CID.
                    for toid in did_accts[todid["phone_number"]]:
                      # check filter via checking each DID for a True result from the expression
                      filter = False
                      if cfg.exists("web","webfilter") and todid["phone_number"] in eval(cfg.get("web","webfilter")):
                        _logger.debug(str(("webfilter",eval(cfg.get("web","webfilter")),todid["phone_number"])))
                        for evalexp in eval(cfg.get("web","webfilter"))[todid["phone_number"]]:
                          _logger.debug(str(("Filter:",toid,evalexp,eval(evalexp),todid["phone_number"])))
                          filter = eval(evalexp)
                          if filter: break
                      # if filtering out this destination, skip to next
                      if filter: continue
                      # SMS message?
                      if payload["type"] == "SMS":
                        self.ask_q.put_nowait(("MsgNew",payload["from"]["phone_number"],None,toid,None,payload["text"],"IN",todid["phone_number"],"SMS",payload["id"]))
                      # must be MMS
                      else:
                        if payload["text"] != "":
                          self.ask_q.put_nowait(("MsgNew",payload["from"]["phone_number"],None,toid,None,payload["text"],"IN",todid["phone_number"],"SMS",payload["id"]))
                        for mmsmsg in mms_msaages:
                          self.ask_q.put_nowait(("MsgNew",payload["from"]["phone_number"],None,toid,None,mmsmsg,"IN",todid["phone_number"],"MMS",payload["id"]))
                  else:
                    _logger.error("The DID "+todid["phone_number"]+" not found in API's did_accts.keys(): "+str(self.api.did_accts.keys()))
            # something very wrong
            except:
                PrintException()
                # return 500 Error
                status = "500 Error"
                response_body = b"Internal error"
            else:
                # return 200 OK
                status = "200 OK"
                response_body = b"ok"
            finally:
                headers = [("Content-type", "text/plain"),
                    ("Content-Length", str(len(response_body)))]
                start_response(status, headers)
                return [response_body]
      # GET request for MMS media
      if method == "GET" and path.startswith(cfg.get("web","pathget")):
            _logger.debug(str(("GET method: path:",path)))
            lpath = os.path.expanduser(cfg.get("web","localmedia"))
            _logger.debug(str(("GET method: lpath:",lpath)))
            rpath = os.path.relpath(path,cfg.get("web","pathget"))
            _logger.debug(str(("GET method: rpath:",rpath)))
            fpath = os.path.join(lpath, rpath)
            _logger.debug(str(("GET method: fpath:",fpath)))
            if os.path.exists(fpath):
                ftype = mimetypes.guess_type(fpath)[0] or "application/octet-stream"
                filelen = os.path.getsize(fpath)
                start_response("200 OK", [("Content-Type", ftype),
                  ("Content-Length", str(filelen))])
                return util.FileWrapper(open(fpath, "rb"),1024*1024)
      # not the right paths for GET/POST
      response_body = b"Oops... missing something!"
      status = "404 Not found"
      headers = [("Content-type", "text/plain"),
            ("Content-Length", str(len(response_body)))]
      start_response(status, headers)
      return [response_body]

# used for generic catch all exceptions
def PrintException():
    import linecache
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    _logger.critical("EXCEPTION IN ({}, LINE {} \"{}\"): {}".format(filename, lineno, line.strip(), exc_obj))

# this class has the db thread and gets the AOR from flexisip
class db_class():

  api_q = None
  pjsip_q = None

  # look up the linphone user's address in the aor and return it's contact uri and other into
  def get_aor(self,addr):
    from io import StringIO
    from contextlib import redirect_stdout
    try:
      from flexisip_cli import sendMessage, getpid
      # socket setup for AOR query
      server = "flexisip-proxy"
      pid = getpid(server)
      socket = "/tmp/{}-{}".format(server, pid)
      # collect stdout and place in string
      with StringIO("") as s:
        with redirect_stdout(s):
          # get the AOR address list
          rslt = sendMessage(socket,"REGISTRAR_DUMP")
        s.seek(0)
        rsltstr = s.read()
        _logger.debug("REGISTRAR_DUMP returned: "+str(rslt)+"\n"+rsltstr.strip())
      # got a good AOR dump
      if rslt == 0:
        aors = eval(rsltstr)
        # contain the one we are looking for? (starts w/ addr)
        for a in aors["aors"]:
          if a.startswith(addr):
            # collect stdout and place in string
            with StringIO("") as s:
              with redirect_stdout(s):
                # query the AOR details, including contact
                rslt = sendMessage(socket,"REGISTRAR_GET sip:"+a)
              s.seek(0)
              rsltstr = s.read()
              _logger.debug("REGISTRAR_GET returned: "+str(rslt)+"\n"+rsltstr.strip())
            # we got the contact for addr
            if rslt == 0:
              cnts = eval(rsltstr)
              return self.addr2name(a)+(cnts["contacts"],)
            else:
              _logger.debug("REGISTRAR_GET failed for "+addr+": "+str(rslt)+" "+rsltstr.strip())
              return None,None,None
        return None,None,None
      else:
        _logger.error("REGISTRAR_DUMP failed: "+str(rslt)+" "+rsltstr.strip())
        return None,None,None
    except:
      PrintException()

# get the object for this class ready
  def __init__(self):
    import queue
    import threading
    self.t = threading.Thread(name="DB-THREAD" , target=self.queue_db, daemon=True)
    self.db_q = queue.Queue()

  # start the thread
  def start(self):
    self.t.start()

  # take contacts infor for an address and make a to/contact uri
  def contact2uri(self,id,dom,contacts):
    from urllib.parse import urlparse, parse_qs
    # it's an array
    for d in contacts:
      # we need a contact that can do SMS
      if "text/plain" in d["accept"]:
        # get scheme sip vs sips
        cp = urlparse(d["contact"])
        proxyid = None
        path = None
        # look at each availablr path
        for p in d['path']:
          pp = urlparse(p)
          ppq = parse_qs(pp.params,separator=';')
          # we need the proxy id to pass SMS/MMS via proxy and activate push notification
          if 'fs-proxy-id' in ppq:
            proxyid = ppq['fs-proxy-id'][0]
          # we want the path that the scheme matches the aor contact
          if pp.scheme == cp.scheme:
            path = pp.path
        # if we got info, return uri
        if proxyid:
          return pp.scheme+":"+id+"@"+path+";CtRt"+proxyid+"=udp:"+dom

  # thread loops forever for db activity
  def queue_db(self):
    import os
    import queue
    import sqlite3
    from datetime import datetime, timedelta
    import xml.etree.ElementTree as ET
    # try to open the db
    try:
      dbfile = os.path.expanduser(cfg.get("mmsgate","dbfile"))
      _logger.debug("DB setting "+cfg.get("mmsgate","dbfile")+" became "+dbfile)
      conn = sqlite3.connect(dbfile)
    except:
      _logger.error("Failed to open DB file: "+cfg.get("mmsgate","dbfile"))
      exit()
    def unixtime(s):
      import time
      return int(time.time())+s
    conn.create_function("unixtime", 1, unixtime)
    # table of messages.
    conn.execute("CREATE TABLE IF NOT EXISTS send_msgs (rcvd_ts INT DEFAULT (unixtime(0)), fromid TEXT, toid TEXT, fromdom TEXT, todom TEXT, msgtype TEXT, "+ \
      "did TEXT, direction TEXT, message TEXT, msgstatus TEXT DEFAULT 'QUEUED', sent_ts INT, init_ts INT DEFAULT (unixtime(0)), trycnt INT DEFAULT 0, msgid TEXT);")
    # indexes for selects and updates.  partial indexes are restricted to queued/active messages.
    conn.execute("CREATE INDEX IF NOT EXISTS sm_to ON send_msgs (toid,todom,rcvd_ts) WHERE msgstatus NOT IN ('200','202');")
    conn.execute("CREATE INDEX IF NOT EXISTS sm_stats1 ON send_msgs (direction,sent_ts,msgstatus);")
    conn.execute("CREATE INDEX IF NOT EXISTS sm_stats2 ON send_msgs (direction,init_ts);")
    conn.commit()
    # get one queued message (oldest) per destination.
    sql_select_pending = "SELECT rcvd_ts,sent_ts,fromid,fromdom,toid,todom,message,direction,msgstatus,did,min(rowid) as rowid,msgtype,trycnt "+ \
      "FROM send_msgs WHERE msgstatus NOT IN ('200','202') GROUP BY toid;"
    # updates for message status
    sql_update_status_via_rowid = "UPDATE send_msgs SET sent_ts = unixtime(0),msgstatus = ?, trycnt = trycnt + 1 WHERE rowid = ?;"
    sql_update_status_dom_via_rowid = "UPDATE send_msgs SET sent_ts = unixtime(0),msgstatus = ?, todom = ?, fromdom = ?, trycnt = trycnt + 1 WHERE rowid = ?;"
    # note: msgstatus is in where clause twice to get sqlite to use sm_hs index.
    sql_update_status_via_to = "UPDATE send_msgs SET sent_ts = unixtime(0),msgstatus = ? WHERE toid = ? AND msgstatus NOT IN ('200','202') AND msgstatus = 'TRYING';"
    sql_insert_new = "INSERT INTO send_msgs(fromid,fromdom,toid,todom,message,direction,did,msgtype,msgid) VALUES(?,?,?,?,?,?,?,?,?);"
    # query for stats
    sql_stats = "SELECT direction as dir, 'Sent last 24h' as stat, COUNT(rowid) AS count FROM send_msgs WHERE msgstatus IN ('200','202') AND sent_ts > unixtime(-60*60*24) GROUP BY direction "+ \
      "UNION "+ \
      "SELECT direction as dir, 'Rcvd last 24h' as stat, COUNT(rowid) AS count FROM send_msgs WHERE init_ts > unixtime(-60*60*24) GROUP BY direction "+ \
      "UNION "+ \
      "SELECT direction as dir, 'Queue backlog' as stat, COUNT(rowid) AS count FROM send_msgs WHERE msgstatus not in ('200','202') GROUP BY direction;"
    # amount of time before trying to send again
    td_timeout = timedelta(minutes=1)
    int_ext = {}
    int_ext_id = {}

    try:
       # loop forever
       while True:
        # get oldest queued messages for each destination (to)
        for rcvd_ts,sent_ts,fromid,fromdom,toid,todom,message,direction,msgstatus,did,rowid,msgtype,trycnt in conn.execute(sql_select_pending).fetchall():
          _logger.debug(str(("SELECT record: ",rcvd_ts,sent_ts,fromid,fromdom,toid,todom,message,direction,msgstatus,did,rowid,msgtype)))
          # queued means it is ready to try
          if msgstatus == "QUEUED":
            # going to linphone user?
            if direction == "IN":
              # try to look them up in flexisip's AOR
              newtoid,newtodom,details = self.get_aor(toid+"@"+(todom or ""))
              _logger.debug("get_aor returned: "+str((newtoid,newtodom,details)))
              # got the AOR info
              if details:
                # found one!
                contact = self.contact2uri(newtoid,newtodom,details)
                if contact:
                  toaddr = toid+"@"+newtodom
                  if contact[0:5] == "sips:":
                    fromaddr = "\""+fromid+"\" <sips:"+fromid+"@"+newtodom+">"
                  else:
                    fromaddr = "\""+fromid+"\" <sip:"+fromid+"@"+newtodom+">"
                  _logger.debug("contact for "+toaddr+" is "+str(contact))
                  # send it as SIP message via PJSIP
                  if msgtype == "SMS":
                    self.pjsip_q.put_nowait(("MsgSend",fromaddr,toaddr,did,message,contact,None))
                  else:
                    self.pjsip_q.put_nowait(("MsgSend",fromaddr,toaddr,did,message,contact,"application/vnd.gsma.rcs-ft-http+xml"))
                  _logger.debug("Sent: "+str(("MsgSend",fromaddr,toaddr,did,message,contact)))
                  # update the status so we don't try again and know what to update when the result comes back
                  self.update_row_db(conn,sql_update_status_dom_via_rowid,("TRYING",newtodom,newtodom,rowid))
                else:
                  _logger.debug("contact for "+toid+" not found ")
                  self.update_row_db(conn,sql_update_status_via_rowid,("Missing Contact",rowid))
              else:
                _logger.debug("contact for "+toid+" not found ")
                self.update_row_db(conn,sql_update_status_via_rowid,("Missing AOR",rowid))

            # going to PSTN or internal extention
            else:
              # int ext?
              if toid in int_ext and fromid in int_ext_id:
                _logger.debug(str(("MsgSend Int Ext",fromid,fromdom,toid,todom,message,msgtype)))
                # mark it done
                self.update_row_db(conn,sql_update_status_via_rowid,(200,rowid))
                # turn it around as inbound
                self.db_q.put_nowait(("MsgNew",int_ext_id[fromid],None,int_ext[toid],None,message,"IN",None,msgtype,None))
              # PSTN via API
              else:
                try:
                  if msgtype == "MMS":
                    # parse the body as XML
                    root = ET.fromstring(message)
                    # loop for each file elem
                    file_url = []
                    for fe in root.findall("./"):
                      ftype,furl,fname = "","",""
                      # Loop for each file info elem and get needed values
                      for fie in fe.findall("./"):
                        if "}content-type" in fie.tag: ftype = fie.text.split(";")[0]
                        if "}data" in fie.tag: furl = fie.attrib["url"]
                        if "}file-name" in fie.tag: fname = fie.text
                      _logger.debug("Parsed XML: "+str((fname, ftype, furl)))
                      file_url.append({"name":fname, "type":ftype, "url":furl})
                    # did we get a url for the file?  if so, we'll send it via API
                    if len(file_url) != 0:
                      # send SMS message containing just the url?
                      if cfg.get("mmsgate","outvia") == "sms":
                        for furl in file_url:
                          self.api_q.put_nowait(("MsgSend",fromid,fromdom,toid,todom,furl["url"],"SMS"))
                          self.update_row_db(conn,sql_update_status_via_rowid,("TRYING",rowid))
                      # send MMS for only some kinds of media, SMS others?
                      elif cfg.get("mmsgate","outvia") == "auto":
                        for furl in file_url:
                          if furl["type"].split(";")[0] in cfg.get("mmsgate","autotypes"):
                            self.api_q.put_nowait(("MsgSend",fromid,fromdom,toid,todom,furl["url"],"MMS"))
                            self.update_row_db(conn,sql_update_status_via_rowid,("TRYING",rowid))
                          else:
                            self.api_q.put_nowait(("MsgSend",fromid,fromdom,toid,todom,furl["url"],"SMS"))
                            self.update_row_db(conn,sql_update_status_via_rowid,("TRYING",rowid))
                      # or always send as MMS.  voip.ms cannot handle just any media.  so, this can fail
                      else:
                        for furl in file_url:
                          self.api_q.put_nowait(("MsgSend",fromid,fromdom,toid,todom,furl["url"],"MMS"))
                          self.update_row_db(conn,sql_update_status_via_rowid,("TRYING",rowid))
                      _logger.debug("Sent via API: "+str((toid,file_url)))
                    else:
                      _logger.error("Error: Did not find any URLs in msgBody: "+prm.msgBody)
                      self.update_row_db(conn,sql_update_requeue_via_rowid,("No URL",rowid))
                  else:
                      self.api_q.put_nowait(("MsgSend",fromid,fromdom,toid,todom,message,"SMS"))
                      self.update_row_db(conn,sql_update_status_via_rowid,("TRYING",rowid))
                except:
                  PrintException()

          # is it a message we tried before?  if timeout, then queue it back up.
          if msgstatus != "QUEUED":
            if msgstatus == "API ERR":
              # time between retry will grow exponentially for issues w/ voip.ms
              if (datetime.utcnow() - datetime.utcfromtimestamp(sent_ts)) > (td_timeout * trycnt * trycnt):
                self.update_row_db(conn,sql_update_status_via_rowid,("QUEUED",rowid))
            else:
              # try again soon
              if (datetime.utcnow() - datetime.utcfromtimestamp(sent_ts)) > td_timeout:
                self.update_row_db(conn,sql_update_status_via_rowid,("QUEUED",rowid))

        # check the inter-process queue
        try:
          item = self.db_q.get(timeout=10)
          _logger.debug("From queue "+str(item))
          # we got a result from pjsua2"s onInstantMessageStatusor other results?
          if item[0] == "MsgStatus":
            mtype,prmcode,toid,todom,prmmsgBody = item
            # put the result in the db. we only get back the message and destination (to).  so use the destination (to) find original message.
            self.update_row_db(conn,sql_update_status_via_to,(str(prmcode),toid))
          # got a new message.  place it in the db as a queued message to send.
          if item[0] == "MsgNew":
            mtype,fromid,fromdom,toid,todom,message,direction,did,msgtype,msgid = item
            cnt = conn.execute(sql_insert_new,(fromid,fromdom,toid,todom,message,direction,did,msgtype,msgid))
            conn.commit()
          # internal extension update?
          if item[0] == "IntExt":
            mtype,int_ext,int_ext_id = item
          # shutdown?
          if item[0] == "Done":
            break
        except queue.Empty:
          pass
    except:
      PrintException()
    conn.close()
    _logger.warning("Exiting DB thread.")

  # run sql update
  def update_row_db(self,conn,sql,params):
    try:
      _logger.debug("Updating via: "+str(params))
      cnt = conn.execute(sql,params).rowcount
      conn.commit()
      if cnt == 1:
        _logger.debug("Rows updated: "+str(cnt)+" for update via "+str(params))
      else:
        _logger.warning("Rows updated: "+str(cnt)+" for update via "+str(params))
    except:
      PrintException()

  # split an address into id and domain
  def addr2name(self,addr):
    e = addr.find("@")
    return (addr[:e],addr[e+1:])

# this is the config class.  It had all the settings from config file and CLI switches
class config_class:
  # defaults to pick up if not specified
  defaults = {"sip": {"sipboundaddress": "127.0.0.2",
    "sipport": "5060",
    "sipcert": "~/data/mmsgate-local-cert.pem",
    "sipkey": "~/data/mmsgate-local-key.pem",
    "sipid": "<sip:mmsgate@localhost>",
    "sipproxy": "localhost",
    "siploglevel": "0",
    "sipconsoleloglevel": "0"},
    "web": {"webbind": "0.0.0.0",
    "webport": "38443",
    "protocol": "http",
    "pathget": "/mmsmedia",
    "pathfile": "/file",
    "localmedia": "~/mmsmedia",
    "pathpost": "/mmsgate"},
    "mmsgate": {"outvia": "auto",
    "autotypes": "image/jpg,image/jpeg,image/png,image/gif,audio/3gpp",
    "dbfile": "~/data/mmsgate.sqlite",
    "flexisippath": "/opt/belledonne-communications/bin",
    "logger": "WARNING"}}
  # descriptions for all the section/option settings in the config file
  descriptions = {"sip": {"_section": "This section defines parameters for PJSIP.",
    "sipboundaddress": "This is the local address that PJSIP will bind to for receiving data.",
    "sipport": "This is the port that PJSIP will listen to for receiving messages.",
    "sipcert": "This is the SIP TLS transport certificate for local communication.  If not found, it will be automatically created.  A ~ is allowed for home.",
    "sipkey": "This is the SIP TLS transport certificate's key for local communication.  If not found, it will be automatically created.  A ~ is allowed for home.",
    "sipid": "This is the MMSGate's SIP ID URI. Example is <sip:bob@mmsgate.dom1.com>.",
    "sippop": "This is VoIP.ms's POP DNS name.  Example is deluth1.voip.ms.",
    "sipproxy": "This is the DNS name of the Flexisip proxy server, i.e., this server.",
    "authid": "This the ID for SIP authentication.  Example is 123456_mmsgate.",
    "authpw": "This is the plain text password for authentication.",
    "siploglevel": "This is the logging level for PJSIP.",
    "sipconsoleloglevel": "This is the console logging level for PJSIP.",
    "siplogfile": "This is the logging file for PJSIP.  A ~ is allowed for home."},
    "mmsgate": {"_section": "This section contains options related to the MSSGate application",
    "logger": "This is the logging level for the MMSGate.  Options are: DEBUG,INFO,WARNING,ERROR and CRITICAL",
    "loggerfile": "This is the log file for MMSGate, full path or use ~ for home. ",
    "dbfile": "This is the SQLite db file.  A ~ is allowed and will be expanded to home of current user.",
    "flexisippath": "This the the path to the Flexisip bin path.  Needed for flexisip_cli.py.  ",
    "outvia": "Method for sending outgoing MMS to VoIP.ms.  sms: SMS message with URL.  mms: send as MMS.  auto: send SMS or MMS depending on mime type.",
    "autotypes": "Comma seperated list of mime types to send as MMS, others as SMS."},
    "api": {"_section": "This section has options for the API method.",
    "apiid": "Required.  This is the logon id for the API.  It is the same as the VoIP.ms web site logon ID. ",
    "apipw": "Required.  This is the logon password for the API.  It is created at the VoIP.ms SOAP and REST/JSON API web page, https://voip.ms/m/api.php."},
    "web": {"_section": "This section has options for the WSGI web hook and MMS media interface",
    "protocol": "This is the web protocol, either http or https.",
    "cert": "This is the path to the certificate chain file.  It is needed for https protocol.",
    "key": "This is the path to the private key file.  It is needed for https protocol.",
    "bindoverride": "Setting this to a gunicorn bind setting tells mmsgate that TLS and web traffic are handled by a proxy server (nginx) and mmsgate will just do local http.  Example is \"bindoverride=0.0.0.0:8080\".",
    "pathpost": "This is the path the web hook url uses.",
    "pathget": "This is the path the MMS media url uses.",
    "pathfile": "This is the path the MMS file server upload uses.",
    "localmedia": "This is the local path for MMS media file storage.  A ~ can be used for home. The path must exist and account have r/w permissions.",
    "webbind": "This is the IP address to bind for the WSGI webhook service",
    "webport": "This is the port number for the WSGI webhook service",
    "webdns": "Required.  This is the DNS name of the webhook web server and MMS URL web server, i.e., this server.",
    "webfilter": '''This filters the receiving ID mapping to sub accounts.  Normally, all sub accounts with caller id matching the DID will receive a copy of the message.
# Multiple lines must be indented.  DID followed by white space followed by Python logical expression.  Comments allowed.  Result of True will cause that account to NOT get the message.  Examples:
#webfilter =
#   8505551234 "bob" not in toid         # Only Bob's devices will get a copy of the message
#   8505551234 "obi" in toid             # Don't send the message to any Obi ATA devices
#   8505550987 "123456_sallytab" == toid # Sally's tablet will not get a copy of any message
#   8505555678 True                      # Don't send messages for this DID to anyone.'''}}
  # these section/option are required and can't allow default in config file
  required = [["api","apiid"],["api","apipw"],["web","webdns"]]
  # these options all return int
  type_int = ["sipport","siploglevel","sipconsoleloglevel","webport"]

  # load the config file
  def load(self,filename):
    import configparser
    if os.path.exists(filename):
      self.configobj = configparser.ConfigParser()
      self.configobj.read(filename)
    else:
      raise ValueError("Config file not found: "+filename)
      exit()
    # check the config loaded against the descriptions to confirm valid
    for s in self.configobj.keys():
      if s != "DEFAULT":
        if s not in self.descriptions:
          raise ValueError("Invalid section \"[" + s + "]\" found in config file " + filename + ". Please correct.")
        else:
          for o in self.configobj[s].keys():
            if o not in self.descriptions[s]:
              raise ValueError("Invalid option \"" + o + "\" in section \"[" + s + "]\" found in config file " + filename + ". Please correct.")
    # set default values
    opts = {}
    for s in self.defaults:
      opts = dict(opts.items() | self.defaults[s].items())
    self.configobj["DEFAULT"] = opts
    # check for required items and alert if missing from loaded file
    for s,o in self.required:
      if not self.exists(s,o):
        raise ValueError("Missing required option \"" + o + "\" in section \"[" + s + "]\" from in config file " + filename + ". Please correct.")
    if self.exists("web","webfilter"):
      # convert lines in web/webfilter to a dict
      a = {}
      for l in self.get("web","webfilter").split("\n"):
        if l != "":
          did,exp = l.split(maxsplit=1)
          # The key is the DID and the value is a list of expressions
          a[did] = a.get(did,[])+[exp]
      self.configobj["web"]["webfilter"] = str(a)
    # check local TLS crypto files
    self.configobj["sip"]["sipcert"] = os.path.expanduser(self.configobj["sip"]["sipcert"])
    self.configobj["sip"]["sipkey"] = os.path.expanduser(self.configobj["sip"]["sipkey"])
    if not os.path.exists(self.configobj["sip"]["sipcert"]) or not os.path.exists(self.configobj["sip"]["sipkey"]):
      print("Local self signed certificate and/or private key missing.  Creating...")
      import subprocess
      r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:4096", "-keyout", self.configobj["sip"]["sipkey"], "-out", self.configobj["sip"]["sipcert"], "-sha256", "-days", "3650", "-nodes", "-subj", "/CN=localhost"],capture_output=True)
      print("Return code:",r.returncode)
      print(r)
      if r.returncode != 0: 
        raise ValueError("Certificate and/or private key creation failed.")

  # does the section/option exist?  including default values.
  def exists(self,sect,opt):
    return self.configobj.has_option(sect,opt)

  # get the section/option value, including default values.
  def get(self,sect,opt):
    # make sure the section/option has been defined w/ description.
    if sect in self.descriptions:
      if "_section" in self.descriptions[sect]:
        if opt in self.descriptions[sect]:
          # id it an int type?
          if opt in self.type_int:
            # return the int of the option
            return self.configobj.getint(sect,opt,fallback=None)
          else:
            # return the string
            return self.configobj.get(sect,opt,fallback=None)
        else:
          # oops, forgot to add descriptions...
          raise ValueError("Internal error.  Missing option \"" + opt + "\" in section \"[" + sect + "]\" from descriptions definition.")
      else:
        raise ValueError("Internal error.  Missing description for section \"[" + sect + "]\" from descriptions definition.")
    else:
      raise ValueError("Internal error.  Missing section \"[" + sect + "]\" from descriptions definition.")

  # print out the default config file.  all the sections will appear but options will be commented out.  Also, descriptions will appear as comments.  
  def print_default_config(self):
    from io import StringIO
    import configparser
    self.configobj = configparser.ConfigParser()
    # populate the config obj w/ sections from descriptions
    for s in self.descriptions.keys():
      self.configobj.add_section(s)
      # add in each option key
      for o in self.descriptions[s].keys():
        # except the sections description
        if o != "_section":
          # maybe with the default if available
          try:
            self.configobj[s][o] = self.defaults[s][o]
          except:
            self.configobj[s][o] =  ""
    # write the config file to a string
    with StringIO("") as s:
      self.configobj.write(s)
      s.seek(0)
      cfgstr = s.read()
    # add the descriptions as comments
    for s in self.descriptions.keys():
      cfgstr = cfgstr.replace("["+s+"]","\n# "+self.descriptions[s]["_section"]+"\n"+"["+s+"]")
      # also add a note on default (if available) and comment out the option
      for o in self.descriptions[s].keys():
        try:
          cfgstr = cfgstr.replace("\n"+o+" = ","\n\n# "+self.descriptions[s][o]+"\n# Default is: "+self.defaults[s][o]+"\n#"+o+" = ")
        except:
          cfgstr = cfgstr.replace("\n"+o+" = ","\n\n# "+self.descriptions[s][o]+"\n#"+o+" = ")
    # print final config file
    print(cfgstr)
  _logger = None

  # configure the class
  def __init__(self,args_dict):
    import argparse
    import logging
    # get any command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-file",default="/etc/flexisip/mmsgate.conf",type=str,help="Load this config file.  Default is /etc/flexisip/mmsgate.conf.")
    for opt,arg in args_dict:
      parser.add_argument(opt,**arg)
    args = parser.parse_args() 
    # need to print default config w/ descriptions?
    if hasattr(args,"default_config") and args.default_config:
      self.print_default_config()
      exit()
    # load the config file
    self.load(args.config_file)
    # setup logger
    date_fmt = '%Y-%m-%d %H:%M:%S'
    log_format = "%(levelname)s %(asctime)s.%(msecs)03d %(process)d %(threadName)s %(name)s.%(funcName)s %(message)s"
    try:
      if hasattr(args,"mmsgate_logger") and args.mmsgate_logger != "":
        loglvl = eval("logging."+args.mmsgate_logger)
      else:
        loglvl = eval("logging."+self.get("mmsgate","logger"))
    except:
      raise ValueError("Error: Bad MMSGate logging level.")
    if self.exists("mmsgate","loggerfile"):
      logging.basicConfig(format=log_format, datefmt=date_fmt, level=loglvl, filename=os.path.expanduser(self.get("mmsgate","loggerfile")))
      print("Logging to",self.get("mmsgate","loggerfile"))
    else:
      logging.basicConfig(format=log_format, datefmt=date_fmt, level=loglvl)
    self._logger = logging.getLogger(__name__)
    # override the config file"s debug levels with command options
    if hasattr(args,"pjsip_debug") and args.pjsip_debug != -1:
      self.configobj["sip"]["siploglevel"] = str(args.pjsip_debug)
      self.configobj["sip"]["sipconsoleloglevel"] = str(args.pjsip_debug)
    try:
      sys.path.append(self.get("mmsgate","flexisippath"))
      from flexisip_cli import sendMessage, getpid
    except:
      raise ValueError("Error: flexisip_cli.py not found in "+cfg.get("mmsgate","flexisippath"))
    self.args = args

# this is a new process that runs all the non-gunicorn threads
def threads(ask_q,resp_q):
  import threading
  import signal
  threading.current_thread().name = "THREADS-MANAGER"

  # this is a thread to respond to multiprocessing queue requests from gunicorn processes
  def thread2process_q(ask_q,resp_q):
    # loop forever
    while True:
      i = ask_q.get()
      _logger.debug("thread2process_q: "+str(i))
      if i[0] == "GetAccts":
        resp_q.put(api.did_accts)
      if i[0] == "MsgNew":
        db.db_q.put_nowait(i)

  # setup the API thread
  api = api_class()
  # and start it
  api.start()
  # setup PJSIP thread
  pjsip = pjsip_class()
  # setup up the db thread
  db = db_class()
  # API thread will talk to the DB thread
  api.db_q = db.db_q
  # DB thread will talk to PJSIP and API threads
  db.pjsip_q = pjsip.pjsip_q
  db.api_q = api.api_q
  # PJSIP thread will talk to the DB thread
  pjsip.db_q = db.db_q

  # start threads
  db.start()
  pjsip.start()
  # start thread for gunicorn requests
  wt = threading.Thread(name="WEB2THREADS" , target=thread2process_q, args=(ask_q,resp_q), daemon=True)
  wt.start()
  _logger.debug("threads started")
  # catch ctrl-c and term signals for graceful shutdown
  def signal_handler(signum, frame):
    _logger.warning("Received Signal Number: "+str(signum))
    sys.exit(0)
  signal.signal(signal.SIGTERM,signal_handler)
  signal.signal(signal.SIGINT,signal_handler)
  # watch the threads.  if one exists, shutdown...
  try:
    while True:
      for t in (wt,db.t,pjsip.t,api.t):
        if not t.is_alive():
          _logger.error("Thread "+t.name+" has ended.")
          raise
      time.sleep(1)
  except:
      pass
  # tell DB and PJSIP threads to exit
  for q in (db.db_q,pjsip.pjsip_q):
    q.put_nowait(("Done",))
  _logger.warning("Exiting MMSGate in 5 seconds...")
  time.sleep(5)
  os.kill(os.getppid(), signal.SIGTERM)

#
# main()
#
if __name__ == "__main__":
  import multiprocessing as mp

  # configure everything
  args = [("--default-config",{"action":"store_true","help":"Print a default config file and exit."}),
    ("--pjsip-debug",{"default":-1,"type":int,"help":"Override the PJSIP log levels from the configuration file. Values 0-5."}),
    ("--mmsgate-logger",{"default":"","type":str,"help":"Override the MMSGate log levels from the configuration file. Value is DEBUG, INFO, WARNING, ERROR or CRITICAL."})]
  cfg = config_class(args)
  _logger = cfg._logger

  # need a process to run all the threads for non-gunicorn processing
  ctx = mp.get_context('fork')
  ask_q = mp.Queue()
  resp_q = mp.Queue()
  p = ctx.Process(target=threads,args=(ask_q,resp_q),daemon=True)
  p.start()
  _logger.debug("Threads process started - PID: "+str(p.pid))

  # setup the web class with gunicorn
  web = web_class(ask_q,resp_q)
  # clean up memory (fork will dup all the current process memory)
  import gc
  gc.collect()
  # let gunicorn take over
  web.start()
