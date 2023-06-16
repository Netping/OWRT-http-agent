#!/usr/bin/python3

from http.server  import ThreadingHTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
import threading

from urllib.parse import urlparse
from urllib.parse import parse_qs, parse_qsl

import time
import queue
import signal
import ubus
import atexit
import sys
import json
import base64
from parser import *

module_name = "http-agent"

class HttpHandler(BaseHTTPRequestHandler):

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def is_module_cmd_exists(self, mod_name, cmd_name):
        objs = ubus.objects()
        return mod_name in objs and cmd_name in objs[mod_name]

    def parse_url(self, url):
        #Requests lool like: http://ip_addr/module/command?attribute1=value1&attribute2=value2&…&attributeN=valueN
        #url = 'https://www.example.com/some_path?some_key=some_value'
        #url = 'http://192.168.1.54/owrt-digital-outs/get_state?id_relay=5'
        try:
            sub_cmd = (url[1:] if url.startswith('/') else url).split("?",1)[0]
            url_tokens = sub_cmd.rsplit('/')
            if len(url_tokens) != 2:
                raise ValueError(f"An inappropriate path: GET {url}")
            subsys = url_tokens[0]
            cmd = url_tokens[1].split("?",1)[0]
            url_split = url.rsplit("?",1)

            ret = self.is_module_cmd_exists(subsys, cmd)
            if ret == False:
                raise ValueError(f"Invalid ubus: {subsys}/{cmd}")
            parsed_url = urlparse(url)
            url_dict = parse_qs(parsed_url.query)
            args = {}
            if len(url_split) > 1:
                args = parse(url_split[1])
            return (subsys, cmd, args)
        except Exception as e:
            #print('Error during parsing -> malformed url: %s', str(e))
            ret = f'Error during parsing -> malformed url: {str(e)}'
            return (ret,)

    def do_GET(self):
        try:
            client_token = self.headers.get('Authorization').strip('Basic ')
            if self.server.auth_token != client_token:
                self.wfile.write(str("HTTP/1.1 401 Unauthorized\n\n" + 'Wrong credetials\n').encode("utf-8"))
                self.send_response(401)
                return
            else:
                self.wfile.write(str("HTTP/1.1 200 OK\n\n").encode("utf-8"))
                self.send_response(200)
        except AttributeError:
                self.do_AUTHHEAD()
                return

        reply_str = str()
        reply_dict = dict()

        #self.send_response(200)
        #self.end_headers()
        curr_thread_name =  threading.current_thread().name
        print(curr_thread_name)
        query = self.path
        print(f"source query {query}")
        if "/favicon.ico" == query:
            return

        reply_dict["netping"] = {}

        ubus_req = self.parse_url(query)
        print(ubus_req)
        print(type(ubus_req))
        if 1 == len(ubus_req) and isinstance(ubus_req[0],str):
            reply_str = ubus_req[0]
            #reply_str = f"Error parsing input url '{ubus_req[0]}'"
            reply_dict["netping"]["result"] = "error"
            reply_dict["netping"]["message"] = reply_str
            self.wfile.write(json.dumps(reply_dict).encode("utf-8"))
            self.send_response(400)
            return
        reply_dict["netping"]["command"] = ubus_req[0] + "/" + ubus_req[1]
        #print("ubus_req:", ubus_req)
        self.server.q_out.put(ubus_req)
        ret = self.server.q_in.get()
        if isinstance(ret, list) and len(ret) > 1:
            reply_str = json.dumps(ret[0]) + "\n" + json.dumps(ret[1])
            reply_dict["netping"]["result"] = ret[0]
            if "error" == ret[0]:
                reply_dict["netping"]["message"] = ret[1]
            elif "ok" == ret[0]:
                reply_dict["payload"] = ret[1]
        else:
            reply_str = "Fail\nEmpty UbusService's reply";
            reply_dict["netping"]["result"] = "error"
            reply_dict["netping"]["message"] = reply_str
        self.server.q_in.task_done()
        self.wfile.write(json.dumps(reply_dict).encode("utf-8"))
        #self.wfile.write(reply_str.encode("utf-8"))
        return

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    def __init__(self, server_address, RequestHandlerClass, q_in, q_out, auth_token, bind_and_activate=True):
        HTTPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.q_in  = q_in
        self.q_out = q_out
        self.auth_token = auth_token

class UbusService():
    def __init__(self, q_in, q_out):
        self.q_in  = q_in
        self.q_out = q_out
        self.thr = threading.Thread(target=self.worker, daemon=True)
        ubus.connect()
        atexit.register(self.cleanup)
        print("UbusService init ok")

    def cleanup(self):
        ubus.disconnect()
        self.thr.join()

    def worker(self):
        print("Ubus worker started")
        while True:
            res = []
            try:
                item = self.q_in.get()
                print(item, type(item))
                if not isinstance(item, tuple):
                    print("is not a tuple")
                    continue
                if item[0] == "exit":
                    print("worker exits")
                    return
                print(f'Working on {item}')
                objs = item[2]
                #print(objs)
                scheme = ubus.objects()[item[0]][item[1]]
                #print("objs:", scheme)

                for k in objs.keys():
                    if not k in scheme:
                        raise TypeError(f"key {k} isn't related to scheme: {scheme}")

                # 1 - ARRAY
                # 2 - TABLE
                # 3 - STRING
                # 4 - ???
                # 5 - INTEGER
                # 6  - BOOLEAN 
                # 7  - UNKNOWN
                for k,t in scheme.items():
                    if 6 == t:
                        objs[k] = bool(objs[k])
                    if 5 == t:
                        objs[k] = int(objs[k])
                    if 1 == t and k in objs and not isinstance(objs[k], list):
                        if isinstance(objs[k],str):
                            objs[k] = [objs[k]]
                        else:
                            raise TypeError(f"key {k} has to be list")
                    if 2 == t and k in objs and not isinstance(objs[k], dict):
                        raise TypeError(f"key {k} has to be dict")
                #print("objs:", objs)
                res = ubus.call(item[0], item[1], objs)
                res = ["ok"] + res
                #print("ubus.call:", res)
                self.q_in.task_done()
                print(f'Finished {item}')
            except TypeError as e:
                str_err = 'UbusService Texception: invalid type: {}'.format(str(e))
                print(str_err)
                res = ["error", str_err]
            except ValueError as e:
                str_err = 'UbusService Vexception: invalid scheme (wrong json-rpc request for ubus) : {}'.format(str(e))
                print(str_err)
                res = ["error", str_err]
            except RuntimeError as e:
                str_err = 'UbusService RTexception: {}'.format(str(e))
                res = ["error", str_err]
                print(str_err)
            #except Exception as e:
            finally:
                #print(res)
                self.q_out.put(res)

    def run(self):
        self.thr.start()

DEFAULT_HTTP_PORT = 8080

class HttpUbusProxyAgent():
    confName = 'http-agent'
    port = DEFAULT_HTTP_PORT
    auth = False
    auth_login = ''
    auth_password = ''
    def __init__(self, port):
        fpath = "/etc/config/" + self.confName
        connectubus = True
        HttpUbusProxyAgent.__load_conf(self.confName, connectubus)
        server_token = base64.b64encode(bytes(f'{self.auth_login}:{self.auth_password}','utf-8')).decode('utf-8')
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)
        self.q_http_ubus = queue.Queue()
        self.q_ubus_http = queue.Queue()
        self.ubs = UbusService(self.q_http_ubus, self.q_ubus_http)
        self.ubs.run()
        self.http_server = ThreadedHTTPServer(('0.0.0.0', port), HttpHandler, self.q_ubus_http, self.q_http_ubus, server_token)

    def __load_conf(file, connectubus):
        if connectubus:
            try:
                ubus.connect()
            except:
                print("Can't connect to ubus")

        HttpUbusProxyAgent.confName = file

        confvalues = ubus.call("uci", "get", {"config": HttpUbusProxyAgent.confName})
        for confdict in list(confvalues[0]['values'].values()):
            if confdict['.name'] == 'settings':
                if HttpUbusProxyAgent.port != confdict['port']:
                    HttpUbusProxyAgent.port = confdict['port']

                #TBD
                #if HttpUbusProxyAgent.auth != bool(int(confdict['auth_enabled'])):
                #    HttpUbusProxyAgent.auth = bool(int(confdict['auth_enabled']))

                if HttpUbusProxyAgent.auth_login != confdict['auth_login']:
                    HttpUbusProxyAgent.auth_login = confdict['auth_login']

                if HttpUbusProxyAgent.auth_password != confdict['auth_password']:
                    HttpUbusProxyAgent.auth_password = confdict['auth_password']
                
        if connectubus:        
            ubus.disconnect()

    def run(self):
        try:
            print('Starting http server, use <Ctrl-C> to stop')
            #TODO: introduce flag and use it in signal_handler
            #while True:
            #    self.http_server.handle_request()
            self.http_server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            # Clean-up server (close socket, etc.)
            self.server_close()

    def server_close(self):
        print('Stoping http server')
        self.http_server.shutdown()
        self.q_http_ubus.put(("exit",))
        
    def exit_gracefully(self, signum, frame):
        signame = signal.Signals(signum).name
        print(f'Exit_gracefully, signal handler called with signal {signame} ({signum})')
        #self.server.shutdown()
        raise KeyboardInterrupt


def run():
    port = DEFAULT_HTTP_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError as ex:
            print('"%s" cannot be converted to an int: %s' % (sys.argv[1], ex))
            sys.exit(0)
    HttpUbusProxyAgent(port).run()

if __name__ == '__main__':
    run()
