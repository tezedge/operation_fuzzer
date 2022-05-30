#!/usr/bin/python

from xmlrpc.client import ServerProxy

server = ServerProxy('http://127.0.0.1:9002/RPC2')
server.supervisor.stopAllProcesses()
server.supervisor.startProcess('fuzzer', False)
