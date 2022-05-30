#!/usr/bin/python

from xmlrpc.client import ServerProxy

server = ServerProxy('http://172.18.0.101:9002/RPC2')
server.supervisor.stopAllProcesses()
server.supervisor.startProcess('fuzzer', False)
