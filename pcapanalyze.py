# Parses input file of libpcap format and categorizes the data to determine overhead
# see http://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
# issues: dkpt cannot deal with fragmentation at TCP level - just single packets
# 	this means headers may not be parsed correctly if they exceed the default MTU size

import sys
import dpkt
from urlparse import urlparse
from mimetools import Message
from StringIO import StringIO

class HTTPMsg():
	def __init__(self, text, totalSize):
		self.totalSize = totalSize
		head, body = text.split('\r\n\r\n', 1)
		top_line, headers_alone = head.split('\r\n', 1)
		self.methodStr = top_line
		# headers is a dict
		self.headers = Message(StringIO(headers_alone))
		self.headersSize = len(headers_alone); # ASCII, so 1 byte per char
		self.body = body # UTF-8 most likely...
		self.bodySize = totalSize - self.headersSize
	def isGet(self):
		return self.methodStr.startswith("GET")
	def isPost(self):
		return self.methodStr.startswith("POST")
	def isOk(self):
		return self.methodStr.split()[1] == "200"
	def isSwitch(self):
		return self.methodStr.split()[1] == "101"

if len(sys.argv) != 2:
	print "Usage: pcapcategorize <path to pcap file>"
	sys.exit(1)

# open the file
f = open(sys.argv[1], "rb")
# TODO check that the file is in the right format
# convert to pcap: editcap -F libpcap test.pcapng test.pcap

pcap = dpkt.pcap.Reader(f)

baseDone = False
handshakeDone = False
messagesDone = False
retransmitReq = False

trans = None
# length in bytes
messagesTotalBytes = 0
handshakeBytes = 0
httpHeaderOverheadBytes = 0
pollRetransmissions = 0
pollRetransmissionBytes = 0
totalOverheadBytes = 0

num = 0

# loop through each (timestamp, buffer) pair in the pcap file
for ts, buf in pcap:
	num+=1;
	print num, len(buf)
	# parse packet into python objects
	eth = dpkt.ethernet.Ethernet(buf)

	if eth.type != dpkt.ethernet.ETH_TYPE_IP:
		print "ERROR: not ip packet"
		continue

	ip = eth.data

	if not hasattr(ip, 'tcp'):
		print "ERROR: not tcp packet " + str(ip.__dict__)
		continue

	tcp = ip.tcp # also stored in ip.data

	# find first HTTP request for /socket.io/1/
	# if it is websocket then we should see an 'upgrade' header too
	if not baseDone:
		try:
			http = dpkt.http.Request(tcp.data)
		except dpkt.UnpackError:
			#print "not http packet"
			#print "(packet ignored)"
			continue
		#print "http:"
		#print http.__dict__
		path = urlparse(http.uri).path
		if path.startswith("/socket.io/1/") and not path.endswith("socket.io/1/"): # socket.io/1/ is always the server
			path = path[13:]
			slashLoc = path.find("/")
			trans = path[:slashLoc]
			if trans != 'websocket' and trans != 'xhr-polling':
				print "ERROR: unknown transport type found: '" + trans +"'"
				sys.exit(1)
			isWebsocket = True if trans == 'websocket' else False
			#print "Transport: " + trans
			baseDone = True

			messagesTotalBytes += len(tcp)
			httpmsg = HTTPMsg(tcp.data, len(tcp))
			if isWebsocket:
				#print "handshake req: "+str(tcp.data)
				handshakeBytes += httpmsg.headersSize
			else:
				httpHeaderOverheadBytes += httpmsg.headersSize
		# if (not baseDone):
		# 	print "(packet ignored)"
		continue # only proceed past here if we are going to the next part

	if messagesDone:
		continue


	# socket.io connection established
	messagesTotalBytes += len(tcp)

	# XHR and websocket transports diverge at this point...
	if isWebsocket:
		if not handshakeDone:
			# find response to handshake
			try:
				http = HTTPMsg(tcp.data, len(tcp))
			except Exception:
				continue
			if (http.isSwitch()):
				#print "handshake resp: "+tcp.data
				http = HTTPMsg(tcp.data, len(tcp))
				handshakeBytes += http.headersSize
				handshakeDone = True
			else:
				print "ERROR: handshake response is not a 101 "+http.methodStr
				sys.exit(1)
		else:
			# no more HTTP at this point...
			if (len(tcp.data) > 0):
				print "tcp.data:"
				print tcp.data
				if tcp.data.endswith("0::"):
					# disconnection message
					messagesDone = True
					print "messagesDone = True"
	else: # xhr-polling:
		# try:
		# 	# only works for GET requests...
		# 	http = dpkt.http.Request(tcp.data)
		# 	print "http:"
		# 	print http.__dict__
		# 	print "http.data:"
		# 	print http.data
		# 	continue
		# except dpkt.UnpackError:

		# try and parse as a HTTP packet manually
		try:
			http = HTTPMsg(tcp.data, len(tcp))
		except Exception:
			# not HTTP
			if len(tcp.data) > 0:
				print "??tcp.data:"
				print tcp.data
				if tcp.data.endswith("0::"):
					# disconnection message
					messagesDone = True
					print "messagesDone = True"
			continue
		# check if this is a retransmission due to timeout
		# if body == "8::" then this is a NOOP
		# which means that the last request timed out, so:
		# - pollRetransmissions += 1
		# - count this response as overhead
		# - count the next request as overhead (since we didn't count the first one)
		# once we get a body != "8::" then we are no longer getting a NOOP
		# and thus it is not overhead anymore
		if retransmitReq and http.isGet():
			print "This request is a retransmission"
			pollRetransmissionBytes += len(tcp)
			retransmitReq = False
			continue
		
		if http.isOk() and http.body == "8::":
			print "This response is a NOOP"
			pollRetransmissions += 1
			pollRetransmissionBytes += len(tcp)
			retransmitReq = True
			continue


		# add the bytes to the running totals
		httpHeaderOverheadBytes += http.headersSize
		if http.isPost() and http.body.startswith("0"):
			# disconnection message
			messagesDone = True
			print "messagesDone = True"
		continue

f.close()
print
print "Done - processed "+str(num)+" packets."
print "Transport: "+trans
print "Total number of bytes (excluding base page): "+str(messagesTotalBytes)+" bytes"
print "Total amount of overhead just due to HTTP headers: "+str(httpHeaderOverheadBytes)+" bytes"
print "Total amount of overhead used in websocket upgrade: "+str(handshakeBytes)+" bytes"
print "Number of XHR poll timeout/retransmissions: "+str(pollRetransmissions)
print "Amount of overhead just due to XHR poll retransmissions: "+str(pollRetransmissionBytes)+" bytes"
totalOverheadBytes = httpHeaderOverheadBytes + handshakeBytes + pollRetransmissionBytes
print "Percentage of overhead total: "+str((float(totalOverheadBytes) / float(messagesTotalBytes)) * 100) + "%"