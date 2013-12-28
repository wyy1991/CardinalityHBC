#!/usr/bin/python python
# -*- coding: utf-8 -*-

import select
import socket
import random
import sys
from urllib import urlopen
import re
from random import randint

#--------create socket-----------------------------------------------------
def createSocket():
    newsocket = None
    host = ''
    port = 50000 + randint(1,1000)

    
    # create socket
    try:
        newsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        newsocket.bind((host,port))
        #print newsocket.getsockname()
    except socket.error, (code,message):
        if newsocket:
            newsocket.close()
        print "Could not open socket: " + message
        sys.exit(1)
        
    return newsocket
#--------getPublicIP-----------------------------------------------------
def getPublicIp():
    data = str(urlopen('http://checkip.dyndns.com/').read())  #@@@ my have problem
    # data = '<html><head><title>Current IP Check</title></head><body>Current IP Address: 65.96.168.198</body></html>\r\n'

    return re.compile(r'Address: (\d+\.\d+\.\d+\.\d+)').search(data).group(1)
#--------isFirstNode-----------------------------------------------------
def isFirstNode():
    if len(sys.argv) <= 1:
        return False
    elif sys.argv[1] == "first":
        print "This is node One!"
        return True
#--------main function-----------------------------------------------------
def main():
    size = 1024
    # create socket
    netsocket = createSocket()
    myip = getPublicIp()
    myport = netsocket.getsockname()[1] 
    print "Address:", myip, ":", myport
    
    # <peer number, address>
    peerDic ={ 0 : [myip, myport] } # key 0, stores my address
    myNodeNum = 0;
    if True == isFirstNode():
        myNodeNum = 1
        peerDic[1] = [myip, myport]
    else:
        # ask for node one address
        waitForFirstNode = True
        while waitForFirstNode:
            print "Please enter address of node one, x.x.x.x:xxxx"
            sys.stdout.write("%")
            addrIn = sys.stdin.readline()
            addrInList = addrIn.rstrip('\n').split(":")
            # check if input valid
            if 2 != len(addrInList):
                print "Invalid address!"
            elif 4 != len(addrInList[0].split(".")):
                print "Invalid ip!"
            else:
                peerDic[1] = [addrInList[0], int(addrInList[1])] 
                # insert the address to peerlist
                waitForFirstNode = False
        # check if this is an valid address
        
        
        
    
    # if not, ask for input of node one address
    # connect to node one, and get node number back
    
    
    # loop through sockets
    input = [netsocket,sys.stdin]
    running = True
    
    while running:
        inputready,outputready,exceptready = select.select(input,[],[])
        
        for s in inputready:
    
            if s == netsocket:
                # handle the netsocket socket
                try:
                    data,address = netsocket.recvfrom(size)
                    print "recieved:" + data
                    netsocket.sendto(data,address)
                    print "send:" + data
                except:
                    running = False
    
            elif s == sys.stdin:
                # handle standard input
                textin = sys.stdin.readline()
                
                if textin == "q\n":
                    running = False
                else:
                    #netsocket.sendto(textin,(host,port)) 
                    running = True
                
    # close netsocket socket
    netsocket.close()
    sys.stdout.write("netsocket closed.")
#-------main------------------------------------------------------
if __name__ == '__main__':
    main()