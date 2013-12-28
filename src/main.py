#!/usr/bin/python python
# -*- coding: utf-8 -*-

import select
import socket
import random
import sys

from random import randint

#--------create socket-----------------------------------------------------
def createSocket():
    newsocket = None
    host = ''
    port = 50000 + randint(1,1000)
    size = 1024
    
    # create socket
    try:
        newsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        newsocket.bind((host,port))
        print newsocket.getsockname()
    except socket.error, (code,message):
        if newsocket:
            newsocket.close()
        print "Could not open socket: " + message
        sys.exit(1)
        
    return newsocket

#--------isFirstNode-----------------------------------------------------
def isFirstNode():
    if len(sys.argv) <= 1:
        return False
    elif sys.argv[1] == "first":
        print "This is node One!"
        return True
#--------main function-----------------------------------------------------
def main():
    isNodeOne = isFirstNode()
    netsocket = createSocket()
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
                    netsocket.sendto(textin,(host,port)) 
                   
                
    # close netsocket socket
    netsocket.close()
    sys.stdout.write("netsocket closed.")
#-------main------------------------------------------------------
if __name__ == '__main__':
    main()