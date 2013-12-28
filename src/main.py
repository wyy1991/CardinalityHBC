#!/usr/bin/python python
# -*- coding: utf-8 -*-

import select
import socket
import sys

#---------class HCB start---------------------------------------
class HBC:
    host = ''
    port = 50000
    backlog = 5
    size = 1024

    # create socket
    netsocket = None
    try:
        netsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        netsocket.bind((host,port))
        print netsocket.getsockname()
    except socket.error, (code,message):
        if netsocket:
            netsocket.close()
            print "Could not open socket: " + message
            sys.exit(1)
    
    # loop through sockets
    input = [netsocket,sys.stdin]
    running = True

    while running:
        inputready,outputready,exceptready = select.select(input,[],[])
        for s in inputready:

            if s == netsocket:
                # handle the server socket
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
                    print "input:" + textin
                    #netsocket.sendto(textin,(host,port)) 
               
            
    # close server socket
    netsocket.close()
    sys.stdout.write("netsocket closed.")
    
    
    
    def f(self):
        return 'hello world'

#---------class HCB end---------------------------------------
    
    


#--------main function-----------------------------------------------------
def main():
    status = 0
    hbc = HBC()

    
#-------main------------------------------------------------------
if __name__ == '__main__':
    main()