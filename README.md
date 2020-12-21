# ICMP-X - A robust ICMP tunneling transfer application.

## ICMP_Receiver 
Handles multiple clients transmitting encrypted traffic with dynamic key assignment.
ARGS:
("-p", "--Preferred_Path", help = "Path to save output files to.")
("-i", "--Interface", help = "Interface to receieve on.")

## ICMP_Sender
("-p", "--Peer", help = "IP address of receiving host -ex 192.168.1.1")
("-m", "--Mode", help = "Operation mode, 'file' or 'stream'. Defaults to file.") 
("-f", "--Filename", help = "File to transfer. Used with 'file' mode.")
("-k", "--Key_Type", help = "dynamic or static")

### This project is still in development and will have more features in the future. Feel free to make pull requests if you have any recommendations or questions.

### Creation of Ben Kangas and Charles Warren

