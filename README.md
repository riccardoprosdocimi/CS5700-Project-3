# Project 3: Raw Sockets

When we first started the project, my teammate and I decided to split our tasks based on 
the sending and receiving sides, as we knew there would have been a sending and a receiving 
socket, each with their own responsibilities. However, when we got to work, we quickly 
realized that this approach was not feasible because the workload was not equally 
distributed. We then decided to create three classes, representing an IP, a TCP, and an 
HTTP packet (called Data), as well as a socket class, handling both the sending and the 
receiving duties. We also delegated all the utility functions to a file called utils, so
that the program's driver (rawhttpget) just contains the main function.

I, Riccardo, worked on the checksum calculation and validation, the Data class, the 
download functionalities, the packing of outgoing packets, the retransmission, the 
congestion control, the port validation, the ordering of packets, the pydocs, and this 
README.

Rohit, my teammate, worked on unpacking and parsing incoming packets, the three-way 
handshake, the handling of the communication with the server (sending packets with the 
correct flags and validating incoming packets, sliding and congestion windows), and the driver.

We both worked on which instance variables and attributes each class should have had and 
how to best deal with bit shifting and flag setting. Moreover, debugging was mostly a team 
effort, but Rohit was more successful than myself at fixing bugs.

There were a myriad of challenges we faced throughout this project, probably too many to 
list them all, so I'll just mention the most noteworthy (the ones we spent the most 
time on). Firstly, we had troubles figuring out why the server was not responding back 
to us after the first syn packet; Rohit then discovered that the parsing of incoming 
packets was incorrect. Secondly, Linux has various firewalls in place, which disrupt the 
correct and predictable communication with the server. Lastly, we had to play around a 
lot with the congestion control to get it right, since it's an overly simplified version 
of the original, as well as chunking to handle its hexadecimal numbers indicating the 
chunk size.
