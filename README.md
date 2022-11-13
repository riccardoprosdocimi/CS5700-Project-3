# Project 3: Raw Sockets

## Team

-   Rohit Awate (awate.r@northeastern.edu)
-   Riccardo Prosdocimi (prosdocimi.r@northeastern.edu)

## High-level Approach

The project is implemented in Python 3. It contains the following components (classes):

-   **IPPacket** & **TCPPacket**: Encapsulates all the header fields, flags and payload data that go into an IPv4 and TCP packet respectively. Provides an API to build a raw packet from the object as well as to parse raw incoming packets into an object. Also performs checksum verfication and calculation.
-   **TCPSocket**: Provides all of the core TCP functionality (more details below). It encapsulates the two underlying read and send raw sockets used for communication. It provides APIs to send and receive packets. Apart from the TCP functionality, it also chooses a random, available port on the OS.
-   **Data**: Class for dealing with all things HTTP. It provides APIs to compose GET requests, parse HTTP responses and to save files to disk.
-   **download.py**: Accepts a URL, sets up a TCPSocket connection, sends a GET request, accepts a response and saves it to disk. `rawhttpget` simply makes a call to this.

## Features Implemented

-   ### IP
    -   Packet parsing + generation
    -   Checksum calculation + verification
    -   Filtering packets based on protocol
-   ### TCP
    -   Packet parsing + generation
    -   Checksum calculation + verification
    -   Filtering packets based on port
    -   3-way handshake
    -   Sliding window using SEQ and ACK numbers
    -   Packet reordering
    -   Discard duplicate packets
    -   Basic congestion control
    -   Timeouts and retransmissions to tackle packet loss
    -   Connection closing
-   ### HTTP
    -   Composition of requests
    -   Parsing responses for headers, status code and body
    -   Decoding of chunked transfer-encoding
    -   Saving responses to disk
    -   Deducing target filenames based on URL

## Who Did What

When we first started the project, my teammate and I decided to split our tasks based on the sending and receiving sides, as we knew there would have been a sending and a receiving socket, each with their own responsibilities. However, when we got to work, we quickly realized that this approach was not feasible because the workload was not equally distributed. We then decided to create three classes, representing an IPPacket, a TCPPacket, and an HTTP packet (called Data), as well as a TCPSocket class, handling both the sending and the receiving duties. We also delegated all the utility functions to a file called utils, so that the program's driver (rawhttpget) just contains the main function.

**Riccardo** worked on:

-   Checksum calculation and validation
-   the Data class, the download functionalities
-   Packing of outgoing packets (both TCP and IP)
-   Retransmission of TCP packets
-   Congestion control
-   Port scanning
-   Re-ordering of packets
-   Pydocs
-   This README

**Rohit** worked on:

-   Unpacking and parsing incoming packets (both TCP and IP)
-   TCPSocket class
-   TCP three-way handshake
-   Filtering received packets (based on IP protocol field and TCP port)
-   Sliding window
-   Sending packets using congestion-control
-   Closing connection
-   Decoding chunked transfer-encoding
-   Driver code

We both worked on the design of each class (deciding what variables and APIs to have) and how to best deal with bit shifting and flag setting. Moreover, debugging was mostly a team effort, but Rohit was more successful than myself at fixing bugs.

## Challenges

There were a myriad of challenges we faced throughout this project, probably too many to list them all, so I'll just mention the most noteworthy (the ones we spent the most time on).

-   We had troubles figuring out why the server was not responding back
    to us after the first SYN packet; Rohit then discovered that the parsing of incoming packets was using incorrect byte offsets.
-   Secondly, Ubuntu has different firewall configurations for Desktop vs Server (what Rohit was using). We learned the hard way that Ubuntu Server's iptable rules were messing up our TCP flows. More details [on this Piazza comment](https://piazza.com/class/l781ljflhl536s/post/220_f1).
-   We had to play around a lot with the congestion control to get it right, since it's an overly simplified version of the original, as well as chunking to handle its hexadecimal numbers indicating the chunk size.
-   We had a bug in our checksum calculation which went largely unnoticed because it messed up just one bit in some cases. This was extremely hard to debug.
