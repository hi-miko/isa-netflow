# How to capture packets and process them

`tcpdump -c [count] -i [interface] -w [outfile]` -> simple command to capture *count* packets on the *i* interface and
output them to *outfile*

`nfdump [file from nfpcapd]` -> processes the file from the netflow exporter and outputs it to the terminal

`nfpcapd -r [pcap file] -v -w [output dir]` -> exports the pcap file into the netflow format

`sudo nfpcapd -i [interface] -H [server]/[port]` -> to listen to network data on *interface* and send it to *server*/*pot*

`sudo nfcapd -w [directory] -p [port]` -> to listen to incoming flows on *port* and save them into *directory*
