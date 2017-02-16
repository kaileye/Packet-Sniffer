package packetsniffer;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class PacketSniffer {

    /**
     * Main startup method
     *
     * @param args ignored
     */
    public static void main(String[] args) {
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
        StringBuilder errbuf = new StringBuilder(); // For any error msgs  

        /**
         * *************************************************************************
         * First get a list of devices on this system 
             *************************************************************************
         */
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf
                    .toString());
            return;
        }

        System.out.println("Network devices found:");

        int i = 0;
        for (PcapIf device : alldevs) {
            String description
                    = (device.getDescription() != null) ? device.getDescription()
                    : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }

        System.out.println("Choose one device from the above list");
        int ch = -1;
        while (ch < 0 || ch >= alldevs.size()) {
            ch = new Scanner(System.in).nextInt();
        }
        PcapIf device = alldevs.get(ch);

        System.out
                .printf("\nListening to '%s' :\n",
                        (device.getDescription() != null) ? device.getDescription()
                        : device.getName());

        /**
         * *************************************************************************
         * Second we open up the selected device 
             *************************************************************************
         */
        int snaplen = 64 * 1024;           // Capture all packets, no truncation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000;           // 10 seconds
        Pcap pcap
                = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }
        /**
         * *************************************************************************
         * Third we create a packet handler which will receive packets from the
         * libpcap loop. 
             *************************************************************************
         */
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            public void nextPacket(PcapPacket packet, String user) {
                Udp udp = new Udp();
                if (!packet.hasHeader(udp)) {
                    return;
                }
                System.out.println(packet.toString()); //Uncomment this to cheat (Also great way to check if you're doing it right)

                /**
                 * ****************************FRAME*********************************************
                 */
                System.out.println("\n---------Frame---------");
                System.out.printf("Arrival time: %s\nWire Length: %-4d\nCaptured Length: %-4d\n",
                        new Date(packet.getCaptureHeader().timestampInMillis()),
                        packet.getCaptureHeader().wirelen(), // Original length  
                        packet.getCaptureHeader().caplen() // Length actually captured  
                );

                int size = packet.size();
                int x = 0; // The current byte pointer

                /**
                 * ******************************ETHERNET***************************************
                 */
                //http://www.comptechdoc.org/independent/networking/guide/ethernetdata.gif
                System.out.println("\n---------Ethernet---------");
                System.out.printf("Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(x), packet.getUByte(++x),
                        packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x));
                System.out.printf("Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(++x), packet.getUByte(++x),
                        packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x));
                int ethernetType = packet.getUShort(++x); // 12th byte
                if (ethernetType == 2048) {
                    System.out.printf("EtherType: 0x%x [IPv4]\n", ethernetType);
                } else if (ethernetType == 34525) {
                    System.out.printf("EtherType: 0x%x [IPv6]\n", ethernetType);
                } else {
                    System.out.printf("EtherType: 0x%x [Other]\n", ethernetType);
                }
                x++;
                /**
                 * *****************************Internet Protocol***********************************
                 */
                //http://www.diablotin.com/librairie/networking/puis/figs/puis_1603.gif
                System.out.println("\n---------Internet Protocol---------"); //IPv6 not handled (not even sure many sites use IPv6)
                int version = packet.getUByte(++x) >> 4;
                int protocolType = 0;
                System.out.printf("Version: %d\n", version);
                if (version == 4) { //IPv4
                    System.out.printf("Header Length: %d\n", (packet.getUByte(x) >> 4) * (packet.getUByte(x) & 15));
                    System.out.printf("Differentiated Services Field: %d\n", packet.getUByte(++x));
                    System.out.printf("Total Length: %d\n", ((packet.getUByte(++x) << 8) | packet.getUByte(++x)));
                    System.out.printf("Identification: 0x%x (%d)\n", ((packet.getUByte(++x) << 8) | packet.getUByte(++x)), ((packet.getUByte(--x) << 8) | packet.getUByte(++x)));
                    System.out.printf("Flags: 0x%x\n", packet.getUByte(++x) >> 5);
                    System.out.printf("Fragment offset: %d\n", ((packet.getUByte(x) & 31) << 8) | packet.getUByte(++x));
                    System.out.printf("Time to live: %d\n", packet.getUByte(++x));
                    protocolType = packet.getUByte(++x);
                    System.out.printf("Protocol: %d", protocolType);
                    if (protocolType == 6) {
                        System.out.printf(" (TCP)\n");
                    } else if (protocolType == 17) {
                        System.out.printf(" (UDP)\n");
                    }
                    System.out.printf("Checksum: %d\n", ((packet.getUByte(++x) << 8) | packet.getUByte(++x)));
                    System.out.printf("Source IP: %d.%d.%d.%d\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x));
                    System.out.printf("Destination IP: %d.%d.%d.%d\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x));
                }
                if (version == 6) { //IPv6
                    System.out.printf("Traffic Class: %d\n", (packet.getUByte(x) & 15) << 4 | packet.getUByte(++x) >> 4);
                    System.out.printf("Flow Label: %d\n", (packet.getUByte(x) & 15) << 12 | packet.getUByte(++x) << 8 | packet.getUByte(++x));
                    System.out.printf("Payload Length: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));
                    protocolType = packet.getUByte(++x);
                    System.out.printf("Next Header: %d", protocolType);
                    if (protocolType == 6) {
                        System.out.printf(" (TCP)\n");
                    } else if (protocolType == 17) {
                        System.out.printf(" (UDP)\n");
                    } else {
                        System.out.printf("\n");
                    }
                    System.out.printf("Hop Limit: %d\n", packet.getUByte(++x));
                    System.out.printf("Source IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n", packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
                            packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
                            packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
                            packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x));
                    System.out.printf("Destination IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n", packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
                            packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
                            packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
                            packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x));

                }
                /**
                 * *****************************Transport Layer***********************************
                 */
                boolean port53 = false;
                if (protocolType == 6) {//TCP
                    System.out.println("\n---------Transmission Control Protocol---------");
                    System.out.printf("Source Port: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));
                    System.out.printf("Destination Port: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));
                    byte input[] = new byte[8];
                    for (int i = 0; i < 4; i++) {
                        input[i] = 0;
                    }
                    for (int i = 4; i < 8; i++) {
                        input[i] = (byte) (packet.getUByte(++x));
                    }
                    BigInteger unsigned = new BigInteger(input);
                    System.out.printf("Sequence Number: %d\n", unsigned);
                    for (int i = 4; i < 8; i++) {
                        input[i] = (byte) (packet.getUByte(++x));
                    }
                    unsigned = new BigInteger(input);
                    System.out.printf("Acknowledge Number: %d\n", unsigned);
                    System.out.printf("Data Offset: %d\n", packet.getUByte(++x) >> 4);
                    System.out.printf("Reserved: %d\n", (packet.getUByte(x) & 15) >> 1);
                    System.out.printf("Flags: %d\n", (packet.getUByte(x) & 1) << 8 | packet.getUByte(++x));
                    System.out.printf("Window Size: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));
                    System.out.printf("Checksum: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));
                    System.out.printf("Urgent Pointer: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));

                } else if (protocolType == 17) {//UDP
                    System.out.println("\n---------User Datagram Protocol---------");
                    int tempPort = packet.getUByte(++x) << 8 | packet.getUByte(++x);
                    System.out.printf("Source Port: %d\n", tempPort);
                    if (tempPort == 53) {
                        port53 = true;
                    }
                    tempPort = packet.getUByte(++x) << 8 | packet.getUByte(++x);
                    if (tempPort == 53) {
                        port53 = true;
                    }
                    System.out.printf("Destination Port: %d\n", tempPort);
                    System.out.printf("Length: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));
                    System.out.printf("Checksum: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));
                }
                System.out.println("\n---------Application Layer---------");
                /**
                 * *****************************Application Layer***********************************
                 */
                //Checks for HTTP or DNS Packet or other packet.
                /**
                 * *********************************************************************************
                 */
                //Uncomment this if you want it to print(see) every Byte of the packet
                x++;//move pointer to start of Application Layer
                byte s[] = new byte[5];
                for (int i = x; i < x + 5; i++) {
                    if ((i) >= size) {
                        break;
                    }
                    s[i - x] = (byte) packet.getUByte(i);
                }
                String s2 = new String(s);
                if (s2.contains("HTTP")) {
                    System.out.printf("RequestVersion: ");
                    for (int i = x; i < size; i++) {
                        if ((byte) packet.getUByte(i) == ' ') {
                            x++;
                            break;
                        }
                        System.out.print((char) packet.getUByte(i));
                        x++;
                    }
                    System.out.printf("\nResponseCode: ");
                    for (int i = x; i < size; i++) {
                        if ((byte) packet.getUByte(i) == ' ') {
                            x++;
                            break;
                        }
                        System.out.print((char) packet.getUByte(i));
                        x++;
                    }
                    System.out.printf("\nResponseCodeMsg: ");
                    for (int i = x; i < size; i++) {
                        if ((byte) packet.getUByte(i) == ' ') {
                            x++;
                            break;
                        }
                        System.out.print((char) packet.getUByte(i));
                        x++;
                    }
                    while (x <= size) {
                        x += printNextString(x, size, packet);
                    }
                } else if (s2.contains("GET") || s2.contains("POST")) {
                    System.out.printf("RequestMethod: ");
                    for (int i = x; i < size; i++) {
                        if ((byte) packet.getUByte(i) == ' ') {
                            x++;
                            break;
                        }
                        System.out.print((char) packet.getUByte(i));
                        x++;
                    }
                    System.out.printf("\nRequestURL: ");
                    for (int i = x; i < size; i++) {
                        if ((byte) packet.getUByte(i) == ' ') {
                            x++;
                            break;
                        }
                        System.out.print((char) packet.getUByte(i));
                        x++;
                    }
                    System.out.printf("\nRequestVersion: ");
                    for (int i = x; i < size; i++) {
                        if ((byte) packet.getUByte(i) == ' ') {
                            x++;
                            break;
                        }
                        System.out.print((char) packet.getUByte(i));
                        x++;
                    }
                    while (x <= size) {
                        x += printNextString(x, size, packet);
                    }
                } else if (protocolType == 17 && port53 == true) {//UDP
                    //http://stackoverflow.com/questions/7565300/identifying-dns-packets
                    int i = x;
                    //Check if it's DNS
                    int id = (packet.getUByte(i) << 8) | packet.getUByte(++i);
                    int qr = packet.getUByte(++i) >> 7;//qr is 8th bit //Set to 0 when the query is generated; changed to 1 when that query is changed to a response by a replying server.
                    int opCode = (packet.getUByte(i) >> 3) & 15;//opCode is bits 4-7
                    //Flags
                    int aa = (packet.getUByte(i) % 4) >> 2; //aa is bit 3
                    int tc = (packet.getUByte(i) % 2) >> 1; //tc is bit 2
                    int rd = (packet.getUByte(i)) & 1; //rd is bit 1
                    int ra = (packet.getUByte(++i) >> 7);
                    int zero = (packet.getUByte(i) >> 4) & 7; //padding
                    int responseCode = (packet.getUByte(i) & 15);
                    int qdCount = (packet.getUByte(++i) << 8) | packet.getUByte(++i);
                    if (qdCount == 1 && zero == 0) { //Must be 0 for DNS
                        int anCount = (packet.getUByte(++i) << 8) | packet.getUByte(++i);
                        int nsCount = (packet.getUByte(++i) << 8) | packet.getUByte(++i);
                        int arCount = (packet.getUByte(++i) << 8) | packet.getUByte(++i);
                        System.out.printf("--------DNS---------\n");
                        System.out.printf("Id: %d\n", id);
                        System.out.printf("Qr: %d\n", qr);
                        System.out.printf("OpCode: %d\n", opCode);
                        System.out.printf("Authoritative Answer Flag: %d\n", aa);
                        System.out.printf("Truncation Flag: %d\n", tc);
                        System.out.printf("Recursion Desired: %d\n", rd);
                        System.out.printf("RecursionAvailable: %d\n", ra);
                        System.out.printf("ResponseCode: %d\n", responseCode);
                        System.out.printf("QD Count: %d\n", qdCount);
                        System.out.printf("AN Count: %d\n", anCount);
                        System.out.printf("NS Count: %d\n", nsCount);
                        System.out.printf("AR Count: %d\n", arCount);
                        System.out.printf("\nQuery:\n");
                        x += 13;
                        System.out.printf("\nName: ");
                        int xcount = printNextStringDNS(x, size, packet);
                        x += xcount;
                        System.out.printf("[Name Length: %d]\n", xcount - 1);
                        xcount = x - xcount;
                        System.out.printf("Type: %d\n", (packet.getUByte(x) << 8) | packet.getUByte(++x));
                        System.out.printf("Class: %d\n", (packet.getUByte(++x) << 8) | packet.getUByte(++x));
                        if ((x + 1) < size) {
                            System.out.printf("\nAnswer:\n\n");
                            if (packet.getUByte(++x) == 0) {
                                System.out.printf("Name: <Root>\n");
                                x = AuthoritativeNameServer(x, size, packet);
                            } else {
                                int ptr = packet.getUByte(++x);
                                int placeHolder = 0;
                                while ((x + 1) < size) {
                                    if (((packet.getUByte(x + 1) << 8) | packet.getUByte(x + 2)) == 6) {
                                        System.out.printf("Name: ");
                                        printNextStringDNS(placeHolder, size, packet);
                                        x = AuthoritativeNameServer(x, size, packet);
                                        continue;
                                    } else if (ptr == 12) {
                                        System.out.printf("Name: ");
                                        printNextStringDNS(xcount, size, packet);
                                    } else if (ptr == 43) {
                                        System.out.printf("Name: ");
                                        printNextStringDNS(placeHolder, size, packet);
                                    } else {
                                        x++;
                                        while (x < size) {
                                            x += dumpPayload(x, size, packet);
                                        }
                                        break;
                                    }
                                    int type = (packet.getUByte(++x) << 8) | packet.getUByte(++x);
                                    System.out.printf("Type: %d\n", type);
                                    System.out.printf("Class: %d\n", (packet.getUByte(++x) << 8) | packet.getUByte(++x));
                                    byte input[] = new byte[8];
                                    for (int i2 = 0; i2 < 4; i2++) {
                                        input[i2] = 0;
                                    }
                                    for (int i2 = 4; i2 < 8; i2++) {
                                        input[i2] = (byte) (packet.getUByte(++x));
                                    }
                                    BigInteger unsigned = new BigInteger(input);
                                    System.out.printf("Time to Live: %d\n", unsigned);
                                    int dataLength = (packet.getUByte(++x) << 8) | packet.getUByte(++x);
                                    System.out.printf("Data Length: %d\n", dataLength);
                                    if (dataLength < 3) {

                                    } else if (type == 5) {
                                        packet.getUByte(++x);
                                        System.out.printf("CNAME: ");
                                        placeHolder = x + 1;
                                        x += printNextStringDNS(x + 1, size, packet);
                                        System.out.printf("\n");
                                    } else if (type == 28) {
                                        System.out.printf("AAAA Address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x));
                                    } else if (dataLength > 4) {
                                        packet.getUByte(++x);
                                        System.out.printf("Domain Name: ");
                                        placeHolder = x + 1;
                                        x += printNextStringDNS(x + 1, size, packet);
                                        System.out.printf("\n");
                                    } else {
                                        System.out.printf("Address: %d.%d.%d.%d\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x));
                                    }
                                    System.out.printf("\n");
                                    if ((x + 1) < size) {
                                        if (packet.getUByte(++x) == 192) {
                                            ptr = packet.getUByte(++x);
                                        }
                                    }
                                }
                            }
                            //x+=dumpPayload(x,size,packet);
                        }
                    } else {//UDP
                        if (x < size) {
                            //System.out.printf("\n------Payload-------\n");
                        }
                        while (x < size) {
                            x += dumpPayload(x, size, packet);
                        }
                    }
                } else { //TCP
                    if (x + 3 >= size) {
                        return;
                    }
                    if (packet.getUByte(x) == 1 && packet.getUByte(x + 1) == 1 && packet.getUByte(x + 2) == 8 && packet.getUByte(x + 3) == 10) {
                        if (packet.getUByte(x + 12) == 'G' || packet.getUByte(x + 12) == 'P' || packet.getUByte(x + 12) == 'H') {
                            x += 12;
                            while (x < size) {
                                x += printNextString(x, size, packet);
                            }
                        }
                    }
                    while (x < size) {
                        x += dumpPayload(x, size, packet);
                    }
                }

                /*for (int i = x; i < size; i ++) {  
                  	  System.out.printf("%c", packet.getUByte(i));
                  	  if(packet.getUByte(i) == 0){
                  		System.out.printf("\n");
                  	  }
                    }*/
                System.out.println("\n-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.");
            }

            private int AuthoritativeNameServer(int x, int size, PcapPacket packet) {
                try {
                    System.out.printf("Type: %d\n", (packet.getUByte(++x) << 8) | packet.getUByte(++x));
                    System.out.printf("Class: %d\n", (packet.getUByte(++x) << 8) | packet.getUByte(++x));
                    byte input[] = new byte[8];
                    for (int i2 = 0; i2 < 4; i2++) {
                        input[i2] = 0;
                    }
                    for (int i2 = 4; i2 < 8; i2++) {
                        input[i2] = (byte) (packet.getUByte(++x));
                    }
                    BigInteger unsigned = new BigInteger(input);
                    System.out.printf("Time to Live: %d\n", unsigned);
                    System.out.printf("Data Length: %d\n", (packet.getUByte(++x) << 8) | packet.getUByte(++x));
                    System.out.printf("Class: %d\n", (packet.getUByte(++x) << 8) | packet.getUByte(++x));
                    System.out.printf("Primary Name Server: ");
                    x += printNextStringDNS(x, size, packet);
                    x++;
                    System.out.printf("Responsible Authority's Mailbox: ");
                    x += printNextStringDNS(x, size, packet);
                    x--;
                    for (int i2 = 4; i2 < 8; i2++) {
                        input[i2] = (byte) (packet.getUByte(++x));
                    }
                    unsigned = new BigInteger(input);
                    System.out.printf("Serial Number: %d\n", unsigned);
                    for (int i2 = 4; i2 < 8; i2++) {
                        input[i2] = (byte) (packet.getUByte(++x));
                    }
                    unsigned = new BigInteger(input);
                    System.out.printf("Refresh Invterval: %d\n", unsigned);
                    for (int i2 = 4; i2 < 8; i2++) {
                        input[i2] = (byte) (packet.getUByte(++x));
                    }
                    unsigned = new BigInteger(input);
                    System.out.printf("Retry Invterval: %d\n", unsigned);
                    for (int i2 = 4; i2 < 8; i2++) {
                        input[i2] = (byte) (packet.getUByte(++x));
                    }
                    unsigned = new BigInteger(input);
                    System.out.printf("Expire Limit: %d\n", unsigned);
                    for (int i2 = 4; i2 < 8; i2++) {
                        input[i2] = (byte) (packet.getUByte(++x));
                    }
                    unsigned = new BigInteger(input);
                    System.out.printf("Maximum TTL: %d\n", unsigned);
                } catch (Exception e) {
                }
                return x;
            }

            private int printNextString(int x, int size, PcapPacket packet) {
                int incr = 0;
                int i = 0;
                for (i = x; i < size; i++) {
                    if ((byte) packet.getUByte(i) == 10) {
                        System.out.print("\n");
                        try {
                            if ((byte) packet.getUByte(i + 1) == 13) {
                                System.out.print("\n");
                                incr += 3;
                                while (x + incr < size) {
                                    incr += dumpPayload(x + incr, size, packet);
                                }
                            }
                        } catch (java.nio.BufferUnderflowException e) {
                            System.out.print("BufferUnderflowException\n");
                        }
                        incr++;
                        break;
                    }
                    System.out.print((char) packet.getUByte(i));
                    incr++;
                }
                return incr;
            }

            private int printNextStringDNS(int x, int size, PcapPacket packet) {
                int incr = 0;
                for (int i = x; i < size; i++) {
                    //System.out.print(((byte) packet.getUByte(i))+" ");
                    if (((byte) packet.getUByte(i) == 0) || ((byte) packet.getUByte(i) == -64)) {
                        System.out.print("\n");
                        incr++;
                        if ((byte) packet.getUByte(i) == -64) {
                            incr++;
                        }
                        break;
                    }
                    if (packet.getUByte(i) >= 32 && packet.getUByte(i) <= 126) {
                        System.out.print((char) packet.getUByte(i));
                    } else {
                        System.out.print(".");
                    }
                    incr++;
                }
                return incr;
            }

            private int dumpPayload(int x, int size, PcapPacket packet) {
                int incr = 0;
                char asciiChar[] = new char[16];
                char temp;
                boolean isPrinted = false;
                for (int i = x; i < size; i++) {
                    isPrinted = false;
                    System.out.printf("%02x ", packet.getUByte(x + incr));
                    temp = (char) packet.getUByte(x + incr);
                    if (temp >= 32 && temp <= 126) {
                        asciiChar[incr % 16] = temp;
                    } else {
                        asciiChar[incr % 16] = '.';
                    }
                    incr++;
                    if (incr % 4 == 0) {
                        System.out.printf(" ");
                    }
                    if (incr % 16 == 0) {
                        System.out.printf("\t%s\n", new String(asciiChar));
                        isPrinted = true;
                    }
                }
                if (!isPrinted) {
                    System.out.printf("\t%s\n", new String(asciiChar));
                }
                return incr;
            }
        };

        /**
         * *************************************************************************
         * Tells us how many times to Loop jpacketHandler.
             *************************************************************************
         */
        pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "");
        //pcap.loop(10, jpacketHandler, "");  
        /**
         * *************************************************************************
         * Last thing to do is close the pcap handle 
             *************************************************************************
         */
        pcap.close();
    }
}
