#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iso646.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnet.h>
#include <string>
#include <libnetfilter_queue/libnetfilter_queue.h>

std::string http_methods[9] = {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};
std::string filter_host_prefix = "Host: ";
std::string target_host;

static unsigned int extract_packet_id(struct nfq_data *data)
{
    struct nfqnl_msg_packet_hdr *header = nfq_get_msg_packet_hdr(data);
    return header ? ntohl(header->packet_id) : 0;
}

static bool inspect_http_host(unsigned char *pkt)
{
    auto *ip_hdr = (struct libnet_ipv4_hdr *)pkt;
    if (ip_hdr->ip_p != IPPROTO_TCP) return false;

    auto *tcp_hdr = (struct libnet_tcp_hdr *)(pkt + ip_hdr->ip_hl * 4);
    const char *payload = (const char *)(pkt + ip_hdr->ip_hl * 4 + tcp_hdr->th_off * 4);

    uint16_t sport = ntohs(tcp_hdr->th_sport);
    uint16_t dport = ntohs(tcp_hdr->th_dport);
    if (sport != 80 and dport != 80) return false;

    bool is_http = false;
    for (const auto &m : http_methods)
        if (strncmp(payload, m.c_str(), m.size()) == 0)
        {
            is_http = true;
            break;
        }
    if (!is_http) return false;

    const char *p = payload;
    while (*p)
    {
        if (strncmp(p, filter_host_prefix.c_str(), filter_host_prefix.size()) == 0)
            return strncmp(p + filter_host_prefix.size(), target_host.c_str(), target_host.size()) == 0;
        ++p;
    }

    return false;
}

static int process_packet(struct nfq_q_handle *qh, struct nfgenmsg *msg,
                          struct nfq_data *nfa, void *param)
{
    unsigned char *pkt = nullptr;
    unsigned int id = extract_packet_id(nfa);
    nfq_get_payload(nfa, &pkt);

    if (pkt and inspect_http_host(pkt))
        return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("syntax : netfilter-test <host>\n");
        printf("sample : netfilter-test test.gilgil.net\n");
        return 1;
    }

    target_host = argv[1];

    struct nfq_handle *handle = nfq_open();
    if (!handle)
    {
        perror("nfq_open failed");
        return 1;
    }

    nfq_unbind_pf(handle, AF_INET);
    if (nfq_bind_pf(handle, AF_INET) < 0)
    {
        perror("nfq_bind_pf failed");
        return 1;
    }

    struct nfq_q_handle *qhandle = nfq_create_queue(handle, 0, &process_packet, nullptr);
    if (!qhandle)
    {
        perror("nfq_create_queue failed");
        return 1;
    }

    if (nfq_set_mode(qhandle, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        perror("nfq_set_mode failed");
        return 1;
    }

    int fd = nfq_fd(handle);
    char buf[4096] __attribute__((aligned));
    while (true)
    {
        int len = recv(fd, buf, sizeof(buf), 0);
        if (len >= 0)
        {
            nfq_handle_packet(handle, buf, len);
            continue;
        }
        if (errno == ENOBUFS)
        {
            fprintf(stderr, "packet loss detected\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    nfq_destroy_queue(qhandle);
    nfq_close(handle);
    return 0;
}
