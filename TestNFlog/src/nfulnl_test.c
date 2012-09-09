#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/netfilter.h>
#include <libnetfilter_log/linux_nfnetlink_log.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <jni.h>
#include "javaPacketUtils.h"

#define BUF_SIZE 4096

static jobject* _interp_iphdr(char*payload, u_int32_t len) {

	struct iphdr *iph = (struct iphdr *) payload;

	if (len < sizeof(struct iphdr) || len <= (u_int32_t) (iph->ihl * 4)) {
		printf("Invalid ip header.");
	}

	len -= iph->ihl * 4;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		printf("TCP");
		break;
	case IPPROTO_UDP:
		printf("UDP");
		break;
	case IPPROTO_ICMP:
		printf("ICMP");
		break;
	case IPPROTO_SCTP:
		printf("SCTP");
		break;
	case IPPROTO_IGMP:
		printf("IGMP");
		break;
	default:
		printf("UNKNOWN");
		break;
	}

	char tmp[512];

	inet_ntop(AF_INET, &iph->saddr, tmp, sizeof(tmp));
	printf(tmp);
	fputc(' ', stdout);
	inet_ntop(AF_INET, &iph->daddr, tmp, sizeof(tmp));
	printf(tmp);

	printf(" %u", iph->ttl);
	printf(" %u", iph->tot_len);
	printf(" %u", iph->id);
	printf(" %u", iph->protocol);
}

static jobject* parsePacket(struct nflog_data *ldata, javaRef* javaRef) {
	struct nfulnl_msg_packet_hdr *ph = nflog_get_msg_packet_hdr(ldata);
	u_int32_t mark = nflog_get_nfmark(ldata);
	u_int32_t indev = nflog_get_indev(ldata);
	u_int32_t outdev = nflog_get_outdev(ldata);
	char *prefix = nflog_get_prefix(ldata);
	char *payload;
	int payload_len = nflog_get_payload(ldata, &payload);

	if (ph) {
		printf("hw_protocol=0x%04x hook=%u ", ntohs(ph->hw_protocol), ph->hook);
	}

	printf("mark=%u ", mark);

	if (indev > 0)
		printf("indev=%u ", indev);

	if (outdev > 0)
		printf("outdev=%u ", outdev);

	if (prefix) {
		printf("prefix=\"%s\" ", prefix);
	}
	if (payload_len >= 0)
		printf("payload_len=%d ", payload_len);

	fputc('\n', stdout);

	return _interp_iphdr(payload, payload_len);
}

static int handlePacket(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
		struct nflog_data *nfa, void *data) {

	javaRef* javaRef = data;

	jobject* packet = parsePacket(nfa, javaRef);

	if (packet == NULL )
		return -1;

	notifyPacket(javaRef, packet);

	return 0;
}

int main(int argc, char **argv) {
	int group = 0;

	struct nflog_handle *nflogHandle = nflog_open();
	if (!nflogHandle) {
		fprintf(stderr, "error during nflog_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_log handler for AF_INET (if any)\n");
	if (nflog_unbind_pf(nflogHandle, AF_INET) < 0) {
		fprintf(stderr, "error nflog_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_log to AF_INET\n");
	if (nflog_bind_pf(nflogHandle, AF_INET) < 0) {
		fprintf(stderr, "error during nflog_bind_pf()\n");
		exit(1);
	}

	struct nflog_g_handle* nflogGroupHandle = nflog_bind_group(nflogHandle,
			group);

	if (!nflogGroupHandle) {
		fprintf(stderr, "no handle for group %d\n", group);
		exit(1);
	}

	if (nflog_set_mode(nflogGroupHandle, NFULNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet copy mode\n");
		exit(1);
	}

	//javaRef* javaRef = (struct javaRef*) malloc(sizeof(struct javaRef));
	//TODO: set java references
	//nflogGroupHandle->data = javaRef;

	nflog_callback_register(nflogGroupHandle, &handlePacket, NULL );

	int fd = nflog_fd(nflogHandle);
	int rv;
	char buf[BUF_SIZE];

	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		nflog_handle_packet(nflogHandle, buf, rv);
	}

	nflog_unbind_group(nflogGroupHandle);
	nflog_close(nflogHandle);

	exit(0);
}
