#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bits/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/netfilter.h>
#include "interp_ipv4.h"
#include "interp_ipv6.h"
#include "interp_link.h"
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_log/linux_nfnetlink_log.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <jni.h>
#include "javaPacketUtils.h"
#include "net_sf_iptablesJava_log_NetFilterLogTask.h"

#define BUF_SIZE 4096

static jobject* parsePacket(struct nflog_data *ldata, javaRef* javaRef,
		u_int8_t addrFamily) {
	char *payload;
	int payload_len = nflog_get_payload(ldata, &payload);

	fputc('\n', stdout);

	jobject *packet;
	switch (addrFamily) {
	case AF_INET:
		packet = interp_IPv4(javaRef, payload, payload_len);
		break;
	case AF_INET6:
		packet = interp_IPv6(javaRef, payload, payload_len);
		break;
	default:
		printf("Unhandled network packet of %u address family", addrFamily);
		return NULL ;
	}

	char tmp[512];

	sprintf(tmp, "%u", nflog_get_nfmark(ldata));
	setField(javaRef, packet, "mark", tmp);

	u_int32_t physindev = nflog_get_physindev(ldata);
	if_indextoname(physindev, tmp);
	setField(javaRef, packet, "physindev", tmp);

	u_int32_t indev = nflog_get_indev(ldata);
	if_indextoname(indev, tmp);
	setField(javaRef, packet, "indev", tmp);

	u_int32_t physoutdev = nflog_get_physoutdev(ldata);
	if_indextoname(physoutdev, tmp);
	setField(javaRef, packet, "physoutdev", tmp);

	u_int32_t outdev = nflog_get_outdev(ldata);
	if_indextoname(outdev, tmp);
	setField(javaRef, packet, "outdev", tmp);

	char *prefix = nflog_get_prefix(ldata);
	setField(javaRef, packet, "prefix", prefix);

	u_int32_t* uid = malloc(sizeof(u_int32_t));
	nflog_get_uid(ldata, uid);
	sprintf(tmp, "%u", *uid);
	setField(javaRef, packet, "uid", tmp);
	free(uid);

	u_int32_t* gid = malloc(sizeof(u_int32_t));
	nflog_get_gid(ldata, gid);
	sprintf(tmp, "%u", *gid);
	setField(javaRef, packet, "gid", tmp);
	free(gid);

	/*TODO: correct conversion
	 struct timeval* tv = malloc(sizeof(struct timeval));
	 nflog_get_timestamp(ldata, tv);
	 sprintf(tmp, "%s", tv->tv_sec);
	 setField(javaRef, packet, "seconds", tmp);
	 sprintf(tmp, "%s", tv->tv_usec);
	 setField(javaRef, packet, "useconds", tmp);
	 */

	struct nfulnl_msg_packet_hdr *ph = nflog_get_msg_packet_hdr(ldata);

	char* hook;
	switch (ph->hook) {
	case NF_INET_LOCAL_IN:
		hook = "LOCAL_IN";
		break;
	case NF_INET_LOCAL_OUT:
		hook = "LOCAL_OUT";
		break;
	case NF_INET_FORWARD:
		hook = "FORWARD";
		break;
	case NF_INET_PRE_ROUTING:
		hook = "PRE_ROUTING";
		break;
	case NF_INET_POST_ROUTING:
		hook = "POST_ROUTING";
		break;
	default:
		hook = "";
		break;
	}
	setField(javaRef, packet, "hook", hook);

	return packet;

	//TODO
	char* hwHdr = nflog_get_msg_packet_hwhdr(ldata);
	u_int16_t hwHdrLen = nflog_get_msg_packet_hwhdrlen(ldata);

	jobject* hwPacket = interp_link(javaRef, ph->hw_protocol, hwHdr, hwHdrLen);

	setHWPacket(javaRef, packet, hwPacket);

	return packet;
}

static int handlePacket(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
		struct nflog_data *nfa, void *data) {
	javaRef* javaRef = data;

	jobject* packet = parsePacket(nfa, javaRef, nfmsg->nfgen_family);

	if (packet == NULL )
		return NFNL_CB_CONTINUE;

	notifyPacket(javaRef, packet);

	return NFNL_CB_CONTINUE;
}

JNIEXPORT void JNICALL Java_net_sf_iptablesJava_log_NetFilterLogTask_init(
		JNIEnv * env, jobject callerObj, jint group) {

	struct nflog_handle *nflogHandle = nflog_open();
	if (!nflogHandle) {
		fprintf(stderr, "error during nflog_open()\n");
	}

	printf("unbinding existing nf_log handler for AF_INET (if any)\n");
	if (nflog_unbind_pf(nflogHandle, AF_INET) < 0) {
		fprintf(stderr, "error nflog_unbind_pf()\n");
	}

	printf("binding nfnetlink_log to AF_INET\n");
	if (nflog_bind_pf(nflogHandle, AF_INET) < 0) {
		fprintf(stderr, "error during nflog_bind_pf()\n");
	}

	printf("unbinding existing nf_log handler for AF_INET6 (if any)\n");
	if (nflog_unbind_pf(nflogHandle, AF_INET6) < 0) {
		fprintf(stderr, "error nflog_unbind_pf()\n");
	}

	printf("binding nfnetlink_log to AF_INET6\n");
	if (nflog_bind_pf(nflogHandle, AF_INET6) < 0) {
		fprintf(stderr, "error during nflog_bind_pf()\n");
	}

	struct nflog_g_handle* nflogGroupHandle = nflog_bind_group(nflogHandle,
			group);

	if (!nflogGroupHandle) {
		fprintf(stderr, "no handle for group %d\n", group);
	}

	if (nflog_set_mode(nflogGroupHandle, NFULNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet copy mode\n");
	}

	//javaRef* javaRef = (struct javaRef*) malloc(sizeof(struct javaRef));
	//TODO: set java references
	//nflogGroupHandle->data = javaRef;

	nflog_callback_register(nflogGroupHandle, &handlePacket, NULL );

	int fd = nflog_fd(nflogHandle);
	int rv;
	char buf[BUF_SIZE];

	printf("Start listening\n");
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		nflog_handle_packet(nflogHandle, buf, rv);
	}

	nflog_unbind_group(nflogGroupHandle);
	nflog_close(nflogHandle);
}

int main(int argc, char **argv) {
	Java_net_sf_iptablesJava_log_NetFilterLogTask_init(NULL, NULL, 0);
	exit(0);
}
