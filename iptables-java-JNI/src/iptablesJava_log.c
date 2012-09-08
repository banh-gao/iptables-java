/**
 * @package iptablesJava
 * @copyright Copyright (C) 2011 iptablesJava. All rights reserved.
 * @license GNU/GPL, see COPYING file
 * @author "Daniel Zozin <zdenial@gmx.com>"
 *
 *         This file is part of iptablesJava.
 *         iptablesJava is free software: you can redistribute it
 *         and/or modify
 *         it under the terms of the GNU General Public License as published by
 *         the Free Software Foundation, either version 3 of the License, or
 *         (at your option) any later version.
 *         iptablesJava is distributed in the hope that it will be
 *         useful,
 *         but WITHOUT ANY WARRANTY; without even the implied warranty of
 *         MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *         GNU General Public License for more details.
 *
 *         You should have received a copy of the GNU General Public License
 *         along with iptablesJava. If not, see
 *         <http://www.gnu.org/licenses/>.
 *
 *         This code was adapted from the files:
 *         filter/raw2packet/ulogd_raw2packet_BASE.c
 *         util/printpkt.c
 *         of the project ulog2 by (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 *         under the terms of the GNU General Public License version 2
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <strings.h>
#include <jni.h>
#include <libnetfilter_log/libipulog.h>
#include "net_sf_iptablesJava_log_NetFilterLogTask.h"

#define BUFSIZE 2048

int len;
ulog_packet_msg_t* upkt;
unsigned char* buf;
struct ipulog_handle* h;

JNIEnv* env;
jobject obj;

jmethodID notificationMethod;
jmethodID buildMethod;

static void setField(jobject retPacket, char * field, char * value) {
	jclass retPacketCls = (*env)->GetObjectClass(env, retPacket);
	jmethodID setMethod = (*env)->GetMethodID(env, retPacketCls, "setField",
			"(Ljava/lang/String;Ljava/lang/String;)V");
	(*env)->CallVoidMethod(env, retPacket, setMethod,
			(*env)->NewStringUTF(env, field), (*env)->NewStringUTF(env, value));
}

static jobject newPacket(char* protocol) {
	jobject packet = (*env)->CallObjectMethod(env, obj, buildMethod,
			(*env)->NewStringUTF(env, protocol));
	setField(packet, "proto", protocol);
	return packet;
}

static void _interp_unknown(jobject ret, char *transporth, u_int32_t len) {
	jbyteArray tmp = (*env)->NewByteArray(env, len);

	jbyte toCopy[len];

	int i;
	for (i = 0; i < len; i++) {
		toCopy[i] = transporth[i];
	}

	(*env)->SetByteArrayRegion(env, tmp, 0, len, toCopy);

	jclass retPacketCls = (*env)->GetObjectClass(env, ret);
	jmethodID rawMethod = (*env)->GetMethodID(env, retPacketCls, "setRawHeader",
			"([B)V");

	(*env)->CallVoidMethod(env, ret, rawMethod, tmp);
}

static void _interp_tcp(jobject ret, struct tcphdr *tcph, u_int32_t len) {
	if (len < sizeof(struct tcphdr)) {
		ipulog_perror("Invalid tcp header.");
	}

	char tmp[512];

	sprintf(tmp, "%u", ntohs(tcph->source));
	setField(ret, "spt", tmp);
	sprintf(tmp, "%u", ntohs(tcph->dest));
	setField(ret, "dpt", tmp);
	sprintf(tmp, "%u", ntohl(tcph->seq));
	setField(ret, "seq", tmp);
	sprintf(tmp, "%u", ntohl(tcph->ack_seq));
	setField(ret, "ack", tmp);
	sprintf(tmp, "%u", ntohs(tcph->window));
	setField(ret, "win", tmp);
	sprintf(tmp, "%u", tcph->check);
	setField(ret, "tcp_sum", tmp);

	if (tcph->urg) {
		setField(ret, "urpF", "1");
		sprintf(tmp, "%u", ntohs(tcph->urg_ptr));
		setField(ret, "urgp", tmp);
	}
	if (tcph->ack)
		setField(ret, "ackF", "1");
	if (tcph->psh)
		setField(ret, "pshF", "1");
	if (tcph->rst)
		setField(ret, "rstF", "1");
	if (tcph->syn)
		setField(ret, "synF", "1");
	if (tcph->fin)
		setField(ret, "finF", "1");
}

static void _interp_udp(jobject ret, struct udphdr *udph, u_int32_t len) {
	if (len < sizeof(struct udphdr)) {
		ipulog_perror("Invalid udp header.");
	}

	char tmp[512];
	sprintf(tmp, "%u", ntohs(udph->source));
	setField(ret, "spt", tmp);
	sprintf(tmp, "%u", ntohs(udph->dest));
	setField(ret, "dpt", tmp);
	sprintf(tmp, "%u", ntohs(udph->len));
	setField(ret, "udp_len", tmp);
	sprintf(tmp, "%u", udph->check);
	setField(ret, "udp_sum", tmp);
}

static void _interp_icmp(jobject ret, struct icmphdr *icmph, u_int32_t len) {
	if (len < sizeof(struct icmphdr)) {
		ipulog_perror("Invalid icmp header.");
	}

	char tmp[512];

	sprintf(tmp, "%u", icmph->type);
	setField(ret, "type", tmp);
	sprintf(tmp, "%u", icmph->code);
	setField(ret, "code", tmp);

	char tmpAddr[INET_ADDRSTRLEN];
	u_int32_t paddr;
	switch (icmph->type) {
	case ICMP_ECHO:
	case ICMP_ECHOREPLY:
		sprintf(tmp, "%u", ntohs(icmph->un.echo.id));
		setField(ret, "echo_id", tmp);
		sprintf(tmp, "%u", ntohs(icmph->un.echo.sequence));
		setField(ret, "echo_seq", tmp);
		break;
	case ICMP_REDIRECT:
	case ICMP_PARAMETERPROB:
		paddr = ntohl(icmph->un.gateway);
		sprintf(tmp, "%s",
				(char *) inet_ntop(AF_INET, &paddr, tmpAddr, sizeof(tmpAddr)));
		setField(ret, "gateway", tmp);
		break;
	case ICMP_DEST_UNREACH:
		if (icmph->code == ICMP_FRAG_NEEDED) {
			sprintf(tmp, "%u", ntohs(icmph->un.frag.mtu));
			setField(ret, "mtu", tmp);
		}
		break;
	}

	sprintf(tmp, "%u", icmph->checksum);
	setField(ret, "icmp_sum", tmp);
}

static void _interp_igmp(jobject ret, struct igmp * igmph, u_int32_t len) {
	if (len < sizeof(struct igmp)) {
		ipulog_perror("Invalid igmp header.");
	}

	char tmp[512];

	sprintf(tmp, "%u", igmph->igmp_type);
	setField(ret, "type", tmp);
	sprintf(tmp, "%u", igmph->igmp_code);
	setField(ret, "code", tmp);
	setField(ret, "group",
			(char *) inet_ntop(AF_INET, &igmph->igmp_group, tmp,
					sizeof(struct in_addr)));
}

static void _interp_icmpv6(jobject ret, struct icmp6_hdr *icmph, u_int32_t len) {

	if (len < sizeof(struct icmp6_hdr)) {
		ipulog_perror("Invalid icmp6 header.");
	}

	char tmp[512];

	sprintf(tmp, "%u", icmph->icmp6_type);
	setField(ret, "type", tmp);
	sprintf(tmp, "%u", icmph->icmp6_code);
	setField(ret, "code", tmp);

	switch (icmph->icmp6_type) {
	case ICMP6_ECHO_REQUEST:
	case ICMP6_ECHO_REPLY:
		sprintf(tmp, "%u", ntohs(icmph->icmp6_id));
		setField(ret, "echo_id", tmp);
		sprintf(tmp, "%u", ntohs(icmph->icmp6_seq));
		setField(ret, "echo_seq", tmp);
		break;
	}

	sprintf(tmp, "%u", icmph->icmp6_cksum);
	setField(ret, "icmpv6_sum", tmp);
}

typedef struct sctphdr {
	__be16 source;
	__be16 dest;
	__be32 vtag;
	__be32 checksum;
}__attribute__((packed)) sctp_sctphdr_t;

static void _interp_sctp(jobject ret, struct sctphdr *sctph, u_int32_t len) {

	if (len < sizeof(struct sctphdr)) {
		ipulog_perror("Invalid sctp header.");
	}

	char tmp[512];

	sprintf(tmp, "%u", ntohs(sctph->source));
	setField(ret, "spt", tmp);
	sprintf(tmp, "%u", ntohs(sctph->dest));
	setField(ret, "dpt", tmp);
	sprintf(tmp, "%u", ntohl(sctph->checksum));
	setField(ret, "sctp_sum", tmp);
}

static int ip6_ext_hdr(u_int8_t nexthdr) {
	switch (nexthdr) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_FRAGMENT:
	case IPPROTO_ESP:
	case IPPROTO_AH:
	case IPPROTO_DSTOPTS:
		return 1;
	default:
		return 0;
	}
}

static jobject _interp_ipv6hdr(ulog_packet_msg_t *pkt, u_int32_t len) {
	struct ip6_hdr * ipv6h = (struct ip6_hdr*) pkt->payload;
	unsigned int ptr, hdrlen = 0;
	u_int8_t curhdr;
	int fragment = 0;

	if (len < sizeof(struct ip6_hdr)) {
		ipulog_perror("Invalid ipv6 header.");
	}

	curhdr = ipv6h->ip6_nxt;
	ptr = sizeof(struct ip6_hdr);
	len -= sizeof(struct ip6_hdr);

	jobject ret;

	switch (curhdr) {
	case IPPROTO_TCP:
		ret = newPacket("tcp");
		break;
	case IPPROTO_UDP:
		ret = newPacket("udp");
		break;
	case IPPROTO_ICMPV6:
		ret = newPacket("icmpv6");
		break;
	default:
		ret = newPacket("IPv6unknown");
		break;
	}

	char tmp[512];

	while (curhdr != IPPROTO_NONE && ip6_ext_hdr(curhdr)) {

		struct ip6_ext *ext = (void *) ipv6h + ptr;

		if (len < sizeof(struct ip6_ext))
			return ret;

		switch (curhdr) {
		case IPPROTO_FRAGMENT: {
			struct ip6_frag *fh = (struct ip6_frag *) ext;

			hdrlen = sizeof(struct ip6_frag);
			if (len < hdrlen)
				return ret;
			len -= hdrlen;

			sprintf(tmp, "%u", ntohs(fh->ip6f_offlg & IP6F_OFF_MASK));
			setField(ret, "frag", tmp);

			sprintf(tmp, "%08x", ntohl(fh->ip6f_ident));
			setField(ret, "id", tmp);

			if (ntohs(fh->ip6f_offlg & IP6F_OFF_MASK))
				fragment = 1;
			break;
		}
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_HOPOPTS:
			if (fragment)
				return ret;

			hdrlen = (ext->ip6e_len + 1) << 3;
			if (len < hdrlen)
				return ret;
			len -= hdrlen;
			break;
		case IPPROTO_AH:
			if (fragment)
				return ret;

			hdrlen = (ext->ip6e_len + 2) << 2;
			if (len < hdrlen)
				return ret;
			len -= hdrlen;
			break;
		case IPPROTO_ESP:
			if (fragment)
				return ret;

			hdrlen = (ext->ip6e_len + 2) << 2;
			if (len < hdrlen)
				return ret;
			len -= hdrlen;
			return ret;
		default:
			return ret;
		}

		curhdr = ext->ip6e_nxt;
		ptr += hdrlen;

		switch (curhdr) {
		case IPPROTO_TCP:
			ret = newPacket("tcp");
			break;
		case IPPROTO_UDP:
			ret = newPacket("udp");
			break;
		case IPPROTO_ICMPV6:
			ret = newPacket("icmpv6");
			break;
		default:
			ret = newPacket("IPv6unknown");
			break;
		}
	}

	if (fragment)
		return ret;

	setField(ret, "src", (char *) &ipv6h->ip6_src);
	setField(ret, "dst", (char *) &ipv6h->ip6_dst);

	sprintf(tmp, "%u", ntohs(ipv6h->ip6_plen));
	setField(ret, "tot_len", tmp);

	sprintf(tmp, "%u", ntohl(ipv6h->ip6_flow & 0x0ff00000) >> 20);
	setField(ret, "tc", tmp);

	sprintf(tmp, "%u", ipv6h->ip6_hlim);
	setField(ret, "hoplimit", tmp);

	sprintf(tmp, "%u", ntohl(ipv6h->ip6_flow & 0x000fffff));
	setField(ret, "flowlabel", tmp);
	sprintf(tmp, "%u", curhdr);
	setField(ret, "nexthdr", tmp);

	switch (curhdr) {
	case IPPROTO_TCP:
		_interp_tcp(ret, (void *) ipv6h + ptr, len);
		break;
	case IPPROTO_UDP:
		_interp_udp(ret, (void *) ipv6h + ptr, len);
		break;
	case IPPROTO_ICMPV6:
		_interp_icmpv6(ret, (void *) ipv6h + ptr, len);
		break;

	default:
		_interp_unknown(ret, (void *) ipv6h + ptr, len);
		break;
	}
	return ret;
}

static jobject _interp_arp(ulog_packet_msg_t *pkt, u_int32_t len) {

	const struct ether_arp *arph = (struct ether_arp*) pkt->payload;

	if (len < sizeof(struct ether_arp)) {
		ipulog_perror("Invalid arp header.");
	}

	jobject retPacket = newPacket("arp");

	char tmp[512];

	sprintf(tmp, "%u", ntohs(arph->arp_op));
	setField(retPacket, "opcode", tmp);

	setField(retPacket, "arp_src", (char *) &arph->arp_spa);
	setField(retPacket, "arp_dst", (char *) &arph->arp_tpa);

	u_int8_t * mac = (u_int8_t *) arph->arp_sha;
	sprintf(tmp, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
			mac[3], mac[4], mac[5]);
	setField(retPacket, "arp_hwdst", tmp);

	mac = (u_int8_t *) arph->arp_tha;
	sprintf(tmp, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
			mac[3], mac[4], mac[5]);
	setField(retPacket, "arp_hwdst", tmp);
	return retPacket;
}

static jobject _interp_iphdr(ulog_packet_msg_t *pkt, u_int32_t len) {

	struct iphdr *iph = (struct iphdr *) pkt->payload;

	void *transportHdr = (u_int32_t *) iph + iph->ihl;

	if (len < sizeof(struct iphdr) || len <= (u_int32_t) (iph->ihl * 4)) {
		ipulog_perror("Invalid ip header.");
	}

	len -= iph->ihl * 4;

	jobject retPacket;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		retPacket = newPacket("tcp");
		break;
	case IPPROTO_UDP:
		retPacket = newPacket("udp");
		break;
	case IPPROTO_ICMP:
		retPacket = newPacket("icmp");
		break;
	case IPPROTO_SCTP:
		retPacket = newPacket("sctp");
		break;
	case IPPROTO_IGMP:
		retPacket = newPacket("igmp");
		break;
	default:
		retPacket = newPacket("IPv4unknown");
		break;
	}

	char tmp[512];

	setField(retPacket, "src",
			(char *) inet_ntop(AF_INET, &iph->saddr, tmp, sizeof(tmp)));
	setField(retPacket, "dst",
			(char *) inet_ntop(AF_INET, &iph->daddr, tmp, sizeof(tmp)));

	sprintf(tmp, "%02X", iph->tos & IPTOS_TOS_MASK);
	setField(retPacket, "tos", tmp);
	sprintf(tmp, "0x%02X", iph->tos & IPTOS_PREC_MASK);
	setField(retPacket, "prec", tmp);
	sprintf(tmp, "%u", iph->ttl);
	setField(retPacket, "ttl", tmp);
	sprintf(tmp, "%u", iph->tot_len);
	setField(retPacket, "tot_len", tmp);
	sprintf(tmp, "%u", iph->id);
	setField(retPacket, "id", tmp);
	sprintf(tmp, "%u", iph->protocol);
	setField(retPacket, "transport_proto", tmp);

	u_int16_t fragOff = ntohs(iph->frag_off);

	if (fragOff & IP_RF)
		setField(retPacket, "rf", "1");

	if (fragOff & IP_DF)
		setField(retPacket, "df", "1");

	if (fragOff & IP_MF)
		setField(retPacket, "mf", "1");

	if (fragOff & IP_OFFMASK) {
		sprintf(tmp, "%u", fragOff & IP_OFFMASK);
		setField(retPacket, "frag", tmp);
	}

	switch (iph->protocol) {
	case IPPROTO_TCP:
		_interp_tcp(retPacket, transportHdr, len);
		break;

	case IPPROTO_UDP:
		_interp_udp(retPacket, transportHdr, len);
		break;

	case IPPROTO_ICMP:
		_interp_icmp(retPacket, transportHdr, len);
		break;

	case IPPROTO_SCTP:
		_interp_sctp(retPacket, transportHdr, len);
		break;

	case IPPROTO_IGMP:
		_interp_igmp(retPacket, transportHdr, len);
		break;

	default:
		_interp_unknown(retPacket, transportHdr, len);
		break;
	}
	return retPacket;
}

static jobject _interp_bridge(ulog_packet_msg_t *pkt, u_int32_t len) {

	// TODO: Detect link protocol
	const u_int16_t proto = ETH_P_IP;

	jobject retPacket;

	switch (proto) {
	case ETH_P_IP:
		retPacket = _interp_iphdr(pkt, len);
		break;
	case ETH_P_IPV6:
		retPacket = _interp_ipv6hdr(pkt, len);
		break;
	case ETH_P_ARP:
		retPacket = _interp_arp(pkt, len);
		break;
		/* ETH_P_8021Q ?? others? */
	};

	return retPacket;
}

static jobject _interp_pkt(ulog_packet_msg_t *pkt, u_int32_t len) {
	jobject retPacket;

	//TODO: Detect network protocol
	u_int8_t family = AF_INET;

	switch (family) {
	case AF_INET:
		retPacket = _interp_iphdr(pkt, len);
		break;
	case AF_INET6:
		retPacket = _interp_ipv6hdr(pkt, len);
		break;
	case AF_BRIDGE:
		retPacket = _interp_bridge(pkt, len);
		break;
	}

	char tmp[512];

	sprintf(tmp, "%u", pkt->hook);
	setField(retPacket, "hook", tmp);
	sprintf(tmp, "%lu", pkt->mark);
	setField(retPacket, "mark", tmp);

	setField(retPacket, "inDev", pkt->indev_name);
	setField(retPacket, "outDev", pkt->outdev_name);

	sprintf(tmp, "%ld", pkt->timestamp_sec);
	setField(retPacket, "sec", tmp);

	sprintf(tmp, "%ld", pkt->timestamp_usec);
	setField(retPacket, "usec", tmp);

	if (strlen(pkt->prefix))
		setField(retPacket, "prefix", pkt->prefix);

	if (pkt->mac_len) {
		unsigned char *mac = pkt->mac;
		sprintf(tmp, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
				mac[3], mac[4], mac[5]);
		setField(retPacket, "mac", tmp);
	}

	return retPacket;
}

JNIEXPORT void JNICALL Java_net_sf_iptablesJava_log_NetFilterLogTask_receiveNewPacket(
		JNIEnv * env, jobject obj) {

	unsigned char buf[BUFSIZE];
	len = ipulog_read(h, buf, BUFSIZE, 1);

	if (len <= 0) {
		ipulog_perror("readed packet too short");
		return;
	}

	jobject retPacket;
	while ((upkt = ipulog_get_packet(h, buf, len))) {
		retPacket = _interp_pkt(upkt, len);
		(*env)->CallVoidMethod(env, obj, notificationMethod, retPacket);
	}
}

JNIEXPORT void JNICALL Java_net_sf_iptablesJava_log_NetFilterLogTask_init(
		JNIEnv * javaEnv, jobject javaObj, jint group) {
	env = javaEnv;
	obj = javaObj;
	jclass cls = (*env)->GetObjectClass(env, obj);
	notificationMethod = (*env)->GetMethodID(env, cls, "notifyNewPacket",
			"(Ljava/lang/Object;)V");
	buildMethod = (*env)->GetMethodID(env, cls, "buildNewPacket",
			"(Ljava/lang/String;)Lnet/sf/iptablesJava/log/Packet;");

	/* create ipulog handle */
	h = ipulog_create_handle(ipulog_group2gmask(group), BUFSIZE);
	if (!h) {
		/* if some error occurrs, print it to stderr */
		ipulog_perror(NULL );
		return;
	}
}
