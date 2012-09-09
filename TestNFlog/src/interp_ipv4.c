/*
 * interp_ipv4.c
 *
 *  Created on: 09/set/2012
 *      Author: meltingshell
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <jni.h>
#include <strings.h>
#include "interp_ipv4.h"
#include "javaPacketUtils.h"

static jobject* interp_unknown(javaRef* javaRef, char *transh, u_int32_t len) {
	jbyteArray tmp = (*javaRef->env)->NewByteArray(javaRef->env, len);

	jbyte toCopy[len];

	int i;
	for (i = 0; i < len; i++) {
		toCopy[i] = transh[i];
	}

	(*javaRef->env)->SetByteArrayRegion(javaRef->env, tmp, 0, len, toCopy);

	jobject* packet = newPacket(javaRef, "unknownIPv4");

	jclass retPacketCls = (*javaRef->env)->GetObjectClass(javaRef->env,
			*packet);
	jmethodID rawMethod = (*javaRef->env)->GetMethodID(javaRef->env,
			retPacketCls, "setRawHeader", "([B)V");

	(*javaRef->env)->CallVoidMethod(javaRef->env, *packet, rawMethod, tmp);
	return packet;
}

static jobject* interp_tcp(javaRef* javaRef, struct tcphdr *tcph, u_int32_t len) {
	if (len < sizeof(struct tcphdr)) {
		printf("Invalid tcp header.");
	}

	jobject* packet = newPacket(javaRef, "tcp");

	char tmp[512];

	sprintf(tmp, "%u", ntohs(tcph->source));
	setField(javaRef, packet, "spt", tmp);
	sprintf(tmp, "%u", ntohs(tcph->dest));
	setField(javaRef, packet, "dpt", tmp);
	sprintf(tmp, "%u", ntohl(tcph->seq));
	setField(javaRef, packet, "seq", tmp);
	sprintf(tmp, "%u", ntohl(tcph->ack_seq));
	setField(javaRef, packet, "ack", tmp);
	sprintf(tmp, "%u", ntohs(tcph->window));
	setField(javaRef, packet, "win", tmp);
	sprintf(tmp, "%u", tcph->check);
	setField(javaRef, packet, "tcp_sum", tmp);

	if (tcph->urg) {
		setField(javaRef, packet, "urpF", "1");
		sprintf(tmp, "%u", ntohs(tcph->urg_ptr));
		setField(javaRef, packet, "urgp", tmp);
	}
	if (tcph->ack)
		setField(javaRef, packet, "ackF", "1");
	if (tcph->psh)
		setField(javaRef, packet, "pshF", "1");
	if (tcph->rst)
		setField(javaRef, packet, "rstF", "1");
	if (tcph->syn)
		setField(javaRef, packet, "synF", "1");
	if (tcph->fin)
		setField(javaRef, packet, "finF", "1");

	return packet;
}

static jobject* interp_udp(javaRef* javaRef, struct udphdr *udph, u_int32_t len) {
	if (len < sizeof(struct udphdr)) {
		printf("Invalid udp header.");
	}

	jobject* packet = newPacket(javaRef, "udp");

	char tmp[512];
	sprintf(tmp, "%u", ntohs(udph->source));
	setField(javaRef, packet, "spt", tmp);
	sprintf(tmp, "%u", ntohs(udph->dest));
	setField(javaRef, packet, "dpt", tmp);
	sprintf(tmp, "%u", ntohs(udph->len));
	setField(javaRef, packet, "udp_len", tmp);
	sprintf(tmp, "%u", udph->check);
	setField(javaRef, packet, "udp_sum", tmp);

	return packet;
}

static jobject* interp_icmp(javaRef* javaRef, struct icmphdr *icmph,
		u_int32_t len) {
	if (len < sizeof(struct icmphdr)) {
		printf("Invalid icmp header.");
	}

	jobject* packet = newPacket(javaRef, "icmp");

	char tmp[512];

	sprintf(tmp, "%u", icmph->type);
	setField(javaRef, packet, "type", tmp);
	sprintf(tmp, "%u", icmph->code);
	setField(javaRef, packet, "code", tmp);

	char tmpAddr[INET_ADDRSTRLEN];
	u_int32_t paddr;
	switch (icmph->type) {
	case ICMP_ECHO:
	case ICMP_ECHOREPLY:
		sprintf(tmp, "%u", ntohs(icmph->un.echo.id));
		setField(javaRef, packet, "echo_id", tmp);
		sprintf(tmp, "%u", ntohs(icmph->un.echo.sequence));
		setField(javaRef, packet, "echo_seq", tmp);
		break;
	case ICMP_REDIRECT:
	case ICMP_PARAMETERPROB:
		paddr = ntohl(icmph->un.gateway);
		sprintf(tmp, "%s",
				(char *) inet_ntop(AF_INET, &paddr, tmpAddr, sizeof(tmpAddr)));
		setField(javaRef, packet, "gateway", tmp);
		break;
	case ICMP_DEST_UNREACH:
		if (icmph->code == ICMP_FRAG_NEEDED) {
			sprintf(tmp, "%u", ntohs(icmph->un.frag.mtu));
			setField(javaRef, packet, "mtu", tmp);
		}
		break;
	}

	sprintf(tmp, "%u", icmph->checksum);
	setField(javaRef, packet, "icmp_sum", tmp);

	return packet;
}

static jobject* interp_igmp(javaRef* javaRef, struct igmp * igmph,
		u_int32_t len) {
	if (len < sizeof(struct igmp)) {
		printf("Invalid igmp header.");
	}

	jobject* packet = newPacket(javaRef, "igmp");

	char tmp[512];

	sprintf(tmp, "%u", igmph->igmp_type);
	setField(javaRef, packet, "type", tmp);
	sprintf(tmp, "%u", igmph->igmp_code);
	setField(javaRef, packet, "code", tmp);
	setField(javaRef, packet, "group",
			(char *) inet_ntop(AF_INET, &igmph->igmp_group, tmp,
					sizeof(struct in_addr)));

	return packet;
}

jobject* interp_IPv4(javaRef* javaRef, void *payload, u_int32_t len) {

	struct iphdr *iph = (struct iphdr *) payload;
	u_int32_t iphLen = iph->ihl * 4;

	if (len < sizeof(struct iphdr) || len <= (u_int32_t) iphLen) {
		printf("Invalid ip header.");
	}

	void* transportPayload = payload + iphLen;
	len -= iphLen;

	jobject* packet;
	switch (iph->protocol) {
	case IPPROTO_TCP:
		packet = interp_tcp(javaRef, transportPayload, len);
		break;
	case IPPROTO_UDP:
		packet = interp_udp(javaRef, transportPayload, len);
		break;
	case IPPROTO_ICMP:
		packet = interp_icmp(javaRef, transportPayload, len);
		break;
	case IPPROTO_IGMP:
		packet = interp_igmp(javaRef, transportPayload, len);
		break;
	default:
		packet = interp_unknown(javaRef, transportPayload, len);
		break;
	}

	char tmp[512];

	inet_ntop(AF_INET, &iph->saddr, tmp, sizeof(tmp));
	setField(javaRef, packet, "saddr", tmp);

	inet_ntop(AF_INET, &iph->daddr, tmp, sizeof(tmp));
	setField(javaRef, packet, "daddr", tmp);

	sprintf(tmp, "%u", iph->ttl);
	setField(javaRef, packet, "ttl", tmp);

	sprintf(tmp, "%02X", iph->tos & IPTOS_TOS_MASK);
	setField(javaRef, packet, "tos", tmp);

	sprintf(tmp, "0x%02X", iph->tos & IPTOS_PREC_MASK);
	setField(javaRef, packet, "prec", tmp);

	u_int16_t fragOff = ntohs(iph->frag_off);

	if (fragOff & IP_RF)
		setField(javaRef, packet, "rf", "1");

	if (fragOff & IP_DF)
		setField(javaRef, packet, "df", "1");

	if (fragOff & IP_MF)
		setField(javaRef, packet, "mf", "1");

	if (fragOff & IP_OFFMASK) {
		sprintf(tmp, "%u", fragOff & IP_OFFMASK);
		setField(javaRef, packet, "frag", tmp);
	}

	return packet;
}
