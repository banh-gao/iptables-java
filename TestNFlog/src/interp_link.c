/*
 * interp_link.c
 *
 *  Created on: 09/set/2012
 *      Author: meltingshell
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <jni.h>
#include "interp_link.h"
#include "javaPacketUtils.h"

static jobject* interp_ether(javaRef* javaRef, struct ethhdr* ethhdr,
		u_int16_t len) {

	jobject* hwPacket = newHWPacket(javaRef, "eth4");

	char tmp[512];

	//FIXME: resolve seg fault when accessing hw address
	return NULL;

	sprintf(tmp, "%02x", ethhdr->h_source[0]);
	int i;
	for (i = 1; i < 6; i++)
		sprintf(tmp + strlen(tmp), ":%02x", ethhdr->h_source[i]);
	setField(javaRef, hwPacket, "srcMac", tmp);

	sprintf(tmp, "%02x", ethhdr->h_dest[0]);
	for (i = 1; i < 6; i++)
		sprintf(tmp + strlen(tmp), ":%02x", ethhdr->h_dest[i]);
	setField(javaRef, hwPacket, "dstMac", tmp);

	return hwPacket;
}

jobject* interp_link(javaRef* javaRef, u_int16_t hwProto, void* payload,
		u_int16_t len) {

	return interp_ether(javaRef, payload, len);
}
