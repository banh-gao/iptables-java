/*
 * interp_link.h
 *
 *  Created on: 09/set/2012
 *      Author: meltingshell
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <jni.h>
#include "javaPacketUtils.h"

#ifndef INTERP_LINK_H_
#define INTERP_LINK_H_

jobject* interp_link(javaRef* javaRef, u_int16_t hwProto, void* payload,
		u_int16_t len);

#endif /* INTERP_LINK_H_ */
