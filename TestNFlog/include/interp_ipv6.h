/*
 * interp_ipv6.h
 *
 *  Created on: 09/set/2012
 *      Author: meltingshell
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <jni.h>
#include "javaPacketUtils.h"

#ifndef INTERP_IPV6_H_
#define INTERP_IPV6_H_

jobject* interp_IPv6(javaRef* javaRef, void* payload, u_int32_t len);

#endif /* INTERP_IPV6_H_ */
