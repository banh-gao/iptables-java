/*
 * javaPacketUtils.h
 *
 *  Created on: 09/set/2012
 *      Author: meltingshell
 */

#ifndef JAVAPACKETUTILS_H_
#define JAVAPACKETUTILS_H_

typedef struct javaRef {
	JNIEnv* env;
	jobject object;
	jmethodID notification;
	jmethodID builder;
}__attribute__ ((packed)) javaRef;

javaRef* getNewJavaRef(JNIEnv* env,jobject callerObj);

void setField(javaRef* javaRef, jobject* retPacket, char * field, char * value);

void setHWPacket(javaRef* javaRef, jobject* retPacket, jobject* hwPacket);

jobject* newPacket(javaRef* javaRef, char* transportProto);

jobject* newHWPacket(javaRef* javaRef, char* HWProto);

void notifyPacket(javaRef* javaRef, jobject* packet);

#endif /* JAVAPACKETUTILS_H_ */
