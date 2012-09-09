/*
 * javaPacket.c
 *
 *  Created on: 09/set/2012
 *      Author: meltingshell
 */

#include <stdlib.h>
#include <jni.h>
#include <javaPacketUtils.h>

//#define DEBUG 1

javaRef* getNewJavaRef(JNIEnv* env, jobject callerObj) {
	javaRef* ref = (javaRef*) malloc(sizeof(javaRef));

	ref->env = env;
	ref->object = callerObj;

	jclass cls = (*env)->GetObjectClass(env, callerObj);
	ref->notification = (*env)->GetMethodID(env, cls, "notifyNewPacket",
			"(Ljava/lang/Object;)V");
	ref->builder = (*env)->GetMethodID(env, cls, "buildNewPacket",
			"(Ljava/lang/String;)Lnet/sf/iptablesJava/log/Packet;");

	return ref;
}

void notifyPacket(javaRef* javaRef, jobject* packet) {
	(*javaRef->env)->CallVoidMethod(javaRef->env, javaRef->object,
			javaRef->notification, *packet);
}

#ifndef DEBUG
void setField(javaRef* javaRef, jobject* retPacket, char * field, char * value) {
	jclass retPacketCls = (*javaRef->env)->GetObjectClass(javaRef->env,
			*retPacket);
	jmethodID setMethod = (*javaRef->env)->GetMethodID(javaRef->env,
			retPacketCls, "setField",
			"(Ljava/lang/String;Ljava/lang/String;)V");
	(*javaRef->env)->CallVoidMethod(javaRef->env, *retPacket, setMethod,
			(*javaRef->env)->NewStringUTF(javaRef->env, field),
			(*javaRef->env)->NewStringUTF(javaRef->env, value));
}

void setHWPacket(javaRef* javaRef, jobject* retPacket, jobject* hwPacket) {
	//TODO
}

jobject* newPacket(javaRef* javaRef, char* transportProto) {
	jobject packet = (*javaRef->env)->CallObjectMethod(javaRef->env,
			javaRef->object, javaRef->builder,
			(*javaRef->env)->NewStringUTF(javaRef->env, transportProto));

	jobject* ptr = &packet;

	setField(javaRef, ptr, "proto", transportProto);

	return ptr;
}

jobject* newHWPacket(javaRef* javaRef, char* HWProto) {
	//TODO
	return NULL ;
}
#endif

#ifdef DEBUG
void setField(javaRef* javaRef, jobject* retPacket, char * field, char * value) {
	printf("%s=%s ", field, value);
}

void setHWPacket(javaRef* javaRef, jobject* retPacket, jobject* hwPacket) {
}

jobject* newPacket(javaRef* javaRef, char* transportProto) {
	return NULL;
}

jobject* newHWPacket(javaRef* javaRef, char* HWProto) {
	return NULL;
}
#endif
