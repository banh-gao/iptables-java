################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../iptablesJava_conn.c \
../iptablesJava_log.c 

OBJS += \
./iptablesJava_conn.o \
./iptablesJava_log.o 

C_DEPS += \
./iptablesJava_conn.d \
./iptablesJava_log.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I/usr/lib/jvm/java-7-openjdk-amd64/include -I"/home/meltingshell/Documents/Informatica/eclipseWorkspace/iptables-java/include" -O3 -Wall -c -fmessage-length=0 -fPIC -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


