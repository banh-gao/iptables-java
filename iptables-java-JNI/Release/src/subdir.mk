################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/iptablesJava_conn.c \
../src/iptablesJava_log.c 

OBJS += \
./src/iptablesJava_conn.o \
./src/iptablesJava_log.o 

C_DEPS += \
./src/iptablesJava_conn.d \
./src/iptablesJava_log.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I/usr/lib/jvm/java-7-openjdk-amd64/include -I"/home/meltingshell/Documents/Informatica/eclipseWorkspace/iptables/iptables-java-lib/include" -I/usr/include -I/usr/local/include -O3 -Wall -c -fmessage-length=0 -fPIC -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


