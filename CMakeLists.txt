cmake_minimum_required(VERSION 3.22)
project(ssh_implementation C)

set(CMAKE_C_STANDARD 11)

add_executable(ssh_implementation main.c)
add_executable(ssh_client client.c
        packet.c
        packet.h
        shared.h
        kexinit.c
        kexinit.h
        utils.c
        utils.h
        dekexinit.h
        dekexinit.c
        dekexreply.h
        dekexreply.c
        kexhkey.c
        kexhkey.h
        newkeys.c
        newkeys.h)
