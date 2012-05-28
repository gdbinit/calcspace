/*
 *   _____     _     _____                 
 *  |     |___| |___|   __|___ ___ ___ ___ 
 *  |   --| .'| |  _|__   | . | .'|  _| -_|
 *  |_____|__,|_|___|_____|  _|__,|___|___|
 *                        |_|              
 *  (c) fG!, 2012 - reverser@put.as
 *
 *  macho.h
 *  
 *  Mach-O header auxiliary commands
 *  
 */


#ifndef calcspace_macho_c
#define calcspace_macho_c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <strings.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include "structures.h"

uint32_t get_header(const uint8_t *targetBuffer, struct mach_header_64 *header);

#endif
