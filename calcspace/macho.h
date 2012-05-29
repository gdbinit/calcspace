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

#ifndef _CALCSPACE_MACHO_H_
#define _CALCSPACE_MACHO_H_

#include <mach-o/loader.h>
#include <mach-o/fat.h>

uint32_t get_header(const uint8_t *buf, struct mach_header_64 *header);

#endif
