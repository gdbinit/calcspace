/*
 *   _____     _     _____                 
 *  |     |___| |___|   __|___ ___ ___ ___ 
 *  |   --| .'| |  _|__   | . | .'|  _| -_|
 *  |_____|__,|_|___|_____|  _|__,|___|___|
 *                        |_|              
 *  (c) fG!, 2012 - reverser@put.as
 *
 *  macho.m
 *  
 *  Mach-O header auxiliary commands
 *  
 */

#include "macho.h"

/*
 * aux function to get the mach header
 */
uint32_t
get_header(const uint8_t *buf, struct mach_header_64 *header)
{
    uint32_t magic = *(uint32_t*)(buf);    
    uint32_t headerSize = 0;
    if (magic == MH_MAGIC)
    {
#if DEBUG
        printf("[DEBUG] Processing 32bits target...\n");
#endif
        memcpy(header, buf, sizeof(struct mach_header));
        headerSize = sizeof(struct mach_header);
    }
    else if (magic == MH_MAGIC_64)
    {
#if DEBUG
        printf("[DEBUG] Processing 64bits target...\n");
#endif
        memcpy(header, buf, sizeof(struct mach_header_64));
        headerSize = sizeof(struct mach_header_64);
    }
    return headerSize;
}
