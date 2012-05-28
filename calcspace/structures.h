/*
 *   _____     _     _____                 
 *  |     |___| |___|   __|___ ___ ___ ___ 
 *  |   --| .'| |  _|__   | . | .'|  _| -_|
 *  |_____|__,|_|___|_____|  _|__,|___|___|
 *                        |_|              
 *  (c) fG!, 2012 - reverser@put.as
 *
 *  structures.h
 *  
 */

#ifndef _CALCSPACE_STRUCTURES_H
#define _CALCSPACE_STRUCTURES_H

#include <stdint.h>

struct options
{
    uint8_t isFat;
    uint8_t allSections;
    uint8_t excelActive;
    uint8_t newCmdsActive;
    uint8_t freeDataSpace;
    uint8_t iosActive;
};

typedef struct options options_t;

#endif
