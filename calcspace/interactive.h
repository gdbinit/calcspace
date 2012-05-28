/*
 *   _____     _     _____                 
 *  |     |___| |___|   __|___ ___ ___ ___ 
 *  |   --| .'| |  _|__   | . | .'|  _| -_|
 *  |_____|__,|_|___|_____|  _|__,|___|___|
 *                        |_|              
 *  (c) fG!, 2012 - reverser@put.as
 *
 *  interactive.c
 *  
 *  Editline related functions
 *
 *  Most of the functions from editline/readline fileman.c example
 *  
 */

#ifndef calcspace_interactive_c
#define calcspace_interactive_c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <strings.h>
#include <editline/readline.h>
#include <locale.h>
#include <ctype.h>

#include "structures.h"
#include "commands.h"
#include "macho.h"

void start_interactive_mode(const uint8_t *targetBuffer, options_t *options);

#endif
