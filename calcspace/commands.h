/*
 *   _____     _     _____                 
 *  |     |___| |___|   __|___ ___ ___ ___ 
 *  |   --| .'| |  _|__   | . | .'|  _| -_|
 *  |_____|__,|_|___|_____|  _|__,|___|___|
 *                        |_|              
 *  (c) fG!, 2012 - reverser@put.as
 *
 *  commands.h
 *  
 *  The commands to process the headers
 *  
 */

#ifndef _CALCSPACE_COMMANDS_H_
#define _CALCSPACE_COMMANDS_H_

void process_target(const uint8_t *buf, options_t options);
void process_injectionspace(const uint8_t *buf, options_t options);
void process_textspace(const uint8_t *buf, options_t options);
void process_nopspace(const uint8_t *buf, options_t options);

#endif