/*
 *   _____     _     _____                 
 *  |     |___| |___|   __|___ ___ ___ ___ 
 *  |   --| .'| |  _|__   | . | .'|  _| -_|
 *  |_____|__,|_|___|_____|  _|__,|___|___|
 *                        |_|              
 *  (c) fG!, 2012 - reverser@put.as
 *
 *  commands.m
 *  
 *  The commands to process the headers
 *  
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <strings.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include "structures.h"
#include "macho.h"
#include "commands.h"

static char * get_cpu(cpu_type_t cputype, cpu_subtype_t cpusubtype);

/*
 * function that will process the target and act according user options
 */
void 
process_target(const uint8_t *buf, options_t options)
{
    // target is a fat binary so we iterate thru all binaries inside
    if (options.isFat)
    {
#if DEBUG
        printf("[DEBUG] Target is fat binary!\n");
#endif
        struct fat_header *fatheader_ptr = (struct fat_header *)buf;
        uint32_t nrFatArch = ntohl(fatheader_ptr->nfat_arch);
        // pointer to the first fat_arch structure
        struct fat_arch *fatArch = (struct fat_arch*)(buf + sizeof(struct fat_header));
        uint8_t *address = (uint8_t *)buf;
        for (uint32_t i = 0; i < nrFatArch ; i++)
        {
#if DEBUG
            printf("[DEBUG] Processing fat binary nr %d of %d (cpu 0x%x)\n", i, nrFatArch, ntohl(fatArch->cputype));
#endif
            // position the buffer into the address and call the function
            address = (uint8_t *)buf + ntohl(fatArch->offset);
            if (ntohl(fatArch->cputype) == CPU_TYPE_POWERPC || ntohl(fatArch->cputype) == CPU_TYPE_POWERPC64)
            {
                // not supported for now or never
            }
            else
            {
                if (options.newCmdsActive)
                    process_injectionspace(address, options);
                if (options.freeDataSpace)
                    process_textspace(address, options);
            }
            fatArch++;
        }
    }
    // non fat so we just have to deal with a single binary
    else
    {
        if (options.newCmdsActive)
            process_injectionspace(buf, options);
        if (options.freeDataSpace)
            process_textspace(buf, options);
    }    
}

/*
 * function to process __TEXT related space calculations
 */
void 
process_textspace(const uint8_t *buf, options_t options)
{
    struct mach_header_64 header;
    uint32_t headerSize = 0;
    uint8_t *address = NULL;
    uint64_t lastTextSection = 0;
    uint64_t dataVMAddress = 0;

    headerSize = get_header(buf, &header);
    
    address = (uint8_t*)buf + headerSize;
    struct load_command *loadCmd;
    
    for (uint32_t i = 0; i < header.ncmds ; i++)
    {
        loadCmd = (struct load_command*)address;
#if DEBUG
        printf("[DEBUG] Current load cmd %x\n", loadCmd->cmd);
#endif
        if (loadCmd->cmd == LC_SEGMENT)
        {
            struct segment_command *segCmd = (struct segment_command*)address;
            if (strncmp(segCmd->segname, "__TEXT", 16) == 0)
            {
                if (options.allSections && segCmd->nsects > 1)
                {
                    for (uint32_t x = 0; x < segCmd->nsects-1; x++)
                    {
                        // current section
                        struct section *currentSectionCmd = (struct section*)(address + sizeof(struct segment_command) + x * sizeof(struct section));
                        struct section *nextSectionCmd = (struct section*)((uint8_t*)currentSectionCmd+sizeof(struct section));
#if DEBUG
                        printf("Current section address: %x\n", currentSectionCmd->addr);
                        printf("Next section address: %x\n", nextSectionCmd->addr);
#endif
                        if (options.excelActive)
                        {
                            printf("%d,", nextSectionCmd->addr - (currentSectionCmd->addr+currentSectionCmd->size));
                        }
                        else
                        {
                            printf("Free space between %.16s and %.16s: %d bytes\n", currentSectionCmd->sectname, nextSectionCmd->sectname, nextSectionCmd->addr - (currentSectionCmd->addr+currentSectionCmd->size));
                        }
                    }
                }
                // but also compute between last section and the first in __DATA
                // substract one to position in the last section
                uint32_t nsects = (segCmd->nsects >= 1) ? segCmd->nsects-1 : segCmd->nsects;
                // read the last section
                struct section *sectionCmd = (struct section*)(address + sizeof(struct segment_command) + nsects * sizeof(struct section));
                lastTextSection = sectionCmd->addr + sectionCmd->size;
#if DEBUG
                printf("[DEBUG] Section name %.16s\n", sectionCmd->sectname);
                printf("[DEBUG] Last text section 0x%x\n", (uint32_t)lastTextSection);
#endif
            }
            else if (strncmp(segCmd->segname, "__DATA", 16) == 0)
            {
                // read the DATA segment vmaddr
#if DEBUG
                printf("[DEBUG] Data VMAddr is %x\n", segCmd->vmaddr);
#endif
                dataVMAddress = segCmd->vmaddr;
                // no need for additional processing
                break;
            }
        }
        else if (loadCmd->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *segCmd = (struct segment_command_64*)address;
            if (strncmp(segCmd->segname, "__TEXT", 16) == 0)
            {
                // compute the difference between all __TEXT sections
                if (options.allSections && segCmd->nsects > 1)
                {
                    for (uint32_t x = 0; x < segCmd->nsects-1; x++)
                    {
                        // current section
                        struct section_64 *currentSectionCmd = (struct section_64*)(address + sizeof(struct segment_command_64) + x * sizeof(struct section_64));
                        struct section_64 *nextSectionCmd = (struct section_64*)((uint8_t*)currentSectionCmd+sizeof(struct section_64));
#if DEBUG
                        printf("Current section address: %x\n", currentSectionCmd->addr);
                        printf("Next section address: %x\n", nextSectionCmd->addr);
#endif
                        if (options.excelActive)
                        {
                            printf("%lld,", nextSectionCmd->addr - (currentSectionCmd->addr+currentSectionCmd->size));
                        }
                        else
                        {
                            printf("Free space between %.16s and %.16s: %lld bytes\n", currentSectionCmd->sectname, nextSectionCmd->sectname, nextSectionCmd->addr - (currentSectionCmd->addr+currentSectionCmd->size));
                        }
                    }
                }
                // substract one to position in the last section
                uint32_t nsects = (segCmd->nsects >= 1) ? segCmd->nsects-1 : segCmd->nsects;
                // read the last section
                struct section_64 *sectionCmd = (struct section_64*)(address + sizeof(struct segment_command_64) + nsects * sizeof(struct section_64));
                lastTextSection = sectionCmd->addr + sectionCmd->size;
#if DEBUG
                printf("[DEBUG] Section name %.16s\n", sectionCmd->sectname);
                printf("[DEBUG] Last text section 0x%llx\n", lastTextSection);
#endif
            }
            else if (strncmp(segCmd->segname, "__DATA", 16) == 0)
            {
                // read the DATA segment vmaddr
#if DEBUG
                printf("[DEBUG] Data VMAddr is %llx\n", segCmd->vmaddr);
#endif
                dataVMAddress = segCmd->vmaddr;
                // no need for additional processing
                break;
            }
        }
        // move to next command
        address += loadCmd->cmdsize;
    }
    char *cpu = get_cpu(header.cputype, header.cpusubtype);
    if (options.excelActive)
        printf("%lld,%s\n", (dataVMAddress - lastTextSection), cpu);
    else
        printf("Available slack space at the end of __TEXT is %lld bytes (%s)\n", dataVMAddress - lastTextSection, cpu);
}

/*
 * calculate the free mach-o header space to inject new commands
 */
void 
process_injectionspace(const uint8_t *buf, options_t options)
{
    struct mach_header_64 header;
    uint32_t headerSize = 0;
    uint8_t *address = NULL;
    
    headerSize = get_header(buf, &header);
    
    address = (uint8_t*)buf + headerSize;
    struct load_command *loadCmd;
    uint64_t firstSectionAddress = 0;
    uint64_t textFirstSectionAddress = 0;
    uint64_t cryptFirstSectionAddress = 0;
    
    for (uint32_t i = 0; i < header.ncmds ; i++)
    {
        loadCmd = (struct load_command*)address;
#if DEBUG
        printf("[DEBUG] Current load cmd %x\n", loadCmd->cmd);
#endif
        if (loadCmd->cmd == LC_SEGMENT)
        {
            struct segment_command *segCmd = (struct segment_command*)address;
            if (strncmp(segCmd->segname, "__TEXT", 16) == 0)
            {
                uint8_t *sectionAddress = address + sizeof(struct segment_command);
                for (uint32_t x = 0; x < segCmd->nsects; x++)
                {
                    struct section *currentSectionCmd = (struct section*)sectionAddress;
                    if (strncmp(currentSectionCmd->sectname, "__text", 16) == 0)
                    {
                        textFirstSectionAddress = currentSectionCmd->offset;
#if DEBUG
                        printf("[DEBUG] first section address %x\n", textFirstSectionAddress);
#endif
                        break;
                    }
                    sectionAddress += sizeof(struct section);
                }
            }
        }
        else if (loadCmd->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *segCmd = (struct segment_command_64*)address;
            if (strncmp(segCmd->segname, "__TEXT", 16) == 0)
            {
                uint8_t *sectionAddress = address + sizeof(struct segment_command_64);
                for (uint32_t x = 0; x < segCmd->nsects; x++)
                {
                    struct section_64 *currentSectionCmd = (struct section_64*)sectionAddress;
                    if (strncmp(currentSectionCmd->sectname, "__text", 16) == 0)
                    {
                        textFirstSectionAddress = currentSectionCmd->offset;
#if DEBUG
                        printf("[DEBUG] first section address %x\n", textFirstSectionAddress);
#endif
                        break;
                    }
                    sectionAddress += sizeof(struct section_64);
                }
            }
        }
        else if (loadCmd->cmd == LC_ENCRYPTION_INFO)
        {
            struct encryption_info_command *segCmd = (struct encryption_info_command*)address;
            cryptFirstSectionAddress = segCmd->cryptoff;
        }
        // move to next command
        address += loadCmd->cmdsize;
    }
    
    // use the lowest one - for signed binaries crypt usually comes first!
    if (cryptFirstSectionAddress == 0 || cryptFirstSectionAddress > textFirstSectionAddress)
        firstSectionAddress = (uint32_t)buf + textFirstSectionAddress;
    else
        firstSectionAddress = (uint32_t)buf + cryptFirstSectionAddress;
    
    // address is positioned after all load commands
    uint32_t headerEndAddress = (uint32_t)address;
    char *cpu = get_cpu(header.cputype, header.cpusubtype);
    if (options.excelActive)
        printf("%lld,%s\n", firstSectionAddress-headerEndAddress, cpu);
    else
        printf("Free injection space: %lld bytes (%s)\n", firstSectionAddress-headerEndAddress, cpu);
}

/*
 * aux function to return a string with the cpu type
 */
static char *
get_cpu(cpu_type_t cputype, cpu_subtype_t cpusubtype)
{
    switch (cputype) 
    {
        case CPU_TYPE_I386:
            return "32bits";
        case CPU_TYPE_X86_64:
            return "64bits";
        case CPU_TYPE_ARM:
        {
            if (cpusubtype == CPU_SUBTYPE_ARM_V6)
                return "armv6";
            else if (cpusubtype == CPU_SUBTYPE_ARM_V7)
                return "armv7";
        }
        default:
            return "";
    }
}
