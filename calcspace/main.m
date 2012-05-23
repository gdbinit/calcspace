//
//  main.c
//  calcspace
//
//  
//  (c) fG!, 2012 - reverser@put.as
//

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <strings.h>
#include <libgen.h>

#define MALLOC_CHECK(variable) \
if (variable == NULL) { printf("[ERROR] Malloc failed! Exiting...\n"); exit(1); }

#define MALLOC(variable, size) \
variable = malloc(size); MALLOC_CHECK(variable);

static uint64_t read_target(uint8_t **targetBuffer, const char *target);
static void help(void);
void process_target(uint8_t *targetBuffer);

static void help(void)
{
    printf("\n");
    printf("Usage Syntax:\n");
    printf("macgyver target\n\n");
    printf("where:\n");
    printf("target - binary to work on\n");
}

int main (int argc, const char * argv[])
{
//    printf(" _____         _____ \n");
//    printf("|     |___ ___|   __|_ _ _ _ ___ ___ \n");
//    printf("| | | | .'|  _|  |  | | | | | -_|  _|\n");
//    printf("|_|_|_|__,|___|_____|_  |\\_/|___|_|  \n");
//    printf("                    |___|            \n");
//    printf("The Mach-O swiss army knife utility\n");
//    printf("(c) fG!, 2012 - reverser@put.as\n\n");
    
    if (argc < 2)
    {
        printf("[ERROR] Invalid number of arguments!\n");
        help();
        exit(1);
    }
    uint8_t *targetBuffer;
    // read target file into a buffer
    uint64_t fileSize = 0;
    fileSize = read_target(&targetBuffer, argv[1]);
    
    
    // verify if it's a valid mach-o target
    uint8_t isFat = 0;
    uint32_t magic = *(uint32_t*)(targetBuffer);
    if (magic == FAT_CIGAM)
        isFat = 1;
    else if (magic == MH_MAGIC || magic == MH_MAGIC_64)
        isFat = 0;
    else
    {
		printf("[ERROR] Target is not a mach-o binary!\n");
        exit(1);
    }
    
    if (isFat)
    {
#if DEBUG
        printf("Target is fat binary!\n");
#endif
        struct fat_header *fatheader_ptr = (struct fat_header *)targetBuffer;
        uint32_t nrFatArch = ntohl(fatheader_ptr->nfat_arch);
        // pointer to the first fat_arch structure
        struct fat_arch *fatArch = (struct fat_arch*)(targetBuffer + sizeof(struct fat_header));
        uint8_t *address = targetBuffer;
        for (uint32_t i = 0; i < nrFatArch ; i++)
        {
#if DEBUG
            printf("Processing fat binary nr %d of %d (cpu 0x%x)\n", i, nrFatArch, ntohl(fatArch->cputype));
#endif
            // position the buffer into the address and call the function
            address = targetBuffer + ntohl(fatArch->offset);
            if (ntohl(fatArch->cputype) == CPU_TYPE_POWERPC || ntohl(fatArch->cputype) == CPU_TYPE_POWERPC64)
            {
            }
            else
            {
                process_target(address);
            }
            fatArch++;
        }
    }
    else
    {
        process_target(targetBuffer);
    }
    return 0;
}

void process_target(uint8_t *targetBuffer)
{
    uint32_t magic = *(uint32_t*)(targetBuffer);
    struct mach_header_64 header;
    uint32_t headerSize = 0;
    uint8_t *address = NULL;
    uint64_t lastTextSection = 0;
    uint64_t dataVMAddress = 0;
    if (magic == MH_MAGIC)
    {
#if DEBUG
        printf("Processing 32bits target...\n");
#endif
        memcpy(&header, targetBuffer, sizeof(struct mach_header));
        headerSize = sizeof(struct mach_header);
    }
    else if (magic == MH_MAGIC_64)
    {
#if DEBUG
        printf("Processing 64bits target...\n");
#endif
        memcpy(&header, targetBuffer, sizeof(struct mach_header_64));
        headerSize = sizeof(struct mach_header_64);
    }
    address = targetBuffer + headerSize;
    struct load_command *loadCmd;
    for (uint32_t i = 0; i < header.ncmds ; i++)
    {
        loadCmd = (struct load_command*)address;
#if DEBUG
        printf("Current load cmd %x\n", loadCmd->cmd);
#endif
        if (loadCmd->cmd == LC_SEGMENT)
        {
            struct segment_command *segCmd = (struct segment_command*)address;
            if (strncmp(segCmd->segname, "__TEXT", 16) == 0)
            {
                // read the last section
                struct section *sectionCmd = (struct section*)(address + sizeof(struct segment_command) + (segCmd->nsects-1) * sizeof(struct section));
#if DEBUG
                printf("Section name %s\n", sectionCmd->sectname);
#endif
                lastTextSection = sectionCmd->addr + sectionCmd->size;
#if DEBUG
                printf("Last text section 0x%x\n", (uint32_t)lastTextSection);
#endif
            }
            else if (strncmp(segCmd->segname, "__DATA", 16) == 0)
            {
                // read the DATA segment vmaddr
#if DEBUG
                printf("Data VMAddr is %x\n", segCmd->vmaddr);
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
                // read the last section
                struct section_64 *sectionCmd = (struct section_64*)(address + sizeof(struct segment_command_64) + (segCmd->nsects-1) * sizeof(struct section_64));
#if DEBUG
                printf("Section name %s\n", sectionCmd->sectname);
#endif
                lastTextSection = sectionCmd->addr + sectionCmd->size;
#if DEBUG
                printf("Last text section 0x%llx\n", lastTextSection);
#endif
            }
            else if (strncmp(segCmd->segname, "__DATA", 16) == 0)
            {
                // read the DATA segment vmaddr
#if DEBUG
                printf("Data VMAddr is %llx\n", segCmd->vmaddr);
#endif
                dataVMAddress = segCmd->vmaddr;
                // no need for additional processing
                break;
            }
            
        }
        // move to next command
        address += loadCmd->cmdsize;
    }
    printf("Available slack space in __TEXT is 0x%llx\n", dataVMAddress - lastTextSection);
}

/*
 * read the target file into a buffer
 */
static uint64_t read_target(uint8_t **targetBuffer, const char *target)
{
    FILE *in_file;
	
    in_file = fopen(target, "r");
    if (!in_file)
    {
		printf("[ERROR] Could not open target file %s!\n", target);
        exit(1);
    }
    if (fseek(in_file, 0, SEEK_END))
    {
		printf("[ERROR] Fseek failed at %s\n", target);
        exit(1);
    }
    
    uint64_t fileSize = ftell(in_file);
    
    if (fseek(in_file, 0, SEEK_SET))
    {
		printf("[ERROR] Fseek failed at %s\n", target);
        exit(1);
    }
    
    *targetBuffer = malloc(fileSize * sizeof(uint8_t));
    if (*targetBuffer == NULL)
    {
        printf("[ERROR] Malloc failed!\n");
        exit(1);
    }
    
    fread(*targetBuffer, fileSize, 1, in_file);
	if (ferror(in_file))
	{
		printf("[ERROR] fread failed at %s\n", target);
        free(*targetBuffer);
		exit(1);
	}
    fclose(in_file);  
    return(fileSize);
}
