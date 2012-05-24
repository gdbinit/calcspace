/*
 *   _____     _     _____                 
 *  |     |___| |___|   __|___ ___ ___ ___ 
 *  |   --| .'| |  _|__   | . | .'|  _| -_|
 *  |_____|__,|_|___|_____|  _|__,|___|___|
 *                        |_|              
 *  (c) fG!, 2012 - reverser@put.as
 *
 *  Small util to calculate the free space between the __TEXT and __DATA segments
 *
 *  The objective is to verify if there's enough space for code injection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <strings.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <getopt.h>

#import <Foundation/Foundation.h>

uint8_t iosActive   = 0;
uint8_t excelActive = 0;

static uint64_t read_target(uint8_t **targetBuffer, const char *target);
static void help(const char *exe);
static void process_target(uint8_t *targetBuffer, uint8_t allsections);

static void 
help(const char *exe)
{
    printf(" _____     _     _____ \n");                
    printf("|     |___| |___|   __|___ ___ ___ ___ \n");
    printf("|   --| .'| |  _|__   | . | .'|  _| -_|\n");
    printf("|_____|__,|_|___|_____|  _|__,|___|___|\n");
    printf("                      |_|              \n");
    printf("Calculate free space between __TEXT and __DATA\n");
    printf("(c) fG!, 2012 - reverser@put.as\n");

    printf("\n");
    printf("Usage Syntax:\n");
    printf("%s <path> [-a] [-i] [-e]\n", exe);
    printf("where:\n");
    printf("<path>: path to the .app folder\n");
    printf("-a    : calculate free space between all __TEXT sections\n");
    printf("-i    : target is an iOS application\n");
    printf("-e    : format output to be imported into Excel\n");
}

int main (int argc, char * argv[])
{
    // required structure for long options
	static struct option long_options[]={
        { "all", no_argument, NULL, 'a' },
        { "ios", no_argument, NULL, 'i' },
        { "excel", no_argument, NULL, 'e' },
		{ NULL, 0, NULL, 0 }
	};
	int option_index = 0;
    int c = 0;
    uint8_t allsections = 0;
    char *myProgramName = argv[0];
    
    // process command line options
	while ((c = getopt_long(argc, argv, "aie", long_options, &option_index)) != -1)
	{
		switch (c)
		{
			case ':':
				help(myProgramName);
				exit(1);
				break;
			case '?':
				help(myProgramName);
				exit(1);
				break;
            case 'a':
                allsections = 1;
                break;
            case 'i':
                iosActive = 1;
                break;
            case 'e':
                excelActive = 1;
                break;
			default:
				help(myProgramName);
				exit(1);
		}
	}

    if (argc-optind < 1)
    {
        fprintf(stderr, "[ERROR] Invalid number of arguments!\n");
        help(myProgramName);
        exit(1);
    }
    char *target;
    @autoreleasepool {

        NSString *path = [NSString stringWithCString:(argv+optind)[0] encoding:NSUTF8StringEncoding];
        NSBundle *bundle = [NSBundle bundleWithPath:path];
        NSDictionary *plistData = [bundle infoDictionary];

        NSString *targetExe = (NSString*)[plistData objectForKey:@"CFBundleExecutable"];
        if (targetExe != nil)
        {
            printf("[INFO] Main executable is %s at %s\n", [targetExe UTF8String], [path UTF8String]);
            NSString *tempString1;
            if (iosActive)
                tempString1 = path;
            else
                tempString1 = [path stringByAppendingPathComponent:@"Contents/MacOS"];

            NSString *tempTarget = [tempString1 stringByAppendingPathComponent:targetExe];
            target = malloc([tempTarget length] * sizeof(char)+1);
            [tempTarget getCString:target maxLength:[tempTarget length]+1 encoding:NSUTF8StringEncoding];
        }
        else
        {
            fprintf(stderr, "[ERROR] Can't find the target exe at %s\n", [path UTF8String]);
            exit(0);
        }
    }    
    uint8_t *targetBuffer;
    // read target file into a buffer
    uint64_t fileSize = 0;
    fileSize = read_target(&targetBuffer, target);
    
    // verify if it's a valid mach-o target
    uint8_t isFat = 0;
    uint32_t magic = *(uint32_t*)(targetBuffer);
    if (magic == FAT_CIGAM)
    {
        isFat = 1;
    }
    else if (magic == MH_MAGIC || magic == MH_MAGIC_64)
    {
        isFat = 0;
    }
    else
    {
		fprintf(stderr, "[ERROR] Target %s is not a mach-o binary!\n", target);
        exit(1);
    }
    free(target);
    // target is a fat binary so we iterate thru all binaries inside
    if (isFat)
    {
#if DEBUG
        printf("[DEBUG] Target is fat binary!\n");
#endif
        struct fat_header *fatheader_ptr = (struct fat_header *)targetBuffer;
        uint32_t nrFatArch = ntohl(fatheader_ptr->nfat_arch);
        // pointer to the first fat_arch structure
        struct fat_arch *fatArch = (struct fat_arch*)(targetBuffer + sizeof(struct fat_header));
        uint8_t *address = targetBuffer;
        for (uint32_t i = 0; i < nrFatArch ; i++)
        {
#if DEBUG
            printf("[DEBUG] Processing fat binary nr %d of %d (cpu 0x%x)\n", i, nrFatArch, ntohl(fatArch->cputype));
#endif
            // position the buffer into the address and call the function
            address = targetBuffer + ntohl(fatArch->offset);
            if (ntohl(fatArch->cputype) == CPU_TYPE_POWERPC || ntohl(fatArch->cputype) == CPU_TYPE_POWERPC64)
            {
                // not supported for now or never
            }
            else
            {
                process_target(address, allsections);
            }
            fatArch++;
        }
    }
    // non fat so we just have to deal with a single binary
    else
    {
        process_target(targetBuffer, allsections);
    }
    free(targetBuffer);
    return 0;
}

static void 
process_target(uint8_t *targetBuffer, uint8_t allsections)
{
    uint32_t magic = *(uint32_t*)(targetBuffer);
    struct mach_header_64 header;
    uint32_t headerSize = 0;
    uint8_t *address = NULL;
    uint64_t lastTextSection = 0;
    uint64_t dataVMAddress = 0;
    // 0 = 32bits, 1 = 64bits
    uint8_t arch = 0;
    if (magic == MH_MAGIC)
    {
#if DEBUG
        printf("[DEBUG] Processing 32bits target...\n");
#endif
        memcpy(&header, targetBuffer, sizeof(struct mach_header));
        headerSize = sizeof(struct mach_header);
    }
    else if (magic == MH_MAGIC_64)
    {
#if DEBUG
        printf("[DEBUG] Processing 64bits target...\n");
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
        printf("[DEBUG] Current load cmd %x\n", loadCmd->cmd);
#endif
        if (loadCmd->cmd == LC_SEGMENT)
        {
            struct segment_command *segCmd = (struct segment_command*)address;
            if (strncmp(segCmd->segname, "__TEXT", 16) == 0)
            {
                // compute the difference between all __TEXT sections
                if (allsections && segCmd->nsects > 1)
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
                        if (excelActive)
                        {
                            printf("%d,", nextSectionCmd->addr - (currentSectionCmd->addr+currentSectionCmd->size));
                        }
                        else
                        {
                            printf("Free space between %.16s and %.16s: %x\n", currentSectionCmd->sectname, nextSectionCmd->sectname, nextSectionCmd->addr - (currentSectionCmd->addr+currentSectionCmd->size));
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
                if (allsections && segCmd->nsects > 1)
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
                        if (excelActive)
                        {
                            printf("%lld,", nextSectionCmd->addr - (currentSectionCmd->addr+currentSectionCmd->size));
                        }
                        else
                        {
                            printf("Free space between %.16s and %.16s: %llx\n", currentSectionCmd->sectname, nextSectionCmd->sectname, nextSectionCmd->addr - (currentSectionCmd->addr+currentSectionCmd->size));
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
                arch = 1;
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
    
    if (excelActive)
        printf("%lld,%s\n", (dataVMAddress - lastTextSection), arch ? "64bits" : "32bits");
//        printf("%lld\n", (dataVMAddress - lastTextSection));
    else
        printf("Available slack space in __TEXT is 0x%llx,%s\n", dataVMAddress - lastTextSection, arch ? "64bits" : "32bits");
}

/*
 * read the target file into a buffer
 */
static uint64_t 
read_target(uint8_t **targetBuffer, const char *target)
{
    FILE *in_file;
	
    in_file = fopen(target, "r");
    if (!in_file)
    {
		fprintf(stderr, "[ERROR] Could not open target file %s!\n", target);
        exit(1);
    }
    if (fseek(in_file, 0, SEEK_END))
    {
		fprintf(stderr, "[ERROR] Fseek failed at %s\n", target);
        exit(1);
    }
    
    long fileSize = ftell(in_file);
    
    if (fseek(in_file, 0, SEEK_SET))
    {
		fprintf(stderr, "[ERROR] Fseek failed at %s\n", target);
        exit(1);
    }
    
    *targetBuffer = malloc(fileSize * sizeof(uint8_t));
    if (*targetBuffer == NULL)
    {
        fprintf(stderr, "[ERROR] Malloc failed!\n");
        exit(1);
    }
    
    fread(*targetBuffer, fileSize, 1, in_file);
	if (ferror(in_file))
	{
		fprintf(stderr, "[ERROR] fread failed at %s\n", target);
        free(*targetBuffer);
		exit(1);
	}
    fclose(in_file);  
    return(fileSize);
}
