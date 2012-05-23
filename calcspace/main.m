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
#import <Foundation/Foundation.h>

// enable comma separated output to easily import into Excel or others
#define EXCEL 0
// set to enable iOS support against unpacked IPA files
#define IOS 0

static uint64_t read_target(uint8_t **targetBuffer, const char *target);
static void help(const char *exe);
static void process_target(uint8_t *targetBuffer);

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
    printf("%s path\n", exe);
    printf("where:\n");
    printf("path - path to the .app folder\n");
}

int main (int argc, const char * argv[])
{
    
    if (argc < 2)
    {
        fprintf(stderr, "[ERROR] Invalid number of arguments!\n");
        help(argv[0]);
        exit(1);
    }
    char *target;
    @autoreleasepool {

        NSString *path = [NSString stringWithCString:argv[1] encoding:NSUTF8StringEncoding];
        NSBundle *bundle = [NSBundle bundleWithPath:path];
        NSDictionary *plistData = [bundle infoDictionary];

        NSString *targetExe = (NSString*)[plistData objectForKey:@"CFBundleExecutable"];
        if (targetExe != nil)
        {
            printf("[INFO] Main executable is %s at %s\n", [targetExe UTF8String], [path UTF8String]);
#if IOS
            NSString *tempString1 = path;
#else
            NSString *tempString1 = [path stringByAppendingPathComponent:@"Contents/MacOS"];
#endif
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
		fprintf(stderr, "[ERROR] Target is not a mach-o binary!\n");
        exit(1);
    }
    
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

static void 
process_target(uint8_t *targetBuffer)
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
                // substract one to position in the last section
                uint32_t nsects = (segCmd->nsects >= 1) ? segCmd->nsects-1 : segCmd->nsects;
                // read the last section
                struct section *sectionCmd = (struct section*)(address + sizeof(struct segment_command) + nsects * sizeof(struct section));
#if DEBUG
                printf("[DEBUG] Section name %s\n", sectionCmd->sectname);
#endif
                lastTextSection = sectionCmd->addr + sectionCmd->size;
#if DEBUG
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
                // read the last section
                struct section_64 *sectionCmd = (struct section_64*)(address + sizeof(struct segment_command_64) + (segCmd->nsects-1) * sizeof(struct section_64));
#if DEBUG
                printf("[DEBUG] Section name %s\n", sectionCmd->sectname);
#endif
                lastTextSection = sectionCmd->addr + sectionCmd->size;
#if DEBUG
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
#if EXCEL
    printf("%lld,%s\n", (dataVMAddress - lastTextSection), arch ? "64bits" : "32bits");
#else
    printf("Available slack space in __TEXT is 0x%llx,%s\n", dataVMAddress - lastTextSection, arch ? "64bits" : "32bits");
#endif
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
