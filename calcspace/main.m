/*
 *   _____     _     _____                 
 *  |     |___| |___|   __|___ ___ ___ ___ 
 *  |   --| .'| |  _|__   | . | .'|  _| -_|
 *  |_____|__,|_|___|_____|  _|__,|___|___|
 *                        |_|              
 *  (c) fG!, 2012 - reverser@put.as
 *
 *  Small util to calculate the free space between the __TEXT and __DATA segments
 *  and between all sections inside __TEXT segment
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
#include <histedit.h>

#import <Foundation/Foundation.h>

//uint8_t iosActive   = 0;
//uint8_t excelActive = 0;
//uint8_t newCmdsActive = 0;

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

static uint64_t read_target(uint8_t **targetBuffer, const char *target);
static void help(const char *exe);
static void process_textspace(const uint8_t *targetBuffer, options_t options);
static void process_target(const uint8_t *targetBuffer, options_t options);
static uint32_t get_header(const uint8_t *targetBuffer, struct mach_header_64 *header);
static void process_injectionspace(const uint8_t *targetBuffer, options_t options);
static void remove_newline(const char *line);
static void init_options(options_t *options);
static void reset_options(options_t *options);
char * prompt(EditLine *e);


static void 
help(const char *exe)
{
    printf(" _____     _     _____ \n");                
    printf("|     |___| |___|   __|___ ___ ___ ___ \n");
    printf("|   --| .'| |  _|__   | . | .'|  _| -_|\n");
    printf("|_____|__,|_|___|_____|  _|__,|___|___|\n");
    printf("                      |_|              \n");
    printf("Calculate free space in mach-o headers\n");
    printf("(c) fG!, 2012 - reverser@put.as\n");

    printf("\n");
    printf("Usage Syntax:\n");
    printf("%s <path> <commands>\n", exe);
    printf("where:\n");
    printf("<path>: path to the .app folder\n");
    printf("and commands:\n");
    printf("-f : calculate free space between last __TEXT section and __DATA\n");
    printf("-a : calculate free space between all __TEXT sections (requires -f)\n");
    printf("-i : target is an iOS application\n");
    printf("-e : format output to be imported into Excel\n");
    printf("-n : calculate free space to inject new commands\n");
}

char * prompt(EditLine *e) 
{
    return "calcspace> ";
}

int main (int argc, char * argv[])
{
    // required structure for long options
	static struct option long_options[]={
        { "all",     no_argument, NULL, 'a' },
        { "ios",     no_argument, NULL, 'i' },
        { "excel",   no_argument, NULL, 'e' },
        { "newcmds", no_argument, NULL, 'n' },
        { "free",    no_argument, NULL, 'f' },
        { "help",    no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	int option_index = 0;
    int c = 0;
    uint8_t allSections = 0;
    uint8_t freeDataSpace = 0;
    char *myProgramName = argv[0];
    options_t options;
    init_options(&options);
    
    // process command line options
	while ((c = getopt_long(argc, argv, "haienf", long_options, &option_index)) != -1)
	{
		switch (c)
		{
			case ':':
			case '?':
            case 'h':
				help(myProgramName);
				exit(1);
				break;
            case 'a':
                options.allSections = 1;
                break;
            case 'i':
                options.iosActive = 1;
                break;
            case 'e':
                options.excelActive = 1;
                break;
            case 'n':
                options.newCmdsActive = 1;
                break;
            case 'f':
                options.freeDataSpace = 1;
                break;
			default:
				help(myProgramName);
				exit(1);
		}
	}

//    if (optind <= 1 || argc-optind < 1 )
//    {
//        fprintf(stderr, "[ERROR] Invalid number of arguments!\n");
//        help(myProgramName);
//        exit(1);
//    }
    
    if (!freeDataSpace && allSections)
    {
        fprintf(stderr, "[ERROR] -a option requires -f\n");
        exit(1);
    }
    
    char *target = NULL;
    @autoreleasepool {

        NSString *path = [NSString stringWithCString:(argv+optind)[0] encoding:NSUTF8StringEncoding];
        NSBundle *bundle = [NSBundle bundleWithPath:path];
        NSDictionary *plistData = [bundle infoDictionary];

        NSString *targetExe = (NSString*)[plistData objectForKey:@"CFBundleExecutable"];
        if (targetExe != nil)
        {
            printf("[INFO] Main executable is %s at %s\n", [targetExe UTF8String], [path UTF8String]);
            NSString *tempString1;
            if (options.iosActive)
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
    uint32_t magic = *(uint32_t*)(targetBuffer);
    if (magic == FAT_CIGAM)
    {
        options.isFat = 1;
    }
    else if (magic == MH_MAGIC || magic == MH_MAGIC_64)
    {
        options.isFat = 0;
    }
    else
    {
		fprintf(stderr, "[ERROR] Target %s is not a mach-o binary!\n", target);
        exit(1);
    }
    free(target);
    
    // no options given so go to interactive mode
    if (optind <= 1 || argc-optind < 1 )
    {
        /* This holds all the state for our line editor */
        EditLine *el;
        
        /* This holds the info for our history */
        History *myhistory;
        
        /* Temp variables */
        int count;
        const char *line;
        int keepreading = 1;
        HistEvent ev;
        
        /* Initialize the EditLine state to use our prompt function and
         emacs style editing. */
        
        el = el_init(argv[0], stdin, stdout, stderr);
        el_set(el, EL_PROMPT, &prompt);
        el_set(el, EL_EDITOR, "emacs");
        
        /* Initialize the history */
        myhistory = history_init();
        if (myhistory == 0) {
            fprintf(stderr, "history could not be initialized\n");
            return 1;
        }
        
        /* Set the size of the history */
        history(myhistory, &ev, H_SETSIZE, 800);
        
        /* This sets up the call back functions for history functionality */
        el_set(el, EL_HIST, history, myhistory);
        printf(" _____     _     _____ \n");                
        printf("|     |___| |___|   __|___ ___ ___ ___ \n");
        printf("|   --| .'| |  _|__   | . | .'|  _| -_|\n");
        printf("|_____|__,|_|___|_____|  _|__,|___|___|\n");
        printf("                      |_|              \n");
        printf("Calculate free space in mach-o headers\n");
        printf("(c) fG!, 2012 - reverser@put.as\n\n");

        while (keepreading) {
            /* count is the number of characters read.
             line is a const char* of our command line with the tailing \n */
            line = el_gets(el, &count);
            
            /* In order to use our history we have to explicitly add commands
             to the history */
            if (count > 0) {
                history(myhistory, &ev, H_ENTER, line);
                
                remove_newline(line);
                
                if (strcmp(line, "quit") == 0)
                    break;
                else if (strcmp(line, "new") == 0)
                {
                    options.newCmdsActive = 1;
                    process_target(targetBuffer, options);
                }
                else if (strcmp(line, "free") == 0)
                {
                    options.freeDataSpace = 1;
                    process_target(targetBuffer, options);
                }
                reset_options(&options);
            }
        }
        /* Clean up our memory */
        history_end(myhistory);
        el_end(el);
        goto end;
    }
    else
    {
        process_target(targetBuffer, options);
    }
end:
    free(targetBuffer);
    return 0;
}

static void 
remove_newline(const char *line)
{
    char *pline = (char*)line;
    if ((pline = strchr(line, '\n')) != NULL)
        *pline = '\0';
}

static void 
init_options(options_t *options)
{
    options->allSections = 0;
    options->excelActive = 0;
    options->freeDataSpace = 0;
    options->newCmdsActive = 0;
    options->iosActive = 0;
    options->isFat = 0;
}

static void 
reset_options(options_t *options)
{
    options->freeDataSpace = 0;
    options->newCmdsActive = 0;
}

/*
 * aux function to get the mach header
 */
static uint32_t
get_header(const uint8_t *targetBuffer, struct mach_header_64 *header)
{
    uint32_t magic = *(uint32_t*)(targetBuffer);    
    uint32_t headerSize = 0;
    if (magic == MH_MAGIC)
    {
#if DEBUG
        printf("[DEBUG] Processing 32bits target...\n");
#endif
        memcpy(header, targetBuffer, sizeof(struct mach_header));
        headerSize = sizeof(struct mach_header);
    }
    else if (magic == MH_MAGIC_64)
    {
#if DEBUG
        printf("[DEBUG] Processing 64bits target...\n");
#endif
        memcpy(header, targetBuffer, sizeof(struct mach_header_64));
        headerSize = sizeof(struct mach_header_64);
    }
    return headerSize;
}

/*
 * function that will process the target and act according user options
 */
static void 
process_target(const uint8_t *targetBuffer, options_t options)
{
    // target is a fat binary so we iterate thru all binaries inside
    if (options.isFat)
    {
#if DEBUG
        printf("[DEBUG] Target is fat binary!\n");
#endif
        struct fat_header *fatheader_ptr = (struct fat_header *)targetBuffer;
        uint32_t nrFatArch = ntohl(fatheader_ptr->nfat_arch);
        // pointer to the first fat_arch structure
        struct fat_arch *fatArch = (struct fat_arch*)(targetBuffer + sizeof(struct fat_header));
        uint8_t *address = (uint8_t *)targetBuffer;
        for (uint32_t i = 0; i < nrFatArch ; i++)
        {
#if DEBUG
            printf("[DEBUG] Processing fat binary nr %d of %d (cpu 0x%x)\n", i, nrFatArch, ntohl(fatArch->cputype));
#endif
            // position the buffer into the address and call the function
            address = (uint8_t *)targetBuffer + ntohl(fatArch->offset);
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
            process_injectionspace(targetBuffer, options);
        if (options.freeDataSpace)
            process_textspace(targetBuffer, options);
    }    
}

/*
 * function to process __TEXT related space calculations
 */
static void 
process_textspace(const uint8_t *targetBuffer, options_t options)
{
    struct mach_header_64 header;
    uint32_t headerSize = 0;
    uint8_t *address = NULL;
    uint64_t lastTextSection = 0;
    uint64_t dataVMAddress = 0;
    // 0 = 32bits, 1 = 64bits
    uint8_t arch = 0;

    headerSize = get_header(targetBuffer, &header);
    
    address = (uint8_t*)targetBuffer + headerSize;
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

    if (options.excelActive)
        printf("%lld,%s\n", (dataVMAddress - lastTextSection), arch ? "64bits" : "32bits");
    else
        printf("Available slack space at the end of __TEXT is %lld bytes (%s)\n", dataVMAddress - lastTextSection, arch ? "64bits" : "32bits");
}

/*
 * calculate the free mach-o header space to inject new commands
 */
static void 
process_injectionspace(const uint8_t *targetBuffer, options_t options)
{
    struct mach_header_64 header;
    uint32_t headerSize = 0;
    uint8_t *address = NULL;
    // 0 = 32bits, 1 = 64bits
    uint8_t arch = 0;
    
    headerSize = get_header(targetBuffer, &header);
    
    address = (uint8_t*)targetBuffer + headerSize;
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
                arch = 1;
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
        firstSectionAddress = (uint32_t)targetBuffer + textFirstSectionAddress;
    else
        firstSectionAddress = (uint32_t)targetBuffer + cryptFirstSectionAddress;
    
    // address is positioned after all load commands
    uint32_t headerEndAddress = (uint32_t)address;
    if (options.excelActive)
        printf("%lld,%s\n", firstSectionAddress-headerEndAddress, arch ? "64bits" : "32bits");
    else
        printf("Free injection space: %lld bytes (%s)\n", firstSectionAddress-headerEndAddress, arch ? "64bits" : "32bits");
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
