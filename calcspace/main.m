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
 *
 *  THIS CODE IS FREE AS IN DO WHATEVER YOU WANT WITH IT.
 *  THE ONLY REQUIREMENT IS TO MAINTAIN ORIGINAL CREDIT.
 *  THIS LICENSE APPLIES TO ALL SOURCE FILES INCLUDED IN THIS PROJECT.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <strings.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <getopt.h>
#include "structures.h"
#include "commands.h"
#include "interactive.h"

#define VERSION "1.0"

static uint64_t read_target(uint8_t **targetBuffer, const char *target);
static void help(const char *exe);
static void remove_newline(const char *line);
void init_options(options_t *options);
void reset_options(options_t *options);
uint8_t init_target(char *targetPath, uint8_t **buf, options_t *options);
void header(void);

void
header(void)
{
    printf(" _____     _     _____ \n");                
    printf("|     |___| |___|   __|___ ___ ___ ___ \n");
    printf("|   --| .'| |  _|__   | . | .'|  _| -_|\n");
    printf("|_____|__,|_|___|_____|  _|__,|___|___|\n");
    printf("                      |_|         v%s  \n", VERSION);
    printf("Calculate free space in mach-o headers\n");
    printf("(c) fG!, 2012 - reverser@put.as\n");   
}

static void 
help(const char *exe)
{
    header();
    printf("\n");
    printf("Usage Syntax:\n");
    printf("%s <path> [<commands>]\n", exe);
    printf("where:\n");
    printf("<path>: path to the .app folder\n");
    printf("and commands:\n");
    printf("-f : calculate free space between last __TEXT section and __DATA\n");
    printf("-a : calculate free space between all __TEXT sections (requires -f)\n");
    printf("-i : target is an iOS application\n");
    printf("-e : format output to be imported into Excel\n");
    printf("-n : calculate free space to inject new commands\n");
    printf("-s : calculate available NOP space in __text section\n");
    printf("-t : calculate only total available NOP space in __text section\n");
    printf("-h : display this help text\n\n");
    printf("Note: Interactive mode will be used if no commands or no path is configured\n");
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
        { "slack",   no_argument, NULL, 's' },
        { "totalslack", no_argument, NULL, 't' },
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
	while ((c = getopt_long(argc, argv, "aienfhst", long_options, &option_index)) != -1)
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
            case 's':
                options.nopSpace = 1;
                break;
            case 't':
                options.totalNopSpace = 1;
                break;
			default:
				help(myProgramName);
				exit(1);
		}
	}

    // switches are set but there's no target configured
    if (optind > 1 && (argv+optind)[0] == NULL)
    {
        fprintf(stderr, "************************************\n");
        fprintf(stderr, "[ERROR] Target application required!\n");
        fprintf(stderr, "************************************\n");
        help(myProgramName);
        exit(1);
    }
    
    if (!freeDataSpace && allSections)
    {
        fprintf(stderr, "*****************************\n");
        fprintf(stderr, "[ERROR] -a option requires -f\n");
        fprintf(stderr, "*****************************\n");
        exit(1);
    }
    
    if (argc == 1)
    {
#if DEBUG
        printf("[DEBUG] No target configured\n");
#endif
        start_interactive_mode(NULL);
    }
    // no options given so go to interactive mode
    else if (optind <= 1 || argc-optind < 1 )
    {
#if DEBUG
        printf("[DEBUG] Target is %s\n", (argv+optind)[0]);
#endif
        start_interactive_mode((argv+optind)[0]);
    }
    // just process the target with the selected options
    else
    {
        uint8_t *targetBuffer = NULL;
        if (init_target((argv+optind)[0], &targetBuffer, &options))
            return 1;
        process_target(targetBuffer, options);
        free(targetBuffer);
    }
    return 0;
}


static void 
remove_newline(const char *line)
{
    char *pline = (char*)line;
    if ((pline = strchr(line, '\n')) != NULL)
        *pline = '\0';
}

void 
init_options(options_t *options)
{
    options->allSections   = 0;
    options->excelActive   = 0;
    options->freeDataSpace = 0;
    options->newCmdsActive = 0;
    options->iosActive     = 0;
    options->isFat         = 0;
    options->nopSpace      = 0;
    options->totalNopSpace = 0;
}

/*
 * aux function to clean the commands fields
 * these fields are used to find which command to execute
 */
void 
reset_options(options_t *options)
{
    options->freeDataSpace = 0;
    options->newCmdsActive = 0;
    options->nopSpace      = 0;
    options->totalNopSpace = 0;
}

/*
 * function that will read the target binary into our buffer
 * we process the Info.plist to find the binary name
 * then we read the binary into our buffer
 * and also verify if it's a valid and fat or not
 */
uint8_t 
init_target(char *targetPath, uint8_t **buf, options_t *options)
{
    char *target = NULL;
    @autoreleasepool {
        
        NSString *path = [NSString stringWithCString:targetPath encoding:NSUTF8StringEncoding];
        NSBundle *bundle = [NSBundle bundleWithPath:path];
        NSDictionary *plistData = [bundle infoDictionary];
        
        NSString *targetExe = (NSString*)[plistData objectForKey:@"CFBundleExecutable"];
        if (targetExe != nil)
        {
//            printf("[INFO] Main executable is %s at %s\n", [targetExe UTF8String], [path UTF8String]);
            NSString *tempString1;
            if (options->iosActive)
                tempString1 = path;
            else
                tempString1 = [path stringByAppendingPathComponent:@"Contents/MacOS"];
            
            NSString *tempTarget = [tempString1 stringByAppendingPathComponent:targetExe];
            target = malloc([tempTarget length] * sizeof(char)+1);
            [tempTarget getCString:target maxLength:[tempTarget length]+1 encoding:NSUTF8StringEncoding];
            NSFileManager *fm = [NSFileManager new];
            if (![fm fileExistsAtPath:tempTarget])
            {
                fprintf(stderr, "[ERROR] Can't find the target exe at %s\n", target);
                [fm release];
                return 1;
            }
            [fm release];
        }
        else
        {
            fprintf(stderr, "[ERROR] Can't find the target exe at %s\n", [path UTF8String]);
            return 1;
        }
    }
    // free the buffer to avoid memory leaks in interactive mode
    // if the new target fails to load we still hold the old one in memory
    free(*buf);
    // read target file into a buffer
    uint64_t fileSize = 0;
    fileSize = read_target(buf, target);
    
    // verify if it's a valid mach-o target
    uint32_t magic = *(uint32_t*)(*buf);
    if (magic == FAT_CIGAM)
    {
        options->isFat = 1;
    }
    else if (magic == MH_MAGIC || magic == MH_MAGIC_64)
    {
        options->isFat = 0;
    }
    else
    {
		fprintf(stderr, "[ERROR] Target %s is not a mach-o binary!\n", target);
        return 1;
    }
    free(target);
    return 0;
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
