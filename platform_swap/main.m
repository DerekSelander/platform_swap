//
//  main.m
//  platform_swap @LOLgrep
//  clang -o /tmp/platform_swap /path/to/platform_swap.m -framework Foundation

#include <Security/Security.h>
#import <Foundation/Foundation.h>
#import <mach-o/fat.h>
#import <mach-o/loader.h>

#define log_out(S, ...)   fprintf(stdout, S, ##__VA_ARGS__);
#define log_out_verbose(S, ...)  if (g_verbose) { fprintf(stdout, S, ##__VA_ARGS__); }
#define log_error(S, ...)  { fprintf(stderr, "ERR: %s:%5d " S, __FILE__, __LINE__, ##__VA_ARGS__);}

struct version {
    int fix : 8;
    int min : 8;
    int max : 16;
};

static const char *get_platform_str(int platform) {
    switch (platform) {
        case PLATFORM_MACOS:
            return  "macos";
        case PLATFORM_IOS:
            return  "ios";
        case PLATFORM_TVOS:
            return  "tvos";
        case PLATFORM_WATCHOS:
            return "watchos";
        case PLATFORM_BRIDGEOS:
            return  "bridgeos";
        case PLATFORM_MACCATALYST:
            return "maccatalyst";
        case PLATFORM_IOSSIMULATOR:
            return  "iossimulator";
        case PLATFORM_TVOSSIMULATOR:
            return  "tvossimulator";
        case PLATFORM_WATCHOSSIMULATOR:
            return  "watchossimulator";
        case PLATFORM_DRIVERKIT:
            return  "driverkit";
        case PLATFORM_ANY:
            return  "any";
        default:
            return "unkown";
    }
    return "unknown";
}

@interface NSData (ReplaceBytesInRange)

@end

static NSData* entitlements_data_for_file(const char *path) {
    NSString *strPath = [NSString stringWithCString:path encoding:NSUTF8StringEncoding];
    NSURL *url = [NSURL fileURLWithPath:strPath];
    SecStaticCodeRef staticCodeRef = nil;
    OSStatus status  = SecStaticCodeCreateWithPathAndAttributes((__bridge CFURLRef _Nonnull)(url), 0, (__bridge CFDictionaryRef _Nonnull)@{}, &staticCodeRef);
    
    CFDictionaryRef cfdict = NULL;
    status = SecCodeCopySigningInformation(staticCodeRef, kSecCSDefaultFlags, &cfdict);
    NSDictionary *dict = (__bridge_transfer NSDictionary*)cfdict;
    
    NSMutableData *data = [[NSMutableData alloc] initWithData:dict[@"entitlements"]];
    if (!data) {
        printf("executable didn't have entitlements");
        return nil;
    }
    NSRange range = NSMakeRange(0, data.length);
    // strip out the 0xfade7171 + uint32_length header
    [data replaceBytesInRange:range withBytes:data.bytes + (sizeof(uint32_t)*2) length:data.length - (sizeof(uint32_t)*2)];
    return data;
}
//
//void get_entitlements(char * path) {
//    NSURL *strPath = [NSString stringWithCString:path encoding:NSUTF8StringEncoding];
//    NSURL *url = [NSURL fileURLWithPath:strPath];
//    SecStaticCodeRef staticCodeRef = nil;
//    OSStatus status  = SecStaticCodeCreateWithPathAndAttributes((__bridge CFURLRef _Nonnull)(url), 0, (__bridge CFDictionaryRef _Nonnull)@{}, &staticCodeRef);
//
//    CFDictionaryRef cfdict = NULL;
//    status = SecCodeCopySigningInformation(staticCodeRef, kSecCSDefaultFlags, &cfdict);
//    NSDictionary *dict = (__bridge  NSDictionary*)cfdict;
//
//    NSLog(@"%@", dict);
//
////    SecStaticCodeCreateWithPath(url, <#SecCSFlags flags#>, <#CF_RETURNS_RETAINED SecStaticCodeRef  _Nullable *staticCode#>)
//}

static int ad_hoc_codesign_file(const char *path) {
    typedef struct __SecCodeSigner *SecCodeSignerRef;
    
    __attribute__((weak))
    OSStatus SecCodeSignerCreate(CFDictionaryRef parameters, SecCSFlags flags,
                                 SecCodeSignerRef *signer);
    
    __attribute__((weak))
    OSStatus SecCodeSignerAddSignature(SecCodeSignerRef signer,
                                       SecStaticCodeRef code, SecCSFlags flags);
    
    __attribute__((weak))
    OSStatus SecCodeSignerAddSignatureWithErrors(SecCodeSignerRef signer,
                                                 SecStaticCodeRef code, SecCSFlags flags, CFErrorRef *errors);
    
    __attribute__((weak))
    extern OSStatus SecStaticCodeCreateWithPathAndAttributes(CFURLRef path, SecCSFlags flags, CFDictionaryRef attributes,
                                                             SecStaticCodeRef * __nonnull CF_RETURNS_RETAINED staticCode);
    NSDictionary *dict = @{ @"signer" :  [NSNull null]};
    SecCodeSignerRef ref = NULL;
    if (!SecCodeSignerCreate || !SecCodeSignerAddSignature || !SecCodeSignerAddSignatureWithErrors) {
        log_error("SDK doesn't support the required APIs, are you on iOS 15+/macOS 10.5+?\n")
        return -1;
    }
    
    OSStatus status = SecCodeSignerCreate((__bridge CFDictionaryRef)(dict),  /*kSecCSDefaultFlags*/ 1, &ref);
    if (status) {
        log_error("SecCodeSignerCreate error: %d\n", status);
        return -1;
    }
    
    NSString *pathStr = [NSString stringWithCString:path encoding:NSUTF8StringEncoding];
    NSURL *url = [NSURL fileURLWithPath:pathStr];
    SecStaticCodeRef staticCodeRef = nil;
    
    status = SecStaticCodeCreateWithPathAndAttributes((__bridge CFURLRef _Nonnull)(url), 0, (__bridge CFDictionaryRef _Nonnull)@{}, &staticCodeRef);
    if (status) {
        log_error("SecStaticCodeCreateWithPathAndAttributes error: %d\n", status);
        return -1;
    }
    
    CFErrorRef error = NULL;
    status = SecCodeSignerAddSignatureWithErrors(ref, staticCodeRef, /*kSecCSDefaultFlags*/ 0 /* kSecCSRemoveSignature*/ , &error);
    if (status || error) {
        log_error("SecCodeSignerAddSignatureWithErrors error: %d\n", status);
        return -1;
    }
    
    /*
     NSDictionary *verifyDict = nil;
     CFDictionaryRef omg = (__bridge CFDictionaryRef)verifyDict;
     status = SecCodeCopySigningInformation(staticCodeRef , kSecCSDynamicInformation | kSecCSSigningInformation | kSecCSRequirementInformation | kSecCSInternalInformation, &omg);
     */
    
    
    return 0;
}


int main(int argc, const char * argv[]) {
    char path[PATH_MAX] = {};
    
    if (argc != 6 && argc != 2) {
        log_out("platform_swap /path/to/file platform_num major minor bugfix,  built on: %s, %s\n\tEX. to convert MacOS M1 binary to iOS 10.3.1 -> platform_swap /tmp/afile 2 10 3 1      # See PLATFORM_* in <mach-o/loader.h>\n", __DATE__, __TIME__);
        exit(1);
    }
    
    if (realpath(argv[1], path) == NULL) {
        log_error("error resolving %s", argv[1]);
    }
    NSString *file = [NSString stringWithUTF8String:path];
    NSURL *fileURL = [NSURL fileURLWithPath:file];
    
    if (!fileURL) {
        log_error("Can't find file %s\n", path);
        exit(1);
    }
    
    NSMutableData *data = [NSMutableData dataWithContentsOfFile:file];
    char *ptr = (void*)[data bytes];
    if (!ptr) {
        log_error("couldn't open file %s\n", file.UTF8String);
        exit(1);
    }
    int32_t *magic = (int32_t*)ptr;
    
    if (*magic != MH_MAGIC_64) {
        if (*magic == FAT_CIGAM || *magic == FAT_MAGIC || *magic == FAT_MAGIC_64 || *magic == FAT_CIGAM_64) {
            log_error("fat file. Use \"lipo -thin <ARCH> -o /tmp/new_file %s\" first\n", path);
        }
        
        log_error("Invalid header file\n");
        exit(1);
    }
    
    struct mach_header_64 *header = (void*)ptr;
    struct load_command *cur = (void*)((uintptr_t)ptr + (uintptr_t)sizeof(struct mach_header_64));
    
    
    
    if (argc == 2) {
        for (int i = 0; i < header->ncmds; i++) {
            if (cur->cmd == LC_BUILD_VERSION) {
                struct build_version_command* build = (void*)cur;
                struct version *v = (void*)&build->minos;
                struct version *sdk = (void*)&build->sdk;
                log_out("%s (%d) %d.%d.%d, built with sdk: %d.%d.%d\nplatform_swap %s %d %d %d %d\n", get_platform_str(build->platform), build->platform, v->max, v->min, v->fix, sdk->max, sdk->min, sdk->fix, path, build->platform, v->max, v->min
                       , v->fix);
                exit(0);
            }
            cur = (void*)(cur->cmdsize  + (uintptr_t)cur);
        }
        log_error("couldn't find LC_BUILD_VERSION in file \"%s\"\n", path);
        exit(1);
    }
    
    long platform = strtol(argv[2], NULL, 10);
    long major  = strtol(argv[3], NULL, 10);
    long minor  = strtol(argv[4], NULL, 10);
    long bugfix = strtol(argv[5], NULL, 10);
    
    char * endOfHeader = header->sizeofcmds + ptr + sizeof(struct mach_header_64);
    // we only need this if we are converting to iOS simulator
    NSData *entitlementsData = platform == PLATFORM_IOSSIMULATOR && getenv("ENTITLEMENTS") ? entitlements_data_for_file(path) : nil;
    for (int i = 0; i < header->ncmds; i++) {
        
        if (entitlementsData) {
            bool needsEntitlementPatching = true;
            if (cur->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *segment = (void*)cur;
                
                if (!strncmp(segment->segname, "__PAGEZERO", 16)) {
                    struct segment_command_64 *segment = (void*)cur;
                    segment->initprot = 5;
                    segment->maxprot = 5;

                }
                
                if (!strncmp(segment->segname, "__TEXT", 16)) {
                    struct section_64 *section = (void*)((uintptr_t)cur + sizeof(struct segment_command_64));
                    for (int k = 0 ; k < segment->nsects; k++) {
                        // need to make sure there's enough space after the mach header and before the code
                        if (k == 0) {
                            if (section->offset - (header->sizeofcmds + sizeof(struct mach_header_64)) > (sizeof(struct section_64) * 2) + entitlementsData.length) {
                                log_error("we dont have enough space after the mach-o header to inset the entitlements\n");
                                exit(1);
                            }
                        }
                        if (!strcmp(section->sectname, "__entitlements") || !strcmp(section->sectname, "__ent_der")) {
                            needsEntitlementPatching = false;
                            break;
                        }
                        section++; /* beware, pointer arithmetic */
                    }
                    
                    uintptr_t space_remaining = segment->vmaddr + segment->vmsize - section->addr + section->size;
                    
                    
                    if (!([entitlementsData length] + sizeof(struct section_64) * 2 < space_remaining)) {
                        log_error("we don't have enoug padding to insert the sim entitlements\n");
                        exit(1);
                    }
                    
//                    segment->vmsize += [entitlementsData length];
//                    segment->
                    segment->cmdsize += (sizeof(struct section_64) * 2);
                    segment->nsects += 2;
                    header->sizeofcmds += (sizeof(struct section_64) * 2) ;
                    NSMutableData *replacedHeader = [NSMutableData dataWithBytes:data.bytes length:((uintptr_t)section - (uintptr_t)header)];
                    
                    
                    struct section_64 entsect = {
                        .sectname = "__entitlements",    /* name of this section */
                        .segname = "__TEXT",    /* segment this section goes in */
                        .addr =  section[-2].addr + section[-2].size, /*section->addr + section->size + (sizeof(struct section_64) * 2),         memory address of this section */
                        .size =  entitlementsData.length,     /* size in bytes of this section */
                        .offset = 0, //sizeof(struct mach_header_64) + header->sizeofcmds,         /* file offset of this section */
                        .align = 0,         /* section alignment (power of 2) */
                        .reloff = 0,         /* file offset of relocation entries */
                        .nreloc = 0,         /* number of relocation entries */
                        .flags = 0,         /* flags (section type and attributes)*/
                        .reserved1 = 0,     /* reserved (for offset or index) */
                        .reserved2 = 0,     /* reserved (for count or sizeof) */
                        .reserved3 = 0,     /* reserved */
                    };
                    [replacedHeader appendBytes:&entsect length:sizeof(entsect)];
                    
                    struct section_64 der_entsect = {
                        .sectname = "__ent_der",    /* name of this section */
                        .segname = "__TEXT",    /* segment this section goes in */
//                        .addr =  section[-2].addr + section[-2].size, /*section->addr + section->size + (sizeof(struct section_64) * 2),         memory address of this section */
                        .size =  0,     /* size in bytes of this section */
                        .offset = 0, //sizeof(struct mach_header_64) + header->sizeofcmds,         /* file offset of this section */
                        .align = 0,         /* section alignment (power of 2) */
                        .reloff = 0,         /* file offset of relocation entries */
                        .nreloc = 0,         /* number of relocation entries */
                        .flags = 0,         /* flags (section type and attributes)*/
                        .reserved1 = 0,     /* reserved (for offset or index) */
                        .reserved2 = 0,     /* reserved (for count or sizeof) */
                        .reserved3 = 0,     /* reserved */
                    };
                    [replacedHeader appendBytes:&der_entsect length:sizeof(struct section_64)];
                    
//                    ReplaceIndexedCollectionItemHdl(/*<#Collection aCollection#>*/, <#SInt32 itemIndex#>, <#Handle itemData#>)
                    
//                    [replacedHeader appendBytes:(void*)((uintptr_t)cur + cur->cmdsize)  length: header->sizeofcmds - ((uintptr_t)section - (uintptr_t)header)];
//                    [replacedHeader appendData:entitlementsData];
                    
//                    NSRange range = NSMakeRange(0, header->sizeofcmds - ((uintptr_t)&section[1] - (uintptr_t)header)  + sizeof(struct mach_header_64));
                    NSRange range = NSMakeRange(0,  ((uintptr_t)section - (uintptr_t)header));
                    [data replaceBytesInRange:range withBytes:replacedHeader.bytes length:replacedHeader.length];
                    
                }
            }
        }
        
        if (cur->cmd == LC_BUILD_VERSION) {
            struct build_version_command*build = (void*)cur;
            NSRange platform_range = NSMakeRange((uintptr_t)&build->platform - (uintptr_t)ptr, sizeof(build->platform));
            int32_t new_platform = (int)platform;
            [data replaceBytesInRange:platform_range withBytes:&new_platform];
            
            NSRange version_range = NSMakeRange((uintptr_t)&build->minos - (uintptr_t)ptr, sizeof(build->minos));
            struct version new_version = {(int)bugfix, (int)minor, (int)major};
            [data replaceBytesInRange:version_range withBytes:&new_version];
            const char *platform_name = get_platform_str(build->platform);
            
            
            NSString *resolvedString = nil;
            if (getenv("INPLACE")) {
                resolvedString = [NSString stringWithFormat:@"%@", file];
            } else {
               resolvedString = [NSString stringWithFormat:@"%@_%s", file, platform_name];
            }
            
            if (!getenv("DRYRUN")) {
                [data writeToFile:resolvedString atomically:YES];
                if (getenv("ADHOC")) {
                    log_out("ad hoc code signing file.... \n");
                    int err = ad_hoc_codesign_file(resolvedString.UTF8String);
                    if (err) {
                        return err;
                    }
                }
            } else {
                log_out("[DRY RUN]");
            }
            
            log_out("writting to file: %s\n", resolvedString.UTF8String);
            
            
            exit(0);
        }
        
        cur = (void*)(cur->cmdsize  + (uintptr_t)cur);
    }
    
    return 0;
}
