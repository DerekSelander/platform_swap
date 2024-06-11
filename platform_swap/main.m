//
//  main.m
//  platform_swap @LOLgrep
//  clang -o /tmp/platform_swap /path/to/platform_swap.m -framework Foundation

#include <Security/Security.h>
#import <Foundation/Foundation.h>
#import <mach-o/fat.h>
#import <mach-o/loader.h>

static int g_verbose = 0;

#define log_out(S, ...)   fprintf(stdout, S, ##__VA_ARGS__);
#define log_out_verbose(S, ...)  if (g_verbose) { fprintf(stdout, S, ##__VA_ARGS__); }
#define log_error(S, ...)  { fprintf(stderr, "ERR: %s:%5d " S, __FILE__, __LINE__, ##__VA_ARGS__);}
#define log_error_and_die(S, ...)  { fprintf(stderr, "ERR: %s:%5d " S, __FILE__, __LINE__, ##__VA_ARGS__); exit(1);}

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
    if (!data || data.length  == 0) {
        log_out("executable didn't have entitlements\n");
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

static int ad_hoc_codesign_file(const char *path, NSString *identifier) {
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
    
    OSStatus status = SecCodeSignerCreate((__bridge CFDictionaryRef)(dict),  /*kSecCSDefaultFlags*/ 0, &ref);
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


static void patchup_lc_offsets(struct mach_header_64 *header, uint32_t delta) {
    if (!header) {
        return;
    }
    if (delta == 0) {
        return;
    }
    
    struct load_command *cur = (void*)((uintptr_t)header + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < header->ncmds; i++, cur = (void*)((uintptr_t)cur + cur->cmdsize)) {
        struct segment_command_64 *segment = (void*)cur;
        struct dysymtab_command *dsym = (void*)cur;
        struct symtab_command *symtab = (void*)cur;
        struct linkedit_data_command *linkedit = (void*)cur;
        struct encryption_info_command_64 *encryption = (void*)cur;
        struct dyld_info_command *dyld = (void*)cur;
        struct note_command *note = (void*)cur;
        struct fileset_entry_command *fileentry = (void*)cur;
        
        switch (cur->cmd) {
            case LC_SEGMENT_64:
                segment->fileoff += segment->fileoff ? delta : 0;
                struct section_64 *sect = (void*)((uintptr_t)cur + sizeof(struct segment_command_64));
                for (uint32_t k = 0; k < segment->nsects; k++) {
                    sect[i].offset += sect[i].offset ? delta : 0;
                }
                break;
            case LC_DYSYMTAB:
                dsym->extrefsymoff += dsym->extrefsymoff ? delta : 0;
                dsym->extreloff += dsym->extreloff ? delta : 0;
                dsym->tocoff += dsym->tocoff ? delta : 0;
                dsym->locreloff += dsym->locreloff ? delta : 0;
                dsym->modtaboff += dsym->modtaboff ? delta : 0;
                dsym->indirectsymoff += dsym->indirectsymoff ? delta : 0;
                break;
            case LC_CODE_SIGNATURE:
            case LC_SEGMENT_SPLIT_INFO:
            case LC_FUNCTION_STARTS:
            case LC_DATA_IN_CODE:
            case LC_DYLIB_CODE_SIGN_DRS:
            case LC_ATOM_INFO:
            case LC_LINKER_OPTIMIZATION_HINT:
            case LC_DYLD_EXPORTS_TRIE:
            case LC_DYLD_CHAINED_FIXUPS:
                linkedit->dataoff += linkedit->dataoff ? delta : 0;
                break;
            case LC_ENCRYPTION_INFO_64:
                encryption->cryptoff += encryption->cryptoff ? delta : 0;
                break;
            case LC_SYMTAB:
                symtab->stroff += symtab->stroff ? delta : 0;
                symtab->symoff += symtab->symoff ? delta : 0;
                break;
            case LC_DYLD_INFO:
                dyld->bind_off += dyld->bind_off ? delta : 0;
                dyld->export_off += dyld->export_off ? delta : 0;
                dyld->rebase_off += dyld->rebase_off ? delta : 0;
                dyld->lazy_bind_off += dyld->lazy_bind_off ? delta : 0;
                dyld->weak_bind_off += dyld->weak_bind_off ? delta : 0;
                break;
            case LC_NOTE:
                note->offset += note->offset ? delta : 0;
                break;
            case LC_FILESET_ENTRY:
                fileentry->fileoff += fileentry->fileoff ? delta : 0;
            default:
                break;
        }
        
    }
}

int main(int argc, const char * argv[]) {
    char path[PATH_MAX] = {};
    
    bool needsNCmdsDec = false;
    bool needsNCmdsOffsetPatchups = false;
    bool shouldInsertDylib = getenv("INJECT")  ? true : false;
    bool isMainExecutable = false;
    
    
    if (argc != 6 && argc != 2) {
        log_error_and_die("platform_swap /path/to/file platform_num major minor bugfix,  built on: %s, %s\n\tEX. to convert MacOS M1 binary to iOS 10.3.1 -> platform_swap /tmp/afile 2 10 3 1      # See PLATFORM_* in <mach-o/loader.h>\n", __DATE__, __TIME__);
    }
    
    if (realpath(argv[1], path) == NULL) {
        log_error("error resolving %s", argv[1]);
    }
    NSString *file = [NSString stringWithUTF8String:path];
    NSURL *fileURL = [NSURL fileURLWithPath:file];
    
    if (!fileURL) {
        log_error_and_die("Can't find file %s\n", path);
    }
    
    NSMutableData *data = [NSMutableData dataWithContentsOfFile:file];
    char *ptr = (void*)data.bytes;
    if (!ptr) {
        log_error_and_die("couldn't open file %s\n", file.UTF8String);
    }
    int32_t *magic = (int32_t*)ptr;
    
    if (*magic != MH_MAGIC_64) {
        if (*magic == FAT_CIGAM || *magic == FAT_MAGIC || *magic == FAT_MAGIC_64 || *magic == FAT_CIGAM_64) {
            log_error("fat file. Use \"lipo -thin <ARCH> -o /tmp/new_file %s\" first\n", path);
        }
        log_error_and_die("Invalid header file\n");
    }
    
    struct mach_header_64 *header = (void*)ptr;
    
    
    
    if (argc == 2) {
        struct load_command *cur = (void*)((uintptr_t)ptr + (uintptr_t)sizeof(struct mach_header_64));
        for (int i = 0; i < header->ncmds; i++) {
            if (cur->cmd == LC_BUILD_VERSION) {
                struct build_version_command* build = (void*)cur;
                struct version *v = (void*)&build->minos;
                struct version *sdk = (void*)&build->sdk;
                log_out("%s (%d) %d.%d.%d, built with sdk: %d.%d.%d\nplatform_swap %s %d %d %d %d\n", get_platform_str(build->platform), build->platform, v->max, v->min, v->fix, sdk->max, sdk->min, sdk->fix, path, build->platform, v->max, v->min
                       , v->fix);
            }
            cur = (void*)(cur->cmdsize  + (uintptr_t)cur);
        }
    }
    
    long platform = strtol(argv[2], NULL, 10);
    long major  = strtol(argv[3], NULL, 10);
    long minor  = strtol(argv[4], NULL, 10);
    long bugfix = strtol(argv[5], NULL, 10);
    char * endOfHeader = header->sizeofcmds + ptr + sizeof(struct mach_header_64);
    struct segment_command_64 *linkedit_segment = NULL;
    
    


    struct load_command *cur = (void*)((uintptr_t)ptr + (uintptr_t)sizeof(struct mach_header_64));
    for (int i = 0; i < header->ncmds; i++) {
        
        // remove the signature if applicable
        if (cur->cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command *lc_sig = (void*)cur;
            assert(i == header->ncmds - 1);
            if (!linkedit_segment) {
                log_error_and_die("We found the LC_CODE_SIGNATURE before the linkedit? The fuck?\n");
            }
            [data replaceBytesInRange:NSMakeRange(lc_sig->dataoff, lc_sig->datasize) withBytes:NULL length:0];
            header->sizeofcmds -= sizeof(struct linkedit_data_command);
            header->ncmds--;
            linkedit_segment->filesize -= lc_sig->datasize;
            log_out_verbose("removing LC_CODE_SIGNATURE\n");
        }
        
        // only pagezero is on the main exe
        if (cur->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *segment = (void*)cur;
            if (!strncmp(segment->segname, "__PAGEZERO", 16)) {
                isMainExecutable = true;
            }
            
            // grab linkedit segment from stripping code signature
            if (!strncmp(segment->segname, "__LINKEDIT", 16)) {
                linkedit_segment = segment;
            }
        }
        cur = (void*)(cur->cmdsize  + (uintptr_t)cur);
    }

    cur = (void*)((uintptr_t)ptr + (uintptr_t)sizeof(struct mach_header_64));
    // only entitlements on executables, not libraries
    NSData *entitlementsData = (platform == PLATFORM_IOSSIMULATOR && isMainExecutable) ? entitlements_data_for_file(path) : nil;
    const char* entPath = getenv("ENTITLEMENTS");
    if (entPath && isMainExecutable) {
        entitlementsData = [NSData dataWithContentsOfFile:[NSString stringWithCString:entPath encoding:NSUTF8StringEncoding]];
        if (!entitlementsData) {
            log_error_and_die("bad file %s\n", entPath);
        }
    }
    
    
// This is kinda fugly but I want a safe amount of memory for the entitlements but don't want to mess other offsets up, so instead of inserting into potentially tightly packed RX mem, I'll just expand the intial RX memory borrowing from PAGEZERO
//#define SAFE_PAGE 0x4000
#define INSERTED_SECTION_COUNT 1
    bool needsBuildVersionAddition = true;
    for (int i = 0; i < header->ncmds; i++) {
        
        // these are just annoying throw them out
        if (cur->cmd == LC_VERSION_MIN_TVOS || cur->cmd == LC_VERSION_MIN_MACOSX || cur->cmd == LC_VERSION_MIN_WATCHOS || cur->cmd == LC_VERSION_MIN_IPHONEOS) {
            struct version_min_command min = {
                .cmd = LC_RPATH,
                .cmdsize = sizeof(struct version_min_command),
                .version = 0,
                .sdk = 0,
            };
            NSRange range = NSMakeRange((uintptr_t)cur - (uintptr_t)header, sizeof(struct version_min_command));
            [data replaceBytesInRange:range withBytes:&min];
            header = (void*)data.bytes;
            log_out("found a patched out a LC_VERSION_MIN\n");
        }
        
        // extract the entitlements that are codesigned, stick them into mach-o sections, then resign as adhoc
        if (entitlementsData) {
            bool needsEntitlementPatching = true;
            if (cur->cmd == LC_SEGMENT_64) {
                
                struct segment_command_64 *segment = (void*)cur;
                if (!strncmp(segment->segname, "__LINKEDIT", 16)) {
                    segment->filesize += entitlementsData.length;
                }
                
                if (!strncmp(segment->segname, "__TEXT", 16)) {
                    needsNCmdsOffsetPatchups = true;
                    
                    struct section_64 *section = (void*)((uintptr_t)cur + sizeof(struct segment_command_64));
                    struct section_64 *first_sect = section;
                    
                    for (int k = 0 ; k < segment->nsects; k++) {
                        // need to make sure there's enough space after the mach header and before the code
                        if (k == 0) {
                            // check for physical space on file
                            if (section->offset - (header->sizeofcmds + sizeof(struct mach_header_64)) < (sizeof(struct section_64) * INSERTED_SECTION_COUNT)) {
                                log_error_and_die("we dont have enough disk space after the mach-o header to inset the entitlements\n");
                            }
                            
                            // check for virtual space when loaded, we want to insert them virtually before
                            // the __text start
                            if (entitlementsData.length  > section->addr - segment->vmaddr - sizeof(struct mach_header_64) - sizeof(struct section_64) - sizeof(header->sizeofcmds)) {
                                log_error_and_die("dont have enough virtual space after the mach-o header to inset the entitlements\n");
                            }
                        }
                        
                        if (!strcmp(section->sectname, "__entitlements") || !strcmp(section->sectname, "__ents_der")) {
                            log_out("%s.%s already exists in binary, not adding entitlements\n",  section->segname, section->sectname);
                            needsEntitlementPatching = false;
                        }
                        section++; /* beware, pointer arithmetic */
                    }
                    
                    if (needsEntitlementPatching) {
                        uintptr_t next_segment = (uintptr_t)section;
                        
                        uintptr_t space_remaining = segment->vmaddr + segment->vmsize - section->addr + section->size;
                        if (!([entitlementsData length] + sizeof(struct section_64) * INSERTED_SECTION_COUNT < space_remaining)) {
                            log_error_and_die("we don't have enoug padding to insert the sim entitlements, size of entitlements: %lu, space remaining %lu at 0x%llx\n", entitlementsData.length + sizeof(struct section_64) * INSERTED_SECTION_COUNT, space_remaining, segment->vmaddr);
                        }
                        
                        segment->cmdsize += (sizeof(struct section_64) * INSERTED_SECTION_COUNT);
                        segment->nsects += INSERTED_SECTION_COUNT;
                        header->sizeofcmds += (sizeof(struct section_64) * INSERTED_SECTION_COUNT);
                        
                        // get the data up to the next mach-o segment (yes, section here is actually pointing to a segment as it ran past its count)
                        uintptr_t length = (uintptr_t)next_segment - (uintptr_t)header;
                        NSMutableData *replacedHeader = [NSMutableData dataWithBytes:data.bytes length:length];
                        
                        uintptr_t initial_length = data.length;
                        
                        struct section_64 entsect = {
                            .sectname = "__entitlements",    /* name of this section */
                            .segname = "__TEXT",    /* segment this section goes in */
                            .addr = first_sect->addr - entitlementsData.length,
                            .size = entitlementsData.length,
                            .offset = (uint32_t)data.length,
                            .align = 0,         /* section alignment (power of 2) */
                            .reloff = 0,         /* file offset of relocation entries */
                            .nreloc = 0,         /* number of relocation entries */
                            .flags = 0,         /* flags (section type and attributes)*/
                            .reserved1 = 0,     /* reserved (for offset or index) */
                            .reserved2 = 0,     /* reserved (for count or sizeof) */
                            .reserved3 = 0,     /* reserved */
                        };
                        [replacedHeader appendBytes:&entsect length:sizeof(entsect)];
    
//                        struct section_64 entsectDer = {
//                            .sectname = "__ents_der",    /* name of this section */
//                            .segname = "__TEXT",    /* segment this section goes in */
//                            //                        .addr =  first_sect->addr - entitlementsData.length,
//                            //                        .addr =  data.length - (found_signature_lc ? found_signature_lc->datasize : 0),
//                            .addr = 0,
//                            //                        .addr =  section[-2].addr + section[-2].size, /*section->addr + section->size + (sizeof(struct section_64) * 2),         memory address of this section */
//                            .size = 0,
//                            //                        .size =  entitlementsData.length,     /* size in bytes of this section */
//                            .offset = (uint32_t)data.length,
//                            .align = 0,         /* section alignment (power of 2) */
//                            .reloff = 0,         /* file offset of relocation entries */
//                            .nreloc = 0,         /* number of relocation entries */
//                            .flags = 0,         /* flags (section type and attributes)*/
//                            .reserved1 = 0,     /* reserved (for offset or index) */
//                            .reserved2 = 0,     /* reserved (for count or sizeof) */
//                            .reserved3 = 0,     /* reserved */
//                        };
//                        [replacedHeader appendBytes:&entsectDer length:sizeof(entsectDer)];
                        
                        [replacedHeader appendBytes:&((char*)data.bytes)[length] length:header->sizeofcmds - length + sizeof(struct mach_header_64)];
                        
                        //                    ReplaceIndexedCollectionItemHdl(/*<#Collection aCollection#>*/, <#SInt32 itemIndex#>, <#Handle itemData#>)
                        
                        //                    [replacedHeader appendBytes:(void*)((uintptr_t)cur + cur->cmdsize)  length: header->sizeofcmds - ((uintptr_t)section - (uintptr_t)header)];
//                        [replacedHeader appendData:entitlementsData];
                        
                        //                    NSRange range = NSMakeRange(0, header->sizeofcmds - ((uintptr_t)&section[1] - (uintptr_t)header)  + sizeof(struct mach_header_64));
                        
                        // make the range before the header could be mutated from the NSMutableData mutation
                        NSRange range = NSMakeRange(0,  replacedHeader.length);
                        [data replaceBytesInRange:range withBytes:replacedHeader.bytes length:replacedHeader.length];
                        [replacedHeader writeToFile:@"/tmp/cmon" atomically:YES];
                    }
                    [data appendData:entitlementsData];
                    
                    // we need to regen the header after an NSMutableData mutation
                    header = (void*)data.bytes;
                    
                    // we final patch, now that we know the size, tell the entitlements section where the data will be
                    
                }
            }
        }
        
        
//        if (!strncmp(segment->segname, "__PAGEZERO", 16)) {
//            struct segment_command_64 *segment = (void*)cur;
//            segment->initprot = 5;
//            segment->maxprot = 5;
//        }
        
//        if (shouldInsertDylib && i == header->ncmds - 1) {
//            struct my_dylib_command {
//                uint32_t    cmd;
//                uint32_t    cmdsize;    /* includes pathname string */
//                struct dylib    dylib;        /* the library identification */
//                char path[16];
//            } lc = {
//                .cmd = LC_LOAD_DYLIB,
//                .cmdsize = sizeof(struct my_dylib_command),
//                .dylib = {
//                    .name.offset = sizeof(struct dylib_command),
//                },
//                    .path = "/tmp/x.dylib"
//            };
//            
//            if (found_signature_lc) {
//                struct segment_command_64 sig_cmd = {};
//                memcpy(&sig_cmd, found_signature_lc, sizeof(sig_cmd));
//                memcpy(found_signature_lc, &lc, sizeof(lc));
//                memcpy((char*)found_signature_lc + sizeof(lc), &sig_cmd, sizeof(sig_cmd));
//            } else {
//                memcpy((char*)header + sizeof(struct mach_header_64) + header->ncmds, &lc, sizeof(lc));
//            }
//            
//            header->sizeofcmds += sizeof(lc);
//            header->ncmds++;
//            break;
//        }


        
        // patch the version to the proper platform
        if (cur->cmd == LC_BUILD_VERSION) {
            log_out("found LC_BUILD_VERSION! patching....\n");
            struct build_version_command*build = (void*)cur;
            NSRange platform_range = NSMakeRange((uintptr_t)&build->platform - (uintptr_t)ptr, sizeof(build->platform));
            int32_t new_platform = (int)platform;
            [data replaceBytesInRange:platform_range withBytes:&new_platform];
            
            NSRange version_range = NSMakeRange((uintptr_t)&build->minos - (uintptr_t)ptr, sizeof(build->minos));
            struct version new_version = {(int)bugfix, (int)minor, (int)major};
            [data replaceBytesInRange:version_range withBytes:&new_version];
            header = (void*)data.bytes;
            needsBuildVersionAddition = false;
        }
        
        cur = (void*)(cur->cmdsize  + (uintptr_t)cur);
    }
    
    // add an LC_BUILD_VERSION if there was none
    if (needsBuildVersionAddition) {
        log_out("creating LC_BUILD_VERSION at end....\n");
        struct version new_version = {(int)bugfix, (int)minor, (int)major};
        struct version sdk = {(int)bugfix, (int)minor, (int)major};
        
        struct build_version_command build = {
            .cmd = LC_BUILD_VERSION,
            .cmdsize = sizeof(struct build_version_command),
            .platform = (uint32_t)platform,
            .minos = *(uint32_t*)&new_version,
            .sdk = *(uint32_t*)&sdk,
            .ntools = 0,
        };
        NSRange range = NSMakeRange((uintptr_t)cur - (uintptr_t)ptr, sizeof(struct build_version_command));
        
        [data replaceBytesInRange:range withBytes:&build];
        header = (void*)data.bytes;
        header->ncmds++;
        header->sizeofcmds += sizeof(struct build_version_command);
    }
    
//    // set when we stripped out the signature
//    if (needsNCmdsDec) {
//        header = (void*)data.bytes;
//        header->ncmds--;
//    }
    
    if (needsNCmdsOffsetPatchups) {
//        patchup_lc_offsets((void*)data.bytes, sizeof(struct section_64) * INSERTED_SECTION_COUNT);
    }
    
    NSString *resolvedString = nil;
    if (getenv("INPLACE")) {
        resolvedString = [NSString stringWithFormat:@"%@", file];
    } else {
        const char *platform_name = get_platform_str((int)platform);
        resolvedString = [NSString stringWithFormat:@"%@_%s", file, platform_name];
    }
    if (!getenv("DRYRUN")) {
        [data writeToFile:resolvedString atomically:YES];
        if (getenv("ADHOC")) {
            log_out("ad hoc code signing file.... \n");
            int err = ad_hoc_codesign_file(resolvedString.UTF8String, nil);
            if (err) {
                return err;
            }
        }
    } else {
        log_out("[DRY RUN]");
    }
    
    log_out("writting to file: %s\n", resolvedString.UTF8String);
    
    return 0;
}
