/*
* Copyright 2020, @Ralph0045
* gcc Kernel64Patcher.c -o Kernel64Patcher
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "patchfinder64.c"

#define GET_OFFSET(kernel_len, x) (x - (uintptr_t) kernel_buf)

// iOS 8 arm64
int get_dealwith_activation_patch_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char* str = "dealwith_activation";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str));
    if(!ent_loc) {
        printf("%s: Could not find \"dealwith_activation\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"dealwith_activation\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
       printf("%s: Could not find \"dealwith_activation\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"dealwith_activation\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t beg_func = bof64(kernel_buf,0,xref_stuff);
    if(!beg_func) {
       printf("%s: Could not find \"dealwith_activation\" funcbegin insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching \"dealwith_activation\" at %p\n\n", __FUNCTION__,(void*)(beg_func));
    // 0xD503201F is nop
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result
    *(uint32_t *) (kernel_buf + beg_func) = 0x52800000; // mov w0, 0x0
    *(uint32_t *) (kernel_buf + beg_func + 0x4) = 0xD65F03C0; // ret
    return 0;
}

// iOS 8 arm64
int get_handle_deactivate_patch_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char* str = "handle_deactivate";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str));
    if(!ent_loc) {
        printf("%s: Could not find \"handle_deactivate\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"handle_deactivate\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
       printf("%s: Could not find \"handle_deactivate\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"handle_deactivate\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t beg_func = bof64(kernel_buf,0,xref_stuff);
    if(!beg_func) {
       printf("%s: Could not find \"handle_deactivate\" funcbegin insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching \"handle_deactivate\" at %p\n\n", __FUNCTION__,(void*)(beg_func));
    // 0xD503201F is nop
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result
    *(uint32_t *) (kernel_buf + beg_func) = 0x52800000; // mov w0, 0x0
    *(uint32_t *) (kernel_buf + beg_func + 0x4) = 0xD65F03C0; // ret
    return 0;
}

// iOS 8 arm64
int get_check_build_expired_patch_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char* str = "check_build_expired";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str));
    if(!ent_loc) {
        printf("%s: Could not find \"check_build_expired\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"check_build_expired\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
       printf("%s: Could not find \"check_build_expired\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"check_build_expired\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t beg_func = bof64(kernel_buf,0,xref_stuff);
    if(!beg_func) {
       printf("%s: Could not find \"check_build_expired\" funcbegin insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching \"check_build_expired\" at %p\n\n", __FUNCTION__,(void*)(beg_func));
    // 0xD503201F is nop
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result
    *(uint32_t *) (kernel_buf + beg_func) = 0x52800000; // mov w0, 0x0
    *(uint32_t *) (kernel_buf + beg_func + 0x4) = 0xD65F03C0; // ret
    return 0;
}

int main(int argc, char **argv) {
    
    printf("%s: Starting...\n", __FUNCTION__);
    
    FILE* fp = NULL;
    
    if(argc < 4){
        printf("Usage: %s <mobactivationd_in> <mobactivationd_out> <args>\n",argv[0]);
        printf("\t-b\t\tPatch dealwith_activation (iOS 8 Only)\n");
        printf("\t-c\t\tPatch handle_deactivate (iOS 8 Only)\n");
        printf("\t-d\t\tPatch check_build_expired (iOS 8 Only)\n");
        
        return 0;
    }
    
    void* kernel_buf;
    size_t kernel_len;
    
    char *filename = argv[1];
    
    fp = fopen(argv[1], "rb");
    if(!fp) {
        printf("%s: Error opening %s!\n", __FUNCTION__, argv[1]);
        return -1;
    }
    
    fseek(fp, 0, SEEK_END);
    kernel_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    kernel_buf = (void*)malloc(kernel_len);
    if(!kernel_buf) {
        printf("%s: Out of memory!\n", __FUNCTION__);
        fclose(fp);
        return -1;
    }
    
    fread(kernel_buf, 1, kernel_len, fp);
    fclose(fp);
    
    if(memmem(kernel_buf,kernel_len,"KernelCacheBuilder",18)) {
        printf("%s: Detected IMG4/IM4P, you have to unpack and decompress it!\n",__FUNCTION__);
        return -1;
    }
    
    if (*(uint32_t*)kernel_buf == 0xbebafeca) {
        printf("%s: Detected fat macho kernel\n",__FUNCTION__);
        memmove(kernel_buf,kernel_buf+28,kernel_len);
    }
    
    init_kernel(0, filename);
    
    for(int i=0;i<argc;i++) {
        if(strcmp(argv[i], "-b") == 0) {
            printf("Kernel: Adding dealwith_activation patch...\n");
            get_dealwith_activation_patch_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-c") == 0) {
            printf("Kernel: Adding handle_deactivate patch...\n");
            get_handle_deactivate_patch_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-d") == 0) {
            printf("Kernel: Adding check_build_expired patch...\n");
            get_check_build_expired_patch_ios8(kernel_buf,kernel_len);
        }
    }
    
    term_kernel();
    
    /* Write patched kernel */
    printf("%s: Writing out patched file to %s...\n", __FUNCTION__, argv[2]);
    
    fp = fopen(argv[2], "wb+");
    if(!fp) {
        printf("%s: Unable to open %s!\n", __FUNCTION__, argv[2]);
        free(kernel_buf);
        return -1;
    }
    
    fwrite(kernel_buf, 1, kernel_len, fp);
    fflush(fp);
    fclose(fp);
    
    free(kernel_buf);
    
    printf("%s: Quitting...\n", __FUNCTION__);
    
    return 0;
}
