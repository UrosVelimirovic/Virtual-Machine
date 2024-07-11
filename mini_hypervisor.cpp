#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <cstring>
#include <cstdint>
#include <linux/kvm.h>
#include <pthread.h>
using namespace std;

size_t MEM_SIZE = 0;
size_t PAGE_SIZE = 0;
char** IMG = nullptr;
size_t IMG_COUNT = 0;
char** FILES = nullptr;
size_t FILE_COUNT = 0;

const char* ARGUMENT_NAMES[] ={
    "-m", "--memory",
    "-p", "--page",
    "-g", "--guest",
    "-f", "--file",
};

#define FILE_OP_SUCCESSFUL 1
#define FILE_OP_FAILED 0

#define FOPEN 1
#define FCLOSE 2
#define FREAD 3
#define FWRITE 4

#define FILE_PORT 0x0278


typedef struct{
    char* IMG;
    int id;
} Thread_param;


typedef struct{
    char filename[256];
    int op;
    int status;
    int counter;
    char buffer[512];
    int WR_size;
    uint64_t FILE;
} File_struct;


#define PDE64_PRESENT 1 // page table flag. Page present
#define PDE64_RW (1U << 1) // page table flag. Page read and write enable
#define PDE64_USER (1U << 2) // page table access privilege level: USER
#define PDE64_PS (1U << 7) // 1 = pointing to next page table level. 0 = pointing to large data page.

// CR4
// "physical address extension" used in long mode(extend 32bit-64bit address) as a flag in system regs.
#define CR4_PAE (1U << 5)

// CR0
#define CR0_PE 1u // protected mode flag set in system regs
#define CR0_PG (1U << 31) // paging flag set in system regs

#define EFER_LME (1U << 8) // "long mode activate" flag in system regs
#define EFER_LMA (1U << 10) // "long mode enable" flag in system regs

struct vm {
    int kvm_fd;
    int vm_fd;
    int vcpu_fd;
    char *mem;
    struct kvm_run *kvm_run;
};

static void setup_64bit_code_segment(struct kvm_sregs *sregs)
{
    struct kvm_segment seg = {
        .base = 0,
        .limit = 0xffffffff,
        .type = 11, // Code: execute, read, accessed
        .present = 1, // Prisutan ili učitan u memoriji
        .dpl = 0, // Descriptor Privilage Level: 0 (0, 1, 2, 3)
        .db = 0, // Default size - ima vrednost 0 u long modu
        .s = 1, // Code/data tip segmenta
        .l = 1, // Long mode - 1
        .g = 1, // 4KB granularnost
    };

    sregs->cs = seg;

    seg.type = 3; // Data: read, write, accessed
    sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

int init_vm(struct vm *vm, size_t mem_size)
{
    // structure used to describe and allocate memory regions that the guest VMs can access directly.
    struct kvm_userspace_memory_region region;
    int kvm_run_mmap_size;

    vm->kvm_fd = open("/dev/kvm", O_RDWR);
    if (vm->kvm_fd < 0) {
        perror("open /dev/kvm");
        return -1;
    }

    vm->vm_fd = ioctl(vm->kvm_fd, KVM_CREATE_VM, 0);
    if (vm->vm_fd < 0) {
        perror("KVM_CREATE_VM");
        return -1;
    }

    vm->mem = (char*)mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (vm->mem == MAP_FAILED) {
        perror("mmap mem");
        return -1;
    }

    region.slot = 0;
    region.flags = 0;
    region.guest_phys_addr = 0;
    region.memory_size = mem_size;
    region.userspace_addr = (unsigned long)vm->mem;
    if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        perror("KVM_SET_USER_MEMORY_REGION");
        return -1;
    }

    vm->vcpu_fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, 0);
    if (vm->vcpu_fd < 0) {
        perror("KVM_CREATE_VCPU");
        return -1;
    }

    kvm_run_mmap_size = ioctl(vm->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (kvm_run_mmap_size <= 0) {
        perror("KVM_GET_VCPU_MMAP_SIZE");
        return -1;
    }

    vm->kvm_run = (struct kvm_run*)mmap(NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE,
                     MAP_SHARED, vm->vcpu_fd, 0);
    if (vm->kvm_run == MAP_FAILED) {
        perror("mmap kvm_run");
        return -1;
    }

    return 0;
}

static void setup_long_mode(struct vm *vm, struct kvm_sregs *sregs)
{
    // Postavljanje 4 niva ugnjezdavanja.
    // Svaka tabela stranica ima 512 ulaza, a svaki ulaz je veličine 8B.
    // Odatle sledi da je veličina tabela stranica 4KB. Ove tabele moraju da budu poravnate na 4KB. 
    uint64_t page = 0;
    uint64_t pml4_addr = 0x1000; // Adrese su proizvoljne.
    uint64_t *pml4 = (uint64_t *)(vm->mem + pml4_addr);

    uint64_t pdpt_addr = 0x2000;
    uint64_t *pdpt = (uint64_t *)(vm->mem + pdpt_addr);

    uint64_t pd_addr = 0x3000;
    uint64_t *pd = (uint64_t *)(vm->mem + pd_addr);

    uint64_t pt_addr = 0x4000;
    uint64_t *pt = (uint64_t *)(vm->mem + pt_addr);

    pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
    pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;

    int pd_entries_num = MEM_SIZE / 2;    
    if(PAGE_SIZE == 4){ // 4KB page
        for(int i = 0; i < pd_entries_num; i ++){
            pd[i] = PDE64_PRESENT | PDE64_RW | PDE64_USER | (pt_addr + i*0x1000);
        }
        // PC vrednost se mapira na ovu stranicu.
        int pc_entry = 0;
        pt[pc_entry] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
         
        int sp_entry = 512 * pd_entries_num - 1;

        pt[sp_entry] = (MEM_SIZE << 20 - 1) | PDE64_PRESENT | PDE64_RW | PDE64_USER;
        // stavljeno je minus 1 zato sto je fizicki MEM_SIZE << 20 ilegalna adresa
    }
    if(PAGE_SIZE == 2){ //2 MB
        for(int i = 0; i < pd_entries_num; i ++){
            pd[i] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS | (i*0x200000);
        }
    }

    // Registar koji ukazuje na PML4 tabelu stranica. Odavde kreće mapiranje VA u PA.
    sregs->cr3  = pml4_addr; 
    sregs->cr4  = CR4_PAE; // "Physical Address Extension" mora biti 1 za long mode.
    sregs->cr0  = CR0_PE | CR0_PG; // Postavljanje "Protected Mode" i "Paging" 
    sregs->efer = EFER_LME | EFER_LMA; // Postavljanje  "Long Mode Active" i "Long Mode Enable"

    // Inicijalizacija segmenata procesora.
    setup_64bit_code_segment(sregs);
}

size_t get_args(int argc, char *argv[]){
    if (argc < 2) {
        printf("The program requests an image to run: %s <guest-image>\n", argv[0]);
        return -10;
    }
    // current[0] => memory
    // current[1] => page
    // current[2] => guest
    // current[3] => file
    // 0 -> not yet processed. ( > 0 ) -> currently being processed, ( < 0 ) -> already processed
    int current[4] = {0}; 
    int argumentBoolean = 0;
    for(int argIndex = 1; argIndex < argc; argIndex ++){
        // check if it's an argument type
        for(int argTypeIndex = 0; argTypeIndex < 8; argTypeIndex ++){
            if(strcmp(argv[argIndex], ARGUMENT_NAMES[argTypeIndex]) == 0){
                argumentBoolean = 1;
                // already processed
                if(current[argTypeIndex/2] < 0){ 
                    return -1;
                }
            
                // someone is currently being processed ( memory or page), 
                // yet we are trying to start new processing
                if(current[0] > 0 || current [1] > 0){
                    return -2;
                }
            
                // what if we are processing img or file (they have multiple arguments)
                // how do we check when we reached the end? The end is reached
                // when a new argument type is next argv.
                if(current[2] > 0){
                    if(argTypeIndex/2 == 2){ // error, we were processing something and try to do it again
                        return -3;
                    }
                    current[2] = -1;
                }
                if(current[3] > 0){
                    if(argTypeIndex/2 == 3){ // error, we were processing something and try to do it again
                        return -4;
                    }
                    current[3] = -1;
                }
                current[argTypeIndex/2]++; // set to currently processing ( > 0 )
                break;
            } 
        }
        if(argumentBoolean){
            argumentBoolean = 0;
            continue;
        }
        // arguments

        // find the argument type currently being processed
        int currentIndex = -1;
        for(int i = 0; i < 4; i ++){
            if(current[i] > 0){
                currentIndex = i;
                break;
            }
        }
        if(currentIndex < 0){ // None is being processed yet we received an argument
            return -5;
        }
        
        char* file;
        char* img;
        switch(currentIndex){
            case 0: // memory
                if(MEM_SIZE != 0){ // MEM_SIZE already set, we received multiple arguments for MEM_SIZE
                    return -6;
                }
                MEM_SIZE = atoi(argv[argIndex]);
                current[0] = -1; // set it to  < 0 (processed)
            break;
            case 1: // page
                if(PAGE_SIZE != 0){ // PAGE_SIZE already set, we received multiple arguments for PAGE_SIZE
                    return -7;
                }
                PAGE_SIZE = atoi(argv[argIndex]);
                current[1] = -1; // set it to  < 0 (processed)
            break;
            case 2: // IMG guest
                img = argv[argIndex];
                IMG = (char**)realloc(IMG, (IMG_COUNT + 1) * sizeof(char*));
                // +1 because strlen() returns number of chars excluding \0 char
                IMG[IMG_COUNT] = (char*)malloc(strlen(img) + 1); 
                strcpy(IMG[IMG_COUNT], img);
                IMG_COUNT++;
            break;
            case 3:
                file = argv[argIndex];
                FILES = (char**)realloc(FILES, (FILE_COUNT + 1) * sizeof(char*));
                // +1 because strlen() returns number of chars excluding \0 char
                FILES[FILE_COUNT] = (char*)malloc(strlen(file) + 1); 
                strcpy(FILES[FILE_COUNT], file);
                FILE_COUNT++;
            break;
        }
    }
    return 0;
}
void set_file_name ( char* name, int user_id){
        // create specific filename for this user
    // Find the last dot in the filename
    char *last_dot = strrchr(name, '.');

    if (last_dot != NULL) {
        // Calculate the position to insert id before the dot
        size_t insert_pos = last_dot - name;

        // Create specific filename for this user
        char id[10]; // Adjust size as needed for your user_id
        sprintf(id, "%d", user_id);

        // Shift characters after insert_pos to make space for id
        memmove(name+ insert_pos + strlen(id), 
                name + insert_pos, 
                strlen(name) - insert_pos + 1);

        // Copy id into filename at insert_pos
        memcpy(name + insert_pos, id, strlen(id));
    }
}

void fopen_ (File_struct* file_struct, int user_id){

    // check if the file is shared
    int file_shared = 0;
    for(int i = 0; i < FILE_COUNT; i ++){
        if(strcmp(FILES[i], file_struct->filename) == 0){ // its a shared file
            file_shared = 1;
            break;
        }
    }
    
    if(file_shared == 0){
        // create specific filename for this user by appending user_id
        set_file_name(file_struct->filename, user_id);
    }

    FILE* file = fopen(file_struct->filename, "r+");

    if(file == NULL){ // maybe it doesnt exist so it needs w+ mode to be created
        file = fopen(file_struct->filename, "w+");
    }

    file_struct->status = (file == NULL)? FILE_OP_FAILED: FILE_OP_SUCCESSFUL;
    file_struct->FILE = (uint64_t)file;
}

void fclose_(File_struct* file_struct){
    int status = fclose((FILE*)(file_struct->FILE));
    file_struct->status = (status == 0)? FILE_OP_SUCCESSFUL:FILE_OP_FAILED;
}

void fwrite_ (File_struct* file_struct, int user_id){
    // check if the file is shared
    int file_shared = 0;
    for(int i = 0; i < FILE_COUNT; i ++){
        if(strcmp(FILES[i], file_struct->filename) == 0){ // its a shared file
            file_shared = 1;
            break;
        }
    }

    if(file_shared == 1){
        char newname[256];
        strcpy(newname, file_struct->filename);
        set_file_name(newname, user_id);
    
        // make new special file
        FILE* f_handle = fopen(newname, "w+");
        
        if(f_handle == NULL){
            file_struct->status = FILE_OP_FAILED;
            return;
        }
        
        // copy file
        size_t bytes_read;
        char buffer[1024];
        fseek((FILE*)(file_struct->FILE), 0, SEEK_SET) != 0;
        while ((bytes_read = fread(buffer, 1, 1024, (FILE*)(file_struct->FILE))) > 0) {
            fwrite(buffer, 1, bytes_read, f_handle);
        }

        fclose_(file_struct);
        strcpy(file_struct->filename, newname);
        file_struct->FILE = (uint64_t)f_handle;
              
    }
    
    file_struct->counter = fwrite(file_struct->buffer, file_struct->WR_size,1, (FILE*)(file_struct->FILE));
    file_struct->status = (file_struct->counter == 0 && file_struct->WR_size != 0)? FILE_OP_FAILED: FILE_OP_SUCCESSFUL;
}

void fread_ (File_struct* file_struct){
    file_struct->counter = fread(file_struct->buffer, 1,file_struct->WR_size, (FILE*)(file_struct->FILE));
    file_struct->status = (file_struct->counter == 0 && file_struct->WR_size != 0)? FILE_OP_FAILED: FILE_OP_SUCCESSFUL;
}

void handle_file_op(File_struct* file_struct, int user_id){
    switch(file_struct->op){
        case FOPEN:
            fopen_(file_struct, user_id);
            break;
        case FCLOSE:
            fclose_(file_struct);
            break;
        case FWRITE:
            fwrite_(file_struct, user_id);
            break;
        case FREAD:
            fread_(file_struct);
            break;
        default:
            cout << "INVALID CODE" << endl;
            break;
    }
}

void* run_vm(void* arg){
  
    struct vm vm;
    struct kvm_sregs sregs;
    struct kvm_regs regs;
    int stop = 0;
    int ret = 0;
    Thread_param* tp = (Thread_param*)arg;

    if (init_vm(&vm, MEM_SIZE << 20)) {
        std::cout << "Failed to init the VM\n";
        return nullptr;
    }

    if (ioctl(vm.vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
        perror("KVM_GET_SREGS");
        return nullptr;
    }

    setup_long_mode(&vm, &sregs);

    if (ioctl(vm.vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
        perror("KVM_SET_SREGS");
        return nullptr;
    }

    memset(&regs, 0, sizeof(regs));
    regs.rflags = 2;
    regs.rip = 0;
    // SP raste nadole
    regs.rsp = MEM_SIZE << 20; 
    

    if (ioctl(vm.vcpu_fd, KVM_SET_REGS, &regs) < 0) {
        perror("KVM_SET_REGS");
        return nullptr;
    }
      

    FILE* imgFile;
   
    imgFile = fopen(tp->IMG, "r");
    if (imgFile == nullptr) {
        std::cout << "Can not open binary file\n";
        return nullptr;
    }
    
    char *p = vm.mem;

    while(!feof(imgFile)) {
        int r = fread(p, 1, 1024, imgFile);
        p += r;
    }
    fclose(imgFile);

    int byte_cnt = 0;
    int border = sizeof(File_struct);
    char* proto_file_struct = (char*)(new File_struct());
    File_struct* file_struct;
    
    while(stop == 0) {
        ret = ioctl(vm.vcpu_fd, KVM_RUN, 0);
        if (ret == -1) {
            std::cout << "KVM_RUN failed\n";
            return nullptr;
        }
        
        // sleep
        switch (vm.kvm_run->exit_reason) {
            case KVM_EXIT_IO:
                
                if (vm.kvm_run->io.direction == KVM_EXIT_IO_OUT && vm.kvm_run->io.port == 0xE9) { //printf
                    char *p = (char *)vm.kvm_run;
                    std::cout << *(p + vm.kvm_run->io.data_offset);
                    
                }
                if (vm.kvm_run->io.direction == KVM_EXIT_IO_IN && vm.kvm_run->io.port == 0xE9) { //scanf
                    char data;
                    scanf("%c", &data);
                    char *data_in = (((char*)vm.kvm_run) + vm.kvm_run->io.data_offset);
                    (*data_in) = data;
                }
                if (vm.kvm_run->io.direction == KVM_EXIT_IO_OUT && vm.kvm_run->io.port == FILE_PORT) {
                    char* p = reinterpret_cast<char*>(vm.kvm_run);
                    char a = *(p + vm.kvm_run->io.data_offset);
               
               
                    proto_file_struct[byte_cnt] = a;
                    byte_cnt++;
                    if(byte_cnt == border){
                        file_struct = (File_struct*)proto_file_struct;
                        byte_cnt = 0;
                        handle_file_op(file_struct, tp->id);
                    }   
                  
                }

                if (vm.kvm_run->io.direction == KVM_EXIT_IO_IN && vm.kvm_run->io.port == FILE_PORT) {
                    char* p = reinterpret_cast<char*>(vm.kvm_run);
                    if(byte_cnt != border){
                        char data = ((char*)file_struct)[byte_cnt];
                        memcpy(p + vm.kvm_run->io.data_offset, &data, vm.kvm_run->io.size);
                        byte_cnt++;  
                    }
                    if(byte_cnt == border){
                        byte_cnt = 0;
                    }   
                }
										
                continue;
            case KVM_EXIT_HLT:
                std::cout << "KVM_EXIT_HLT\n";
                stop = 1;
                break;
            case KVM_EXIT_INTERNAL_ERROR:
                std::cout << "Internal error: suberror = 0x" << std::hex << vm.kvm_run->internal.suberror << "\n";
                stop = 1;
                break;
            case KVM_EXIT_SHUTDOWN:
                std::cout << "Shutdown\n";
                stop = 1;
                break;
            default:
                std::cout << "Exit reason: " << vm.kvm_run->exit_reason << "\n";
                break;
        }
    }
    delete tp;
    return nullptr;
}

void free_memory(){
    for(size_t i = 0; i < IMG_COUNT; i++){
        free(IMG[i]);
    }
    free(IMG);

    for(size_t i = 0; i < FILE_COUNT; i++){
        free(FILES[i]);
    }
    free(FILES);
}

void test_args(){
    std::cout << "--------------------\n";
    std::cout << "memory size: " << MEM_SIZE << "\n";
    std::cout << "page size: " << PAGE_SIZE << "\n";

    std::cout << "images: ";
    for(size_t i = 0; i < IMG_COUNT; i ++){
        std::cout << IMG[i] << " ";
    }
    std::cout << "\n";

    std::cout << "files: ";
    for(size_t i = 0; i < FILE_COUNT; i ++){
        std::cout << FILES[i] << " ";
    }
    std::cout << "\n";
    std::cout << "--------------------\n";
}
void stavkaA(){
    run_vm(&IMG[0]);
}
void stavkaB(){

    pthread_t* threads = new pthread_t[IMG_COUNT];

    for (size_t i = 0; i < IMG_COUNT; i++) {
        Thread_param* tp = new Thread_param();
        tp->id = i;
        tp->IMG = IMG[i];
        pthread_create(&threads[i], nullptr, run_vm, tp);
    }

    for (size_t i = 0; i < IMG_COUNT; i++) {
        pthread_join(threads[i], nullptr);
    }

    delete[] threads;
}

int main(int argc, char *argv[])
{
    if(get_args(argc, argv) < 0){
        std::cout << "GRESKA SA ARGUMENTIMA PROGRAMA\n";
        return 0;
    }
    test_args();

    char c;
    std::cin >> c;
        
    switch(c){
        case 'A':
        case 'a':
            stavkaA();
            break;
        case 'B':
        case 'b':
        case 'C':
        case 'c':
            stavkaB();
            break;
        default:
            std::cout << "Stavka " << c << " ne postoji.\n";
            break;
    }
    
    free_memory();
    return 0;
}
