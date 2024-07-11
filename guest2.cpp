#include <stddef.h>
#include <stdint.h>

#define FILE_PORT 0x0278

#define FOPEN 1
#define FCLOSE 2
#define FREAD 3
#define FWRITE 4

typedef struct{
    char filename[256];
    int op;
    int status;
    int counter;
    char buffer[512];
    int WR_size;
    uint64_t FILE;
} File_struct;



char* my_strcpy(char* dest, const char* src) {
    char* original_dest = dest; // Keep the original pointer to return later
    
    // Copy each character from src to dest, including the null terminator
    while ((*dest++ = *src++) != '\0');
    
    return original_dest; // Return the original destination pointer
}
void *mimic_memcpy(void *dest, const void *src, size_t num_bytes) {
    char *char_dest = (char *)dest;
    const char *char_src = (const char *)src;

    for (size_t i = 0; i < num_bytes; ++i) {
        char_dest[i] = char_src[i];
    }

    return dest;
}

static void outb(uint16_t port, uint8_t value) {
    asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}
static uint8_t inb(uint16_t port) {
    uint8_t ret;
    asm volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}
// // Output a word (32-bit) to the specified port
// static void outl(uint16_t port, uint32_t value) {
//     asm volatile("outl %0, %1" : : "a"(value), "Nd"(port) : "memory");
// }

// static uint32_t inl(uint16_t port) {
//     uint32_t ret;
//     asm volatile("inl %1, %0" : "=a"(ret) : "Nd"(port));
//     return ret;
// }
void send_struct(File_struct* file){
    for(int i = 0; i < sizeof(File_struct); i ++){
        outb(FILE_PORT, ((char*)(file))[i]);
   }
}

void receive_struct(File_struct* file){
    File_struct* file_pointer = file;
    for(int i = 0; i < sizeof(File_struct); i ++){
        ( (char*)(file_pointer) )[i] = inb(FILE_PORT);
    }
}

void fopen_(File_struct* file, char *filename){
   
   my_strcpy(file->filename, filename);
   file->op = FOPEN;   
   file->status = 0;
   file->counter = 0;
   
    send_struct(file);

    receive_struct(file);
}

void fclose_(File_struct* file){
   file->op = FCLOSE;   
   file->status = 0;
   file->counter = 0;
   
    send_struct(file);

    receive_struct(file);
}

void fwrite_(File_struct* file, char* message, int num){
   
   mimic_memcpy(file->buffer, message, num);
   file->op = FWRITE;   
   file->WR_size = num;
   file->status = 0;
   file->counter = 0;
   
    send_struct(file);

    receive_struct(file);
}
void fread_(File_struct* file, int num){
   
   file->op = FREAD;   
    file->WR_size = num;
   file->status = 0;
   file->counter = 0;
   
    send_struct(file);

    receive_struct(file);
}

void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {
    char filename[256] = "test.txt\0";
    char message[256] = "ada\0";

    File_struct file_struct;
    fopen_(&file_struct, filename);
    fread_(&file_struct, 3);
    //fwrite_(&file_struct, file_struct.buffer, file_struct.WR_size);
    fwrite_(&file_struct, message, 3);
    fclose_(&file_struct);

    for (;;)
        asm("hlt");
}