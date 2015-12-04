#ifndef _input_data_
#define _input_data_

/******Defination of structure to store user passed arguments******/
struct input_data{
        char* input_file;
        char* output_file;
        char* keybuf;
        int keylen;
        int flags;
}((__attribute_packed__));
#endif
