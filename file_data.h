#ifndef FILE_DATA_H
#define FILE_DATA_H

#define FN_TYPE_BEGIN    1
//#define FN_TYPE_DATA    2
#define FN_TYPE_END     2

#define FN_FILENAME_POS 13
#define FN_END_LENGTH 13

#define FN_MINLEN    4
#define FN_FILENAMELENGTH 115
#define FN_MAXDATA    128

struct fileInfo{
    long fileSize;
    char fileID;
    char filename[FN_FILENAMELENGTH];
}__attribute__((packed));

struct file_node {
  u_int32_t node_type;
  union {
    //char filename[FN_FILENAMELENGTH];
    struct fileInfo fileinfo;
    u_int8_t data[FN_MAXDATA];
} file_data;
};

#endif /* FILE_DATA_H */
