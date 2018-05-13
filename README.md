## 系统参数

1. 文件系统块大小blocksize = 4096
2. 文件系统地址空间大小为size = 4G
3. 文件名最长为255个字符
4. 一个目录下文件数目最多为 15 + 15 * 11 = 180
5. 文件最大为 (983 + 2 * 1024 + 1024 * 1024) * 4096 = 4307382272 = 4.0115G 

## 算法

### 第一个块

- 存储系统一些基本参数， 结构体如下

  ```c
  static struct first_node {
      uint32_t block_size;
      uint32_t block_num;
      uint32_t free_block_num;
      uint32_t free_stack_used;  // 空闲块栈使用的块个数
      uint32_t free_stack_index;
      uint32_t root_index;
      uint32_t dir_file_max;
      uint32_t data_index_max;
      uint64_t file_size_max;
      uint32_t unused[BLOCK_SIZE / 4 - 10];
  } *first_node;
  ```

  

### 目录文件

- 元信息包括`struct stat`、其上级目录、当前所用一级索引区数目（包括二级里的一级索引区）、15个一级索引区和11个二级索引区
- 索引区里存储文件名和文件元信息所在的块

### 常规文件

- 元信息包括`struct stat`、其上级目录、当前所用一级索引数目（包括二、三级里的一级索引）、983个一级索引、2个二级索引和1个三级索引
- 索引指向的块存储`data`

### 空闲空间管理

- 将`(blocknr * 4 + BLOCK_SIZE - 1) / BLOCK_SIZE`个块组成的连续空间当成一个存储空闲块的栈
- 需要块时弹出一个，不需要时压入一个