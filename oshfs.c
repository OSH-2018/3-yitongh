#define FUSE_USE_VERSION 26
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <errno.h>
#include <fuse.h>
#include <sys/mman.h>

#define MAX_NAME 255
#define BLOCK_SIZE 4096
#define MEMORY_SIZE (4 * 1024 * 1024 * (size_t)1024)

#define DATA_TWICE_INDEXS 2
#define DATA_TRIPLE_INDEXS 1
#define DATA_ONCE_INDEXS ((BLOCK_SIZE - sizeof(struct stat)) / 4 - 2 - DATA_TWICE_INDEXS - DATA_TRIPLE_INDEXS)
#define DATA_INDEX_NODE_INDEXS (BLOCK_SIZE / 4)

#define DIR_ONCE_INDEXS ((BLOCK_SIZE - sizeof(struct stat) - 2*4) / sizeof(struct file_zone))
#define DIR_TWICE_INDEXS ((BLOCK_SIZE - sizeof(struct stat) - 2*4) % sizeof(struct file_zone) / 4)
#define DIR_INDEX_NODE_INDEXS (BLOCK_SIZE / sizeof(struct file_zone))

struct data_zone {
    uint32_t once[DATA_ONCE_INDEXS];
    uint32_t twice[DATA_TWICE_INDEXS];
    uint32_t triple;
};

struct file_zone {
    uint32_t index;
    char name[MAX_NAME + 1];
};

struct dir_zone {
    struct file_zone once[DIR_ONCE_INDEXS];
    uint32_t twice[DIR_TWICE_INDEXS];
};


struct data_index_node {
    uint32_t once[DATA_INDEX_NODE_INDEXS];
};

struct file_index_node {
    struct file_zone once[DIR_INDEX_NODE_INDEXS];
    int32_t unused[(BLOCK_SIZE - sizeof(struct file_zone) * DIR_INDEX_NODE_INDEXS) / 4];
};

struct filenode {
    struct stat st; 
    uint32_t father;
    uint32_t index_used;
    union {
        struct data_zone data;
        struct dir_zone dir;
    } zone;
};

static struct first_node {
    uint32_t block_size;
    uint32_t block_num;
    uint32_t free_block_num;
    uint32_t free_stack_used;
    uint32_t free_stack_index;
    uint32_t root_index;
    uint32_t dir_file_max;
    uint32_t data_index_max;
    uint64_t file_size_max;
    uint32_t unused[BLOCK_SIZE / 4 - 10];
} *first_node;

static void *mem[MEMORY_SIZE / BLOCK_SIZE];

static void filenode_init(uint32_t index, const struct stat *st, uint32_t father)
{
    assert(index && index < first_node->block_num);
    struct filenode *node = (struct filenode *)mem[index];
    memcpy(&(node->st), st, sizeof(struct stat));
    node->index_used = 0;
    node->father = father;
    struct data_zone *data = &(node->zone.data);
    memset(data, 0, sizeof(struct data_zone));
}

static uint32_t get_fileindex(const char *path)
{
    struct filenode *node = (struct filenode *)mem[first_node->root_index];
    uint32_t index = 1;
    struct file_zone *file;
    char filename[strlen(path)];
    char *token;
    char found = 0;

    // is not root
    if (strcmp(path, "/") != 0) {
        strcpy(filename, path);
        token = strtok(filename, "/");
        assert(token != NULL);
        while (token != NULL && S_ISDIR(node->st.st_mode)) {
            file = node->zone.dir.once;
            for (int i = 0; i < DIR_ONCE_INDEXS; i++) {
                if (file[i].index == 0)
                    break;
                if (strcmp(token, file[i].name) == 0) {
                    node = (struct filenode *)mem[file[i].index];
                    index = file[i].index;
                    token = strtok(NULL, "/");
                    found = 1;
                    break;
                }
            }
            // have twice index
            if ((found == 0) && node->index_used > 15) {
                for (int i = 0; i < DIR_TWICE_INDEXS; i++) {
                    if (node->zone.dir.twice[i] == 0)
                        break;                    
                    struct file_index_node *twice = (struct file_index_node *)mem[node->zone.dir.twice[i]];
                    file = twice->once;
                    for (int j = 0; j < DIR_INDEX_NODE_INDEXS; j++) {
                        if (file[j].index == 0)
                            break;
                        if (strcmp(token, file[j].name) == 0) {
                            node = (struct filenode *)mem[file[j].index];
                            index = file[j].index;
                            token = strtok(NULL, "/");
                            found = 1;
                            break;
                        }
                    }
                    if (found == 1) {
                        break;
                    }
                }
            }
            // found, to next dir
            if (found == 1) {
                found = 0;
                continue;
            }
            else
                break;
        }
        // not found
        if (token != NULL) {
            node = NULL;
            index = 0;
        }
    }
    return index;
}

// return 0 if there is not free block
static uint32_t get_freeblock()
{
    // no free block
    if (first_node->free_block_num == 0) {
        return 0;
    }
    uint32_t *stack = (uint32_t *)mem[first_node->free_stack_index];
    uint32_t block = stack[first_node->free_block_num - 1];

    assert(block);
    assert(block >= first_node->free_stack_used + 2);

    first_node->free_block_num--;
    mem[block] = mmap(NULL, BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return block;
}

static void freeblock(uint32_t block)
{
    assert(block);
    assert(block >= first_node->free_stack_used + 2);
    uint32_t *stack = (uint32_t *)mem[first_node->free_stack_index];
    assert(first_node->free_block_num != first_node->block_num - 2);
    stack[first_node->free_block_num] = block;
    first_node->free_block_num++;
    munmap(mem[block], BLOCK_SIZE);
}

static int create_filenode(const char *path, const struct stat *st)
{
    char filepath[strlen(path)];
    strcpy(filepath, path);
    uint32_t father_index;

    // find the file name
    char *filename = rindex(filepath, '/');
    *filename = '\0';
    filename++; 
    if (strlen(filename) > MAX_NAME)
        return -ENAMETOOLONG;
    
    // the father dir is root
    if (filepath[0] == '\0') {
        father_index = first_node->root_index;
    }
    else
        father_index = get_fileindex(filepath);
    // can't find the father dir
    if (father_index == 0)
        return -ENOENT;

    struct filenode *father = (struct filenode *)mem[father_index];
    if (father->index_used >= first_node->dir_file_max)
        return -EMLINK;
    struct file_zone *file;
    if (father->index_used < DIR_ONCE_INDEXS) {
        file = &(father->zone.dir.once[father->index_used]);
    }
    else {
        uint32_t index = father->zone.dir.twice[(father->index_used - DIR_ONCE_INDEXS) / DIR_INDEX_NODE_INDEXS];
        if (index != 0) {
            struct file_index_node *twice = (struct file_index_node *)mem[index];
            file = &(twice->once[(father->index_used - DIR_ONCE_INDEXS) % DIR_INDEX_NODE_INDEXS]);
        }
        else {
            index = get_freeblock();
            if (index == 0) {
                return -ENOSPC;
            }
            father->zone.dir.twice[(father->index_used - DIR_ONCE_INDEXS) / DIR_INDEX_NODE_INDEXS] = index;
            struct file_index_node *twice = (struct file_index_node *)mem[index];
            file = &(twice->once[0]);
        }
    }
    file->index = get_freeblock();
    if (file->index == 0) {
        return -ENOSPC;
    }
    father->index_used++;
    strcpy(file->name, filename);
    filenode_init(file->index, st, father_index);
    father->st.st_size += st->st_size;
    return 0;
}

static int resize(uint32_t index, size_t size)
{
    struct filenode *node = (struct filenode *)mem[index];
    struct filenode *father = (struct filenode *)mem[node->father];
    father->st.st_size -= node->st.st_size;
    uint32_t index_need = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if (index_need > node->index_used) {
        int num = index_need - node->index_used;
        for (int i = 0; i < num; i++) {
            if (node->index_used < DATA_ONCE_INDEXS) {
                node->zone.data.once[node->index_used] = get_freeblock();
                if (node->zone.data.once[node->index_used] == 0)
                    break;
            }
            else if (node->index_used < DATA_ONCE_INDEXS + DATA_TWICE_INDEXS * DATA_INDEX_NODE_INDEXS) {
                uint32_t twice_i = node->index_used - DATA_ONCE_INDEXS;
                if (node->zone.data.twice[twice_i / DATA_INDEX_NODE_INDEXS] == 0) {
                    node->zone.data.twice[twice_i / DATA_INDEX_NODE_INDEXS] = get_freeblock();
                    if (node->zone.data.twice[twice_i / DATA_INDEX_NODE_INDEXS] == 0)
                        break;
                }
                struct data_index_node *twice = (struct data_index_node *)mem[node->zone.data.twice[twice_i / DATA_INDEX_NODE_INDEXS]];
                uint32_t *data = twice->once;
                data[twice_i % DATA_INDEX_NODE_INDEXS] = get_freeblock();
                if (data[twice_i % DATA_INDEX_NODE_INDEXS] == 0)
                    break;
            }
            else {
                if (node->zone.data.triple == 0) {
                    node->zone.data.triple = get_freeblock();
                    if (node->zone.data.triple == 0)
                        break;
                }
                struct data_index_node *index_node = (struct data_index_node *)mem[node->zone.data.triple];
                uint32_t *data = index_node->once;
                uint32_t index_i = node->index_used - DATA_ONCE_INDEXS - DATA_TWICE_INDEXS * DATA_INDEX_NODE_INDEXS;
                if (data[index_i / DATA_INDEX_NODE_INDEXS] == 0) {
                    data[index_i / DATA_INDEX_NODE_INDEXS] = get_freeblock();
                    if (data[index_i / DATA_INDEX_NODE_INDEXS] == 0)
                        break;
                }
                index_node = (struct data_index_node *)mem[data[index_i / DATA_INDEX_NODE_INDEXS]];
                data = index_node->once;
                data[index_i % DATA_INDEX_NODE_INDEXS] = get_freeblock();
                if (data[index_i % DATA_INDEX_NODE_INDEXS] == 0)
                    break;
            }
            node->index_used++;
        }
    }
    else if (index_need < node->index_used) {
        int num = node->index_used - index_need;
        for (int i = 0; i < num; i++) {
            if (node->index_used <= DATA_ONCE_INDEXS) {
                freeblock(node->zone.data.once[node->index_used - 1]);
            }
            else if (node->index_used <= DATA_ONCE_INDEXS + DATA_TWICE_INDEXS * DATA_INDEX_NODE_INDEXS) {
                int index_i = node->index_used - DATA_ONCE_INDEXS - 1;
                struct data_index_node *index_node = (struct data_index_node *)mem[node->zone.data.twice[index_i / DATA_INDEX_NODE_INDEXS]];
                uint32_t *data = index_node->once;
                freeblock(data[index_i % DATA_INDEX_NODE_INDEXS]);
                if (index_i % DATA_INDEX_NODE_INDEXS == 0) {
                    freeblock(node->zone.data.twice[index_i / DATA_INDEX_NODE_INDEXS]);
                    node->zone.data.twice[index_i / DATA_INDEX_NODE_INDEXS] = 0;
                }
            }
            else {
                uint32_t index_i = node->index_used - DATA_ONCE_INDEXS - DATA_TWICE_INDEXS * DATA_INDEX_NODE_INDEXS - 1;
                struct data_index_node *index_node = (struct data_index_node *)mem[node->zone.data.triple];
                uint32_t *data = index_node->once;
                index_node = (struct data_index_node *)mem[data[index_i / DATA_INDEX_NODE_INDEXS]];
                data = index_node->once;
                freeblock(data[index_i % DATA_INDEX_NODE_INDEXS]);
                index_node = (struct data_index_node *)mem[node->zone.data.triple];
                data = index_node->once;
                if (index_i % DATA_INDEX_NODE_INDEXS == 0) {
                    freeblock(data[index_i / DATA_INDEX_NODE_INDEXS]);
                    data[index_i / DATA_INDEX_NODE_INDEXS] = 0;
                }
                if (node->index_used == DATA_ONCE_INDEXS + DATA_TWICE_INDEXS * DATA_INDEX_NODE_INDEXS) {
                    freeblock(node->zone.data.triple);
                    node->zone.data.triple = 0;
                }
            }
            node->index_used--;
        }
    }
    // don't have enough space to allocate
    if (node->index_used != index_need) {
        // free the space that this time allocate
        resize(index, node->st.st_size);
        father->st.st_size += node->st.st_size;
        return -ENOSPC;
    }
    node->st.st_size = size;
    father->st.st_size += node->st.st_size;
    return 0;
}

static void rm_filename(uint32_t index, const char *name)
{
    struct filenode *father = (struct filenode *)mem[index];
    char found = 0;
    struct file_zone *once = father->zone.dir.once;
    for (int i = 0; i < DIR_ONCE_INDEXS; i++) {
        if (found == 1 && once[i].index != 0) {
            strcpy(once[i - 1].name, once[i].name);
            once[i - 1].index = once[i].index;
            once[i].index = 0;
            memset(once[i].name, 0, MAX_NAME + 1);
            continue;
        }
        else if (found == 1 && once[i].index == 0) {
            once[i - 1].index = 0;
            memset(once[i - 1].name, 0, MAX_NAME + 1);
            break;
        }
        assert(once[i].index);
        if (strcmp(once[i].name, name) == 0) {
            once[i].name[0] = '\0';
            once[i].index = 0;
            father->index_used--;
            found = 1;
        }
    }

    for (int i = 0; i < DIR_TWICE_INDEXS; i++) {
        if (found == 1 && father->zone.dir.twice[i] == 0)
            break;
        assert(father->zone.dir.twice[i]);
        struct file_index_node *twice = (struct file_index_node *)mem[father->zone.dir.twice[i]];
        struct file_zone *file = twice->once;
        for (int j = 0; j < DIR_INDEX_NODE_INDEXS; j++) {
            if (found == 1 && file[j].index != 0) {
                if (j == 0 && i == 0) {
                    strcpy(once[DIR_ONCE_INDEXS - 1].name, file[j].name);
                    once[DIR_ONCE_INDEXS - 1].index = file[j].index;
                }
                else if (j == 0) {
                    struct file_index_node *temptwice = (struct file_index_node *)mem[father->zone.dir.twice[i - 1]];
                    struct file_zone *tempfile = temptwice->once;
                    strcpy(tempfile[DIR_INDEX_NODE_INDEXS - 1].name, file[j].name);
                    tempfile[DIR_INDEX_NODE_INDEXS - 1].index = file[j].index;
                }
                else {
                    strcpy(file[j - 1].name, file[j].name);
                    file[j - 1].index = file[j].index;
                }
                memset(file[j].name, 0, MAX_NAME + 1);
                file[j].index = 0;
                continue;
            }
            else if (found == 1 && file[j].index == 0) {
                assert(j);
                memset(file[j - 1].name, 0, MAX_NAME + 1);
                file[j - 1].index = 0;
                break;
            }
            assert(file[j].index);
            if (strcmp(file[j].name, name) == 0) {
                memset(file[j].name, 0, MAX_NAME + 1);
                file[j].index = 0;
                father->index_used--;
                found = 1;
            }
        }
    }
    if (father->index_used >= DIR_ONCE_INDEXS 
        && ((father->index_used - DIR_ONCE_INDEXS) % DIR_INDEX_NODE_INDEXS) == 0) {
        freeblock(father->zone.dir.twice[(father->index_used - DIR_ONCE_INDEXS) / DIR_INDEX_NODE_INDEXS]);
        father->zone.dir.twice[(father->index_used - DIR_ONCE_INDEXS) / DIR_INDEX_NODE_INDEXS] = 0;
    }
}

static void *oshfs_init(struct fuse_conn_info *conn)
{
    // for first node
    mem[0] = mmap(NULL, BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    // for root
    mem[1] = mmap(NULL, BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    // first node init
    first_node = (struct first_node *)mem[0];
    first_node->block_size = BLOCK_SIZE;
    first_node->block_num = MEMORY_SIZE / BLOCK_SIZE;
    
    
    first_node->root_index = 1;
    first_node->free_stack_index = 2;
    first_node->free_stack_used = (first_node->block_num * 4 + BLOCK_SIZE - 1) / BLOCK_SIZE;
    first_node->free_block_num = first_node->block_num - 2 - first_node->free_stack_used;

    first_node->dir_file_max = DIR_ONCE_INDEXS + DIR_TWICE_INDEXS * DIR_INDEX_NODE_INDEXS;
    first_node->data_index_max = DATA_ONCE_INDEXS + DATA_TWICE_INDEXS * DATA_INDEX_NODE_INDEXS + DATA_INDEX_NODE_INDEXS * DATA_INDEX_NODE_INDEXS;
    first_node->file_size_max = first_node->data_index_max * (size_t)BLOCK_SIZE;
    // for free index stack
    mem[2] = mmap(NULL, first_node->free_stack_used * BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    for (uint32_t i = 0; i < first_node->free_stack_used; i++) {
        mem[i + 2] = (char *)mem[2] + BLOCK_SIZE * i;
    }
    
    uint32_t *freestack = (uint32_t *)mem[2];

    for (int i = 0; i < first_node->free_block_num; i++) {
        freestack[i] = i + 2 + first_node->free_stack_used;
    }

    // root init
    struct stat st;
    st.st_mode = S_IFDIR | 0755;
    st.st_uid = fuse_get_context()->uid;
    st.st_gid = fuse_get_context()->gid;
    st.st_nlink = 1;
    st.st_size = BLOCK_SIZE;
    filenode_init(first_node->root_index, &st, first_node->root_index);

    return NULL;
}

static int oshfs_getattr(const char *path, struct stat *stbuf)
{
    int ret = 0;
    uint32_t index = get_fileindex(path);
    struct filenode *node;
    if (index) {
        node = (struct filenode *)mem[index];
        memcpy(stbuf, &(node->st), sizeof(struct stat));
    }
    else {
        ret = -ENOENT;
    }
    return ret;
}

static int oshfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    uint32_t index = get_fileindex(path);
    if (index == 0) {
        return -ENOENT;
    }
    struct filenode *node = (struct filenode *)mem[index];
    struct filenode *temp;

    struct file_zone *file;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    file = node->zone.dir.once;
    for(int i = 0; i < DIR_ONCE_INDEXS; i++) {
        if (file[i].index == 0)
            return 0;
        temp = (struct filenode *)mem[file[i].index];
        filler(buf, file[i].name, &(temp->st), 0);
    }
    // for twice dir
    for (int i = 0; i < DIR_TWICE_INDEXS; i++) {
        if (node->zone.dir.twice[i] == 0)
            return 0;
        struct file_index_node *twice = (struct file_index_node *)mem[node->zone.dir.twice[i]];
        file = twice->once;
        for (int j = 0; j < DIR_INDEX_NODE_INDEXS; j++) {
            if (file[j].index == 0)
                return 0;
            temp = (struct filenode *)mem[file[j].index];
            filler(buf, file[j].name, &(temp->st), 0);
        }
    }
    return 0;
}

static int oshfs_mknod(const char *path, mode_t mode, dev_t dev)
{
    struct stat st;
    st.st_mode = mode;
    st.st_uid = fuse_get_context()->uid;
    st.st_gid = fuse_get_context()->gid;
    st.st_nlink = 1;
    st.st_size = 0;
    return create_filenode(path, &st);
}

static int oshfs_open(const char *path, struct fuse_file_info *fi)
{
    if (get_fileindex(path))
        return 0;
    return -ENOENT;
}

static int oshfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    if (offset + size > first_node->file_size_max)
        return -EFBIG;
    uint32_t index = get_fileindex(path);
    if (index == 0)
        return -ENOENT;
    struct filenode *node = (struct filenode *)mem[index];
    
    uint32_t index_need = (size + offset + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if (size + offset > node->st.st_size) {
        int ret = resize(index, size + offset);
        if (ret == -ENOSPC)
            return -ENOSPC;
    }

    uint32_t sz;
    sz = size;

    size_t alloc_size;
    uint32_t target = offset / BLOCK_SIZE;
    for (uint32_t i = target; i < index_need; i++) {
        alloc_size = size > (BLOCK_SIZE - offset % BLOCK_SIZE) ? (BLOCK_SIZE - offset % BLOCK_SIZE) : size;
        if (i < DATA_ONCE_INDEXS) {
            memcpy((char *)mem[node->zone.data.once[i]] + offset % BLOCK_SIZE, buf, alloc_size);
        }
        else if (i < DATA_ONCE_INDEXS + DATA_TWICE_INDEXS * DATA_INDEX_NODE_INDEXS) {
            struct data_index_node *twice = (struct data_index_node *)mem[node->zone.data.twice[(i - DATA_ONCE_INDEXS) / DATA_INDEX_NODE_INDEXS]];
            uint32_t *data = twice->once;
            memcpy((char *)mem[data[(i - DATA_ONCE_INDEXS) % DATA_INDEX_NODE_INDEXS]] + offset % BLOCK_SIZE, buf, alloc_size);
        }
        else {
            uint32_t *data = (uint32_t *)mem[node->zone.data.triple];
            data = (uint32_t *)mem[data[(i - DATA_ONCE_INDEXS - DATA_TWICE_INDEXS * DATA_INDEX_NODE_INDEXS) / DATA_INDEX_NODE_INDEXS]];
            memcpy((char *)mem[data[(i - DATA_ONCE_INDEXS - DATA_TWICE_INDEXS * DATA_INDEX_NODE_INDEXS) % DATA_INDEX_NODE_INDEXS]] + offset % BLOCK_SIZE, buf, alloc_size);
        }
        offset += alloc_size;
        buf += alloc_size;
        size -= alloc_size;
    }
    return sz;
}

static int oshfs_truncate(const char *path, off_t size)
{
    if (size > first_node->file_size_max)
        return -EFBIG;
    uint32_t index = get_fileindex(path);
    if (index == 0)
        return -ENOENT;
    return resize(index, size);
}

static int oshfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    uint32_t index = get_fileindex(path);
    if (index == 0)
        return -ENOENT;
    struct filenode *node = (struct filenode *)mem[index];
    uint32_t index_need = (size + offset + BLOCK_SIZE - 1) / BLOCK_SIZE;

    size_t sz = size;

    size_t read_size;
    uint32_t target = offset / BLOCK_SIZE;

    for (uint32_t i = target; i < index_need && i < node->index_used; i++) {
        read_size = size > (BLOCK_SIZE - offset % BLOCK_SIZE) ? (BLOCK_SIZE - offset % BLOCK_SIZE) : size;
        if (i < DATA_ONCE_INDEXS) {
            memcpy(buf, (char *)mem[node->zone.data.once[i]] + offset % BLOCK_SIZE, read_size);
        }
        else if (i < DATA_ONCE_INDEXS + 2*DATA_INDEX_NODE_INDEXS) {
            uint32_t *data = (uint32_t *)mem[node->zone.data.twice[(i - DATA_ONCE_INDEXS) / DATA_INDEX_NODE_INDEXS]];
            memcpy(buf, (char *)mem[data[(i - DATA_ONCE_INDEXS) % DATA_INDEX_NODE_INDEXS]] + offset % BLOCK_SIZE, read_size);
        }
        else {
            uint32_t *data = (uint32_t *)mem[node->zone.data.triple];
            data = (uint32_t *)mem[data[(i - DATA_ONCE_INDEXS - DATA_TWICE_INDEXS * DATA_INDEX_NODE_INDEXS) / DATA_INDEX_NODE_INDEXS]];
            memcpy(buf, (char *)mem[data[(i - DATA_ONCE_INDEXS - DATA_TWICE_INDEXS * DATA_INDEX_NODE_INDEXS) % DATA_INDEX_NODE_INDEXS]] + offset % BLOCK_SIZE, read_size);
        }
        offset += read_size;
        buf += read_size;
        size -= read_size;
    }
    if (size) {
        memset(buf, 0, size);
    }
    return sz;
}

static int oshfs_unlink(const char *path)
{
    uint32_t index = get_fileindex(path);
    if (index == 0)
        return -ENOENT;
    
    char *filename = rindex(path, '/');
    filename++;
    struct filenode *node = (struct filenode *)mem[index];
    rm_filename(node->father, filename);
    resize(index, 0);
    freeblock(index);
    return 0;
}

static int oshfs_mkdir(const char *path, mode_t mode)
{
    struct stat st;
    st.st_mode = mode | S_IFDIR;
    st.st_uid = fuse_get_context()->uid;
    st.st_gid = fuse_get_context()->gid;
    st.st_nlink = 1;
    st.st_size = BLOCK_SIZE;
    return create_filenode(path, &st);
}

static int oshfs_rmdir(const char *path)
{
    uint32_t index = get_fileindex(path);
    if (index == 0)
        return -ENOENT;
    struct filenode *node = (struct filenode *)mem[index];
    if (node->index_used != 0)
        return -ENOTEMPTY;
    char *filename = rindex(path, '/');
    filename++;
    rm_filename(node->father, filename);
    node = (struct filenode *)mem[node->father];
    node->st.st_size -= BLOCK_SIZE;
    freeblock(index);
    return 0;
}

static const struct fuse_operations op = {
    .init = oshfs_init,
    .getattr = oshfs_getattr,
    .readdir = oshfs_readdir,
    .mknod = oshfs_mknod,
    .open = oshfs_open,
    .write = oshfs_write,
    .truncate = oshfs_truncate,
    .read = oshfs_read,
    .unlink = oshfs_unlink,
    .mkdir = oshfs_mkdir,
    .rmdir = oshfs_rmdir
};

int main(int argc, char *argv[])
{
    return fuse_main(argc, argv, &op, NULL);
}
