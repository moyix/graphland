#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef struct _graph_node graph_node_t;

typedef struct _graph_node {
    int num_neighbors;
    int label;
    void *metadata;
    graph_node_t *hash_next;
    graph_node_t **neighbors;
} graph_node_t;

typedef enum _opcode {
    ADD_NODE,
    DEL_NODE,
    SET_METADATA,
    ADD_EDGE,
    DEL_EDGE,
    PRINT_GRAPH,
    PRINT_NODE,
    LAST_OPCODE
} opcode_t;

char *opcode_names[] = {
    "ADD_NODE",
    "DEL_NODE",
    "SET_METADATA",
    "ADD_EDGE",
    "DEL_EDGE",
    "PRINT_GRAPH",
    "PRINT_NODE"
};

// Handler prototypes
void add_node(uint8_t *, int);
void del_node(uint8_t *, int);
void set_metadata(uint8_t *, int);
void add_edge(uint8_t *, int);
void del_edge(uint8_t *, int);
void print_graph(uint8_t *, int);
void print_node(uint8_t *, int);

void (*opcode_handlers[])(uint8_t *, int) = {
    [ADD_NODE] = add_node,
    [DEL_NODE] = del_node,
    [SET_METADATA] = set_metadata,
    [ADD_EDGE] = add_edge,
    [DEL_EDGE] = del_edge,
    [PRINT_GRAPH] = print_graph,
    [PRINT_NODE] = print_node,
};

typedef struct _command {
    uint16_t opcode;
    uint16_t size;
    uint8_t *data;
} command_t;

#define HASH_SIZE 128
struct graph_hashtable {
    graph_node_t *buckets[HASH_SIZE];
} graph = {};

int hash_node(int label) {
    if (label < 0) label = -label;
    return label % HASH_SIZE;
}

void free_node(graph_node_t *node) {
    free(node->metadata);
    free(node->neighbors);
    free(node);
}

void hash_insert(graph_node_t *node) {
    if (node == NULL) return;
    int nodehash = hash_node(node->label);
    node->hash_next = NULL;
    
    graph_node_t *cursor = graph.buckets[nodehash];
    if (!cursor) {
        graph.buckets[nodehash] = node;
        //printf("DEBUG: inserted label %d node %p\n", node->label, node);
        return;
    }
    // Seek to the last element
    graph_node_t *last;
    while(cursor) {
        // Don't allow duplicate labels
        if (cursor->label == node->label) {
            //printf("DEBUG: not adding duplicate node %d\n", node->label);
            free_node(node);
            return;
        }
        last = cursor;
        cursor = cursor->hash_next;
    }

    // Insert
    last->hash_next = node;
    //printf("DEBUG: inserted label %d node %p\n", node->label, node);
    return;
}

graph_node_t * hash_lookup(int label) {
    //printf("DEBUG: trying to look up label %d\n", label);
    graph_node_t *cursor = graph.buckets[hash_node(label)];
    while (cursor) {
        if (cursor->label == label) break;
        cursor = cursor->hash_next;
    }
    //printf("DEBUG: label %d => %p\n", label, cursor);
    return cursor;
}

// Remove node from the hash by label
// Does NOT free the node
void hash_remove(int label) {
    //printf("DEBUG: trying to remove label %d\n", label);
    graph_node_t *cursor = graph.buckets[hash_node(label)];
    // Didn't find it, bail
    if (!cursor) return;
    // Special case for first bucket entry
    if (cursor->label == label) {
        graph.buckets[hash_node(label)] = cursor->hash_next;
        if (!cursor->hash_next) return;
    }
    while(cursor->hash_next) {
       if (cursor->hash_next->label == label) {
           cursor->hash_next = cursor->hash_next->hash_next;
           return;
       }
       cursor = cursor->hash_next;
    }
    return;
}

void add_node(uint8_t *data, int size) {
    if (size != sizeof(int)) return;
    int label = *(int *)data;
    //printf("DEBUG: adding node with label %d\n", label);
    graph_node_t *node = calloc(1, sizeof(graph_node_t));
    if (!node) return;
    node->label = label;
    hash_insert(node);
}

void del_node(uint8_t *data, int size) {
    if (size != sizeof(int)) return;
    int label = *(int *)data;
    //printf("DEBUG: deleting node with label %d\n", label);
    graph_node_t *node = hash_lookup(label);
    if (!node) return;
    hash_remove(label);
    free_node(node);
}

void set_metadata(uint8_t *data, int size) {
    if (size < 2*sizeof(int)) return;
    int label = *(int *)data;
    int metadata_len = *(int *)(data + sizeof(int));
    //printf("DEBUG: setting metadata for node %d mdlen %d\n", label, metadata_len);
    if (size != 2*sizeof(int) + metadata_len) return;
    graph_node_t *node = hash_lookup(label);
    //printf("DEBUG: node lookup returned %p\n", node);
    if (!node) return;
    if (node->metadata) {
        //printf("DEBUG: node has pre-existing metadata, freeing\n");
        free(node->metadata);
        node->metadata = NULL;
    }
    uint8_t *metadata = malloc(metadata_len);
    if (!metadata) return;
    memcpy(metadata, data + 2*sizeof(int), metadata_len);
    node->metadata = metadata;
}

void add_edge(uint8_t *data, int size) {
    if (size != 2*sizeof(int)) return;
    int src_label = *(int *)data;
    int dst_label = *(int *)(data + sizeof(int));
    graph_node_t *src_node = hash_lookup(src_label);
    if (!src_node) return;
    graph_node_t *dst_node = hash_lookup(dst_label);
    if (!dst_node) return;

    src_node->num_neighbors++;
    // Increase the neighbor array size
    src_node->neighbors = realloc(src_node->neighbors,
            src_node->num_neighbors * sizeof(graph_node_t *));
    if (!src_node->neighbors) {
        src_node->num_neighbors--;
        return;
    }
    src_node->neighbors[src_node->num_neighbors-1] = dst_node;
}

void del_edge(uint8_t *data, int size) {
    if (size != 2*sizeof(int)) return;
    int src_label = *(int *)data;
    int dst_label = *(int *)(data + sizeof(int));
    graph_node_t *src_node = hash_lookup(src_label);
    if (!src_node) return;
    graph_node_t *dst_node = hash_lookup(dst_label);
    if (!dst_node) return;
    int i;
    for (i = 0; i < src_node->num_neighbors; i++) {
        if (src_node->neighbors[i] == dst_node) break;
    }
    // If not found ignore
    if (i == src_node->num_neighbors) return;
    // Shift array down by one
    memmove(src_node->neighbors+i,
            src_node->neighbors+i+1,
            src_node->num_neighbors-(i+1));
    // Resize array
    src_node->num_neighbors--;
    graph_node_t **tmp = realloc(src_node->neighbors,
            src_node->num_neighbors * sizeof(graph_node_t *));
    // Need to distinguish between realloc failure and the case
    // where we simply resized the array down to 0
    if (!tmp && src_node->num_neighbors) {
        src_node->num_neighbors++;
        return;
    }
    src_node->neighbors = tmp;
}

static void print_node_internal(graph_node_t *node) {
#ifndef FUZZER
    printf("[node @%p with label %d]\n", node, node->label);
#endif
    for (int i = 0; i < node->num_neighbors; i++) {
#ifndef FUZZER
        printf("[edge %d -> %d]\n", node->label, node->neighbors[i]->label);
#endif
    }
}

void print_graph(uint8_t *data, int size) {
    graph_node_t *cursor;
    for(int i = 0; i < HASH_SIZE; i++) {
        cursor = graph.buckets[i];
        while(cursor) {
            print_node_internal(cursor);
            cursor = cursor->hash_next;
        }
    }
}

void print_node(uint8_t *data, int size) {
    if (size != sizeof(int)) return;
    int label = *(int *)data;
    graph_node_t *node = hash_lookup(label);
    if (!node) return;
    print_node_internal(node);
}

void free_graph() {
    graph_node_t *cursor;
    for(int i = 0; i < HASH_SIZE; i++) {
        cursor = graph.buckets[i];
        while(cursor) {
            graph_node_t *tmp = cursor;
            cursor = cursor->hash_next;
            free_node(tmp);
        }
        graph.buckets[i] = NULL;
    }
}

void test_hashtable() {
    for (int i = 0; i < 10000; i++) {
        add_node((uint8_t *)&i, sizeof(i));
    }
    for (int i = 0; i < 10000-1; i++) {
        int buf[2] = {i, i+1};
        add_edge((uint8_t *)buf, sizeof(buf));
        buf[0] = i+1;
        buf[1] = i;
        add_edge((uint8_t *)buf, sizeof(buf));
    }
    for (int i = 0; i < 10000-1; i++) {
        int buf[2] = {i, i+1};
        del_edge((uint8_t *)buf, sizeof(buf));
    }
    for (int i = 0; i < 10000; i++) {
        assert(hash_lookup(i) != NULL);
    }
    for (int i = 0; i < 10000; i++) {
        del_node((uint8_t *)&i, sizeof(i));
    }
    free_graph();
}

#ifndef FUZZER
int main(int argc, char **argv) {
    int err = 0;
    if (argc < 2) {
        test_hashtable();
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        err = 1; goto cleanup;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        err = 1; goto cleanup;
    }
    while (!feof(f)) {
        uint16_t opcode;
        uint16_t size;
        int n;
        n = fread(&opcode, sizeof(uint16_t), 1, f);
        if (!n) {
            fprintf(stderr, "failed to read from file\n");
            err = 1; goto cleanup;
        }
        n = fread(&size, sizeof(uint16_t), 1, f);
        if (!n) {
            fprintf(stderr, "failed to read from file\n");
            err = 1; goto cleanup;
        }
        uint8_t *data = malloc(size);
        if (!data) {
            perror("malloc");
            err = 1; goto cleanup;
        }
        n = fread(data, size, 1, f);
        if (!n) {
            fprintf(stderr, "failed to read from file\n");
            err = 1; goto cleanup;
        }
        if (opcode >= LAST_OPCODE) {
            fprintf(stderr, "note: invalid opcode, skipping\n");
            free(data);
            continue;
        }
        //printf("DEBUG: opcode %s size %d\n", opcode_names[opcode], size);
        opcode_handlers[opcode](data, size);
        free(data);
    }

cleanup:
    free_graph();

    return err;
}

#else

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    int i = 0;
    uint8_t *dp = (uint8_t *)Data;
    while (i < Size) {
        if (Size - i < sizeof(uint16_t)) goto cleanup;
        uint16_t opcode = *(uint16_t *)(dp+i); i += sizeof(uint16_t);
        if (Size - i < sizeof(uint16_t)) goto cleanup;
        uint16_t cmd_size = *(uint16_t *)(dp+i); i += sizeof(uint16_t);
        if (Size - i < cmd_size) goto cleanup;
        if (opcode >= LAST_OPCODE) {
            i += cmd_size;
            continue;
        }
        //printf("DEBUG: opcode %s size %d\n", opcode_names[opcode], cmd_size);
        opcode_handlers[opcode](dp+i, cmd_size);
        i += cmd_size;
    }
cleanup:
    free_graph();
    return 0;
}

#endif
