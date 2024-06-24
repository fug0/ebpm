#ifndef FUNCTION_HASH_TABLE_H
#define FUNCTION_HASH_TABLE_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define INITIAL_CAPACITY 1024

typedef struct FunctionNode {
    uint64_t address;
	uint32_t pid;
	uint32_t cpu_id;
	uint32_t count;
    char *func_name;
    char *comm;
    struct FunctionNode *next;
} FunctionNode;

typedef struct {
    FunctionNode **buckets;
    size_t capacity;
    size_t size;
    size_t total_count;
} FunctionHashTable;

FunctionHashTable* create_function_hash_table();
void free_function_hash_table(FunctionHashTable *table);
int function_hash_table_put(FunctionHashTable *table, uint64_t address, const char *func_name, uint32_t pid, uint32_t cpu_id, const char *comm);
const FunctionNode* function_hash_table_get(FunctionHashTable *table, uint64_t address);
void print_hash_table(FunctionHashTable *table);

#endif // FUNCTION_HASH_TABLE_H