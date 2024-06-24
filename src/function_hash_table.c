#include "function_hash_table.h"

// Simple hash function for addresses
static uint64_t hash_address(uint64_t address) {
    return ((address) >> 3); // Shift right to reduce the influence of lower bits
}

// Create a new address hash table
FunctionHashTable* create_function_hash_table() {
    FunctionHashTable *table = malloc(sizeof(FunctionHashTable));
    table->capacity = INITIAL_CAPACITY;
    table->size = 0;
    table->total_count = 0;
    table->buckets = calloc(table->capacity, sizeof(FunctionNode*));
    return table;
}

// Free the function hash table
void free_function_hash_table(FunctionHashTable *table) {
    for (size_t i = 0; i < table->capacity; i++) {
        FunctionNode *node = table->buckets[i];
        while (node) {
            FunctionNode *temp = node;
            node = node->next;
            free(temp->comm);
            free(temp->func_name);
            free(temp);
        }
    }
    free(table->buckets);
    free(table);
}

// Resize the address hash table
void resize_function_hash_table(FunctionHashTable *table) {
    size_t new_capacity = table->capacity * 2;
    FunctionNode **new_buckets = calloc(new_capacity, sizeof(FunctionNode*));
    
    for (size_t i = 0; i < table->capacity; i++) {
        FunctionNode *node = table->buckets[i];
        while (node) {
            unsigned long new_index = hash_address(node->address) % new_capacity;
            FunctionNode *temp = node->next;
            node->next = new_buckets[new_index];
            new_buckets[new_index] = node;
            node = temp;
        }
    }
    
    free(table->buckets);
    table->buckets = new_buckets;
    table->capacity = new_capacity;
}

// Insert an address-function name pair into the hash table
int function_hash_table_put(FunctionHashTable *table, uint64_t address, const char *func_name, uint32_t pid, uint32_t cpu_id, const char *comm) {
    if (table->size >= table->capacity * 0.75) {
        resize_function_hash_table(table);
    }
    
    unsigned long index = hash_address(address) % table->capacity;
    FunctionNode *node = table->buckets[index];
    while (node) {
        if (node->address == address) {
            node->count++;
            table->total_count++;
            return 0;
        }
        node = node->next;
    }
    
    FunctionNode *new_node = malloc(sizeof(FunctionNode));
    new_node->address = address;
    new_node->func_name = strdup(func_name);
    new_node->pid = pid;
    new_node->cpu_id = cpu_id;
    new_node->comm = strdup(comm);
    new_node->count = 1;
    new_node->next = table->buckets[index];
    table->buckets[index] = new_node;
    table->size++;
    table->total_count++;
    
    return 0;
}

// Retrieve a function name from the hash table
const FunctionNode* function_hash_table_get(FunctionHashTable *table, uint64_t address) {
    unsigned long index = hash_address(address) % table->capacity;
    FunctionNode *node = table->buckets[index];
    while (node) {
        if (node->address == address) {
            return node;
        }
        node = node->next;
    }
    return NULL;
}

// Function to print all address-function name pairs in the hash table
void print_hash_table(FunctionHashTable *table) {
    for (size_t i = 0; i < table->capacity; i++) {
        FunctionNode *node = table->buckets[i];
        while (node) {
            printf("%016lx %-32s @ CPU %u === %.2f%%\n", node->address, node->func_name, node->cpu_id, (node->count / (float)table->total_count) * 100);
            node = node->next;
        }
    }
}
