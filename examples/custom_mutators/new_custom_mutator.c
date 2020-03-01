/*
  New Custom Mutator for AFL++

  Written by Andrea Fioraldi <andreafioraldi@gmail.com>
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void afl_custom_init(unsigned int seed) {

  srand(seed);

}

int afl_custom_queue_get(char* filename) {

  fprintf("Extracting %s from the queue.\n", filename);
  return 1;

}

size_t afl_custom_fuzz(uint8_t *buf, size_t buf_size,
                       uint8_t *add_buf,size_t add_buf_size, // add_buf can be NULL
                       uint8_t *mutated_out, size_t max_size) {

  memcpy(mutated_out, buf, buf_size);
  
  return buf_size;

}

uint8_t *trim_buf;
size_t trim_buf_size
int trimmming_steps;
int cur_step;

int afl_custom_init_trim(uint8_t *buf, size_t buf_size) {

  if (buf_size > 100) trimmming_steps = 10;
  else trimmming_steps = 1;
  
  cur_step = 0;
  trim_buf = buf;
  trim_buf_size = buf_size;
  
  return trimmming_steps;

}

void afl_custom_trim(uint8_t *new_buf, size_t* new_size) {

  *new_size = trim_buf_size - 1;

}

int afl_custom_post_trim(int success) {

  if (success) {
    ++cur_step;
    return cur_step;
  }
  
  return trimmming_steps;

}

size_t afl_custom_pre_save(uint8_t *data, size_t size, uint8_t **new_data) {

  *new_data = data;
  return size;

}
