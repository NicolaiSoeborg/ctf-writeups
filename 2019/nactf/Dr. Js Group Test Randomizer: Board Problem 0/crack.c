#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <sodium.h>
#include <limits.h>


uint64_t seed = 0;

void init_seed() {
  uint64_t r1 = (uint64_t) randombytes_random();
  uint64_t r2 = (uint64_t) randombytes_random();
  seed = (r1 << 32) + r2;
}

uint64_t getDigits(uint64_t number, double start, double end) {
  // Return the digits of number from start to end (inclusive) counting from the right.
  // For example, getDigits(987654321, 3, 5) = 543
  return (number % lround(pow(10, end)))/lround(pow(10, start-1));
}

uint64_t nextRand() {
  // Keep the 8 middle digits from 5 to 12 (inclusive) and square.
  seed = getDigits(seed, 5, 12);
  seed *= seed;
  return seed;
}

void print_flag() {
  FILE *f = fopen("flag.txt", "r");
  char flag[48];
  fgets(flag, sizeof(flag), f);
  printf("%s\n", flag);
  return;
}

int main() {
  setvbuf(stdout, NULL, _IONBF, 0);
  init_seed();

  seed = 7686699414782976;
  printf("%lu\n", nextRand());
  printf("%lu\n", nextRand());


  return 0;
}
