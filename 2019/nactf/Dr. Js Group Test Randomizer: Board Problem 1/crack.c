#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <sodium.h>
#include <limits.h>

#define NUM_CORRECT 4

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
  // Keep the 8 middle digits from 5 to 12 inclusive and square.
  seed = getDigits(seed, 5, 12);  // 9876_65412345_6789 => 65412345
  seed *= seed;                   // 65412345 * 65412345
  return getDigits(seed, 13, 16);
}

int main() {
  setvbuf(stdout, NULL, _IONBF, 0);
  init_seed();

  /*for (uint i = 0; i < 100; i++)
    nextRand();

  if (nextRand() != 39 && nextRand() != 0) {
    printf("Nope (%lu).\n", nextRand());
    for (uint i = 0; i < 1000; i++) nextRand();
  }*/

  for (uint64_t cnt = 0; cnt < 10; cnt++) {
    init_seed();
    uint64_t start_seed = seed + 0;
    uint64_t got_good_at = 0;

  
    uint64_t r;
    for (uint64_t i = 0; i < 2000; i++) {
      r = nextRand();
      if (r == 0 || r == 39) got_good_at += 1;
      //printf("%lu\n", r);
    }

    if ((r == 39 || r == 0) && (nextRand() == r && nextRand() == r)) {
      //printf("GOOD START SEED: %lu (%lu)\n", start_seed, 20000-got_good_at);
      printf("%lu\n", 2000-got_good_at);
    } else {
      //printf("BAAD START SEED: %lu\n", start_seed);
    }
  }

  return 0;
}
