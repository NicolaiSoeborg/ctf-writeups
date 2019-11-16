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
  printf("\nWelcome to Dr. J's Random Number Generator v1! \n"
  "[r] Print a new random number \n"
  "[g] Guess the next two random numbers and receive the flag! \n"
  "[q] Quit \n\n");
  char line[100];
  while (true) {
    printf("> ");
    fgets (line, sizeof(line), stdin);
    line[strcspn(line, "\n")] = 0;

    if (!strcmp("r", line)) {
      uint64_t r = nextRand();
      printf("%lu\n", r);
    }
    if (!strcmp("g", line)) {
      printf("\nGuess the next two random numbers for a flag! "
      "You have a 0.0000000000000000000000000000001%% chance of guessing both correctly... "
      "Good luck!\nEnter your first guess:\n> ");
      uint64_t guess = 0;
      fgets (line, sizeof(line), stdin);
      sscanf(line, "%lu", &guess);
      if (guess == nextRand()) {
        printf("\nWow, lucky guess... You won't be able to guess right a second time.\n"
        "Enter your second guess:\n> ");
      }
      else {
        printf("That's incorrect. Get out of here!\n");
        break;
      }
      guess = 0;
      fgets (line, sizeof(line), stdin);
      sscanf(line, "%lu", &guess);
      if (guess == nextRand()) {
        printf("\nWhat? You must have psychic powers... Well here's your flag: ");
        print_flag();
        break;
      }
      else {
        printf("That's incorrect. Get out of here!\n");
        break;
      }
    }
    if (!strcmp("q", line)) {
      printf("\nGoodbye!\n");
      break;
    }
  }
  return 0;
}
