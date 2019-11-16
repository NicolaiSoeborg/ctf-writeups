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
  seed = getDigits(seed, 5, 12);
  seed *= seed;
  return getDigits(seed, 13, 16);
}

void print_flag() {
  FILE *f = fopen("flag.txt", "r");
  char flag[100];
  fgets(flag, sizeof(flag), f);
  printf("%s\n", flag);
  return;
}

const char *messages[NUM_CORRECT] =
{ "\nYeah, yeah, one correct guess is easy.\n"
"Enter your second guess:\n> ",
  "\nOkay, you're lucky... You won't be able to guess right a third time.\n"
  "Enter your third guess:\n> ",
  "\nWow. I'll admit I'm impressed. This is the final test. \n"
  "Enter your fourth guess:\n> ",
  "\nOh no... we're in the endgame now... Here's your flag:\n"
};

int main() {
  setvbuf(stdout, NULL, _IONBF, 0);
  init_seed();
  printf("\nWelcome to Dr. J's Random Number Generator v2! A vulnerability involving "
  "predictability of outputs has been patched. \n"
  "[r] Print a new random number \n"
  "[g] Guess the next four random numbers and receive the flag! \n"
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
      printf("\nGuess the next four random numbers for a flag! "
      "Dr. Strange sees fourteen million six hundred and five possibilies... and you only guess correctly in one. "
      "Good luck!\nEnter your first guess:\n> ");

      for (int i = 0; i < NUM_CORRECT; i++) {
        uint64_t guess = 0;
        fgets (line, sizeof(line), stdin);
        sscanf(line, "%lu", &guess);
        if (guess == nextRand()) {
          printf("%s", messages[i]);
          if (i == 3) {
            print_flag();
            break;
          }
        }
        else {
          printf("That's incorrect. Get out of here!\n");
          break;
        }
      }
      break;
    }
    if (!strcmp("q", line)) {
      printf("\nGoodbye!\n");
      break;
    }
  }
  return 0;
}
