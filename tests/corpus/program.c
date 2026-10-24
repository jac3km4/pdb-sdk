/* Repository-owned fixture source, licensed under the repository's MIT license.
 * No headers, libraries, or CRT are needed to reproduce these PDBs. */
enum Color { Red = 3, Green = 7, Blue = 11 };
union Payload { int integer; unsigned char bytes[4]; };
struct Sample {
    int value;
    enum Color color;
    union Payload payload;
    int values[3];
    const char *name;
};

struct Sample sample = { 42, Green, { 99 }, { 1, 2, 3 }, "fixture" };
volatile int result;

__declspec(noinline) int compute(struct Sample *input, int factor) {
    int local = input->value * factor;
    return local + input->values[1] + input->color;
}

void entry(void) {
    result = compute(&sample, 2);
}
