#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "harness.h"

int perform_computation() {
  int result = 0;

  for (int i = 0; i < 100; i++)
    result = i + i * 2;

  return result;
}

int main(int argc, char **argv) {
  int result = 0;
  for (int i = 0; i < TEST_ITERATIONS; i++) {
    perf_start_measurement(measure_cpu_clock);
    result = perform_computation();
    perf_stop_measurement(measure_cpu_clock);
    perf_read_measurement(measure_cpu_clock, cpu_clocks + i);
  }

  printf("Result: %d\n", result);
}
