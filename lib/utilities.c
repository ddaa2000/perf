#include <errno.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "perf.h"
#include "utilities.h"

// CAP_PERFMON was added in Linux 5.8
// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/capability.h
#ifndef CAP_PERFMON
#define CAP_PERFMON 38
#endif

#define true 1
#define false 0

void perf_print_error(int error) {
  switch (error) {
  case PERF_ERROR_IO:
    perror("io error");
    break;
  case PERF_ERROR_LIBRARY_FAILURE:
    perror("library failure");
    break;
  case PERF_ERROR_CAPABILITY_NOT_SUPPORTED:
    fprintf(stderr, "unsupported capability\n");
    break;
  case PERF_ERROR_EVENT_OPEN:
    perror("perf_event_open failed");
    break;
  case PERF_ERROR_NOT_SUPPORTED:
    perror("not supported");
    break;
  case PERF_ERROR_BAD_PARAMETERS:
    fprintf(stderr, "bad parameters\n");
    break;
  default:
    fprintf(stderr, "unknown error\n");
    break;
  }
}

int perf_is_supported() {
  return access("/proc/sys/kernel/perf_event_paranoid", F_OK) == 0 ? 1 : 0;
}

int perf_get_event_paranoia() {
  // See: https://www.kernel.org/doc/Documentation/sysctl/kernel.txt
  FILE *perf_event_paranoid = fopen("/proc/sys/kernel/perf_event_paranoid", "r");
  if (perf_event_paranoid == NULL)
    return PERF_ERROR_IO;

  int value;
  if (fscanf(perf_event_paranoid, "%d", &value) < 1)
    return PERF_ERROR_IO;

  if (value >= 2)
    return PERF_EVENT_PARANOIA_DISALLOW_CPU | PERF_EVENT_PARANOIA_DISALLOW_FTRACE | PERF_EVENT_PARANOIA_DISALLOW_KERNEL;
  if (value >= 1)
    return PERF_EVENT_PARANOIA_DISALLOW_CPU | PERF_EVENT_PARANOIA_DISALLOW_FTRACE;
  if (value >= 0)
    return PERF_EVENT_PARANOIA_DISALLOW_CPU;
  return PERF_EVENT_PARANOIA_ALLOW_ALL;
}

int perf_has_sufficient_privilege(const perf_measurement_t *measurement) {
  // Immediately return if the user is an admin
  int has_cap_sys_admin = perf_has_capability(CAP_SYS_ADMIN);
  if (has_cap_sys_admin == 1)
    return true;

  int event_paranoia = perf_get_event_paranoia();
  if (event_paranoia < 0)
    return event_paranoia;

  // This requires CAP_PERFMON (since Linux 5.8) or CAP_SYS_ADMIN capability or a  perf_event_paranoid value of less than 1.
  if (measurement->pid == -1 && measurement->cpu >= 0) {
    int kernel_major, kernel_minor;
    int status = perf_get_kernel_version(&kernel_major, &kernel_minor, NULL);
    if (status != true)
      return status;

    if (kernel_major >= 5 && kernel_minor >= 8) {
      int has_cap_perfmon = perf_has_capability(CAP_PERFMON);
      if (has_cap_perfmon != true)
        return has_cap_perfmon;
    } else {
      // CAP_SYS_ADMIN is already checked at the start of this function
    }
  }

  // Immediately return if all events are allowed
  if (event_paranoia & PERF_EVENT_PARANOIA_ALLOW_ALL)
    return true;

  if (event_paranoia & PERF_EVENT_PARANOIA_DISALLOW_FTRACE && measurement->attribute.type == PERF_TYPE_TRACEPOINT)
    return has_cap_sys_admin;

  if (event_paranoia & PERF_EVENT_PARANOIA_DISALLOW_CPU && measurement->attribute.type == PERF_TYPE_HARDWARE)
    return has_cap_sys_admin;

  if (event_paranoia & PERF_EVENT_PARANOIA_DISALLOW_KERNEL && measurement->attribute.type == PERF_TYPE_SOFTWARE)
    return has_cap_sys_admin;

  // Assume privileged
  return true;
}

int perf_has_capability(int capability) {
  if (!CAP_IS_SUPPORTED(capability))
    return PERF_ERROR_CAPABILITY_NOT_SUPPORTED;

  cap_t capabilities = cap_get_proc();
  if (capabilities == NULL)
    return PERF_ERROR_LIBRARY_FAILURE;

  cap_flag_value_t sys_admin_value;
  if (cap_get_flag(capabilities, capability, CAP_EFFECTIVE, &sys_admin_value) < 0) {
    cap_free(capabilities);
    return PERF_ERROR_LIBRARY_FAILURE;
  }

  if (cap_free(capabilities) < 0)
    return PERF_ERROR_LIBRARY_FAILURE;

  // Return whether or not the user has the capability
  return sys_admin_value == CAP_SET;
}

perf_measurement_t *perf_create_measurement(unsigned type, unsigned config, pid_t pid, int cpu) {
  perf_measurement_t *measurement = (perf_measurement_t *)malloc(sizeof(perf_measurement_t));
  if (measurement == NULL)
    return NULL;

  memset((void *)measurement, 0, sizeof(perf_measurement_t));

  measurement->pid = pid;
  measurement->cpu = cpu;

  measurement->attribute.type = type;
  measurement->attribute.config = config;
  measurement->attribute.disabled = 1;
  measurement->attribute.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID;
  // measurement->attribute.exclude_user = !(space_mode & SPACE_USER);
  // measurement->attribute.exclude_kernel = !(space_mode & SPACE_KERNEL);

  return measurement;
}

int perf_open_measurement(perf_measurement_t *measurement, int group, int flags) {
  // Invalid parameters. See: https://man7.org/linux/man-pages/man2/perf_event_open.2.html
  if (measurement->pid == -1 && measurement->cpu == -1)
    return PERF_ERROR_BAD_PARAMETERS;

  int file_descriptor = perf_event_open(&measurement->attribute, measurement->pid, measurement->cpu, group, flags);
  if (file_descriptor < 0) {
    if (errno == ENODEV ||
        errno == ENOENT ||
        errno == ENOSYS ||
        errno == EOPNOTSUPP ||
        errno == EPERM)
      return PERF_ERROR_NOT_SUPPORTED;
    return PERF_ERROR_EVENT_OPEN;
  }

  measurement->file_descriptor = file_descriptor;
  measurement->group = group;

  // Get the ID of the measurement
  if (ioctl(measurement->file_descriptor, PERF_EVENT_IOC_ID, &measurement->id) < 0)
    return PERF_ERROR_LIBRARY_FAILURE;

  return 0;
}

void perf_start_measurement(perf_measurement_t *measurement){              
  do {                                                                              
    ioctl((measurement)->file_descriptor, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP); 
    ioctl((measurement)->file_descriptor, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
  } while (0);
}

// Stop a measurement.
int perf_stop_measurement(perf_measurement_t *measurement){
  return ioctl((measurement)->file_descriptor, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
}

int perf_read_measurement(const perf_measurement_t *measurement, void *target, size_t bytes) {
  return read(measurement->file_descriptor, target, bytes);
}

int perf_get_kernel_version(int *major, int *minor, int *patch) {
  struct utsname name;
  if (uname(&name) < 0)
    return PERF_ERROR_LIBRARY_FAILURE;

  int parsed_major, parsed_minor, parsed_patch;

  if (sscanf(name.release, "%d.%d.%d", &parsed_major, &parsed_minor, &parsed_patch) < 3)
    return PERF_ERROR_IO;

  if (major != NULL)
    *major = parsed_major;
  if (minor != NULL)
    *minor = parsed_minor;
  if (patch != NULL)
    *patch = parsed_patch;

  return 0;
}

int perf_event_is_supported(const perf_measurement_t *measurement) {
  // Invalid parameters. See: https://man7.org/linux/man-pages/man2/perf_event_open.2.html
  if (measurement->pid == -1 && measurement->cpu == -1)
    return PERF_ERROR_BAD_PARAMETERS;

  int file_descriptor = perf_event_open(&measurement->attribute, measurement->pid, measurement->cpu, -1, 0);
  if (file_descriptor < 0) {
    if (errno == ENODEV ||
        errno == ENOENT ||
        errno == ENOSYS ||
        errno == EOPNOTSUPP ||
        errno == EPERM)
      return 0;
    return PERF_ERROR_EVENT_OPEN;
  }

  if (close(file_descriptor) < 0)
    return PERF_ERROR_IO;

  return 1;
}

int perf_close_measurement(const perf_measurement_t *measurement) {
  if (close(measurement->file_descriptor) < 0)
    return PERF_ERROR_IO;

  return 0;
}

static int prepare_measurement(perf_measurement_t *measurement, perf_measurement_t *parent_measurement) {
  int status = perf_has_sufficient_privilege(measurement);
  if (status < 0) {
    perf_print_error(status);
    return status;
  } else if (status == 0) {
    fprintf(stderr, "error: unprivileged user\n");
    return -1;
  }

  int support_status = perf_event_is_supported(measurement);
  if (support_status < 0) {
    perf_print_error(support_status);
    return support_status;
  } else if (support_status == 0) {
    fprintf(stderr, "warning: not supported\n");
    return -1;
  }

  int group = parent_measurement == NULL ? -1 : parent_measurement->file_descriptor;

  status = perf_open_measurement(measurement, group, 0);
  if (status < 0) {
    perf_print_error(status);
  }
  return 0;
}

void perf_free_measurement(perf_measurement_t *measurement){
  free(measurement);
}

perf_measurement_group_t *perf_create_group(perf_measurement_t** measurements, int size){
  perf_measurement_group_t* group = (perf_measurement_group_t*)malloc(sizeof(perf_measurement_group_t));
  group->measurements = (perf_measurement_t**)malloc(size * sizeof(perf_measurement_t*));
  for(int i = 0; i < size; i++){
    group->measurements[i] = measurements[i];
  }
  group->size = size;
  group->dummy_parent = perf_create_measurement(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_DUMMY, 0, -1);
  return group;
}

int perf_open_group(perf_measurement_group_t *group){
  int status = prepare_measurement(group->dummy_parent, NULL);
  if(status < 0){
    printf("error: create dummy failed\n");
    return -1;
  }
  for(int i = 0; i < group->size; i++){
    status = prepare_measurement(group->measurements[i], group->dummy_parent);
    if(status < 0){
      printf("error: create %d measurement failed\n", i);
      return -1;
    }
  }
  return 0;
}



void perf_start_measurement_group(perf_measurement_group_t *group){
  perf_start_measurement(group->dummy_parent);
}

void perf_stop_measurement_group(perf_measurement_group_t *group){
  perf_stop_measurement(group->dummy_parent);
}

// void perf_read_measurement_group(perf_measurement_group_t *group, void *target, size_t bytes){
//   perf_read_measurement(group->dummy_parent, target, bytes);
// }

void perf_close_measurement_group(perf_measurement_group_t *group){
  perf_close_measurement(group->dummy_parent);
}

typedef struct{
  uint64_t value;
  uint64_t id;
}value_t;

measurement_group_t perf_decode_group(perf_measurement_group_t *group){
  uint64_t* values = (uint64_t*)malloc(group->size * sizeof(uint64_t));


  int size = 0;

  uint64_t expected_size = (group->size + 1) * sizeof(value_t)+sizeof(uint64_t);
  char* buff = (char*)malloc(expected_size);
  size += perf_read_measurement(group->dummy_parent, buff, expected_size);
  // size += perf_read_measurement(group->dummy_parent, recorded_values, group->size * sizeof(value_t));

  uint64_t recorded_nums = *(uint64_t*)buff;
  value_t* recorded_values = (value_t*)(((uint64_t*)buff)+1);

  // printf("recorded nums: %u\n", recorded_nums);
  // printf("expected size: %u\n", expected_size);
  // printf("size: %d\n", size);

  // for(int j = 0; j < group->size; j++){
  //   printf("id: %u\n", group->measurements[j]->id);
  // }

  for(uint64_t i = 0; i < recorded_nums; i++){
    // printf("id: %u, num: %u\n", recorded_values[i].id, recorded_values[i].value);
    for(int j = 0; j < group->size; j++){
      if(recorded_values[i].id == group->measurements[j]->id){
        values[j] = recorded_values[i].value;
        break;
      }
    }
  }
  

  measurement_group_t result;
  result.recorded_values = recorded_nums - 1;
  result.values = values;
  free(buff);
  return result;
}

void perf_free_measurement_group(perf_measurement_group_t *group){
  for(int i = 0; i < group->size; i++){
    perf_free_measurement(group->measurements[i]);
  }
  free(group->measurements);
  perf_free_measurement(group->dummy_parent);
  free(group);
}

void perf_free_measurement_results(measurement_group_t results){
  free(results.values);
}