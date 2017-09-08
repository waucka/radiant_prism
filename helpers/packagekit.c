#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Seriously?
#define I_KNOW_THE_PACKAGEKIT_GLIB2_API_IS_SUBJECT_TO_CHANGE
#include <packagekit-glib2/packagekit.h>

#define PACKAGEKIT_ERR_NONE    0
#define PACKAGEKIT_ERR_PEBKAC  1
#define PACKAGEKIT_ERR_RESOLVE 2

#define PKH_GET_INSTALLED 0
#define PKH_GET_UPDATES   1

/*
YAML FORMAT
kind: PackageList
items:
  - name: "foobar"
    version: "1.0"
    arch: "amd64"
  - name: "dingus"
    version: "0.1"
    arch: "amd64"
...
 */

int enum_packages(int get_type) {
  GError *error = NULL;
  PkError *error_code = NULL;
  PkResults *results = NULL;
  GPtrArray *array = NULL;
  PkPackage *item;
  uint i;
  PkTask *task;
  int err = PACKAGEKIT_ERR_NONE;

  task = pk_task_new();

  switch(get_type) {
  case PKH_GET_INSTALLED:
    results = pk_task_get_packages_sync(task, PK_FILTER_ENUM_INSTALLED, NULL, NULL, NULL, &error);
    break;
  case PKH_GET_UPDATES:
    results = pk_task_get_updates_sync(task, PK_FILTER_ENUM_NOT_INSTALLED, NULL, NULL, NULL, &error);
    break;
  default:
    err = PACKAGEKIT_ERR_PEBKAC;
    goto out;
  }

  error_code = pk_results_get_error_code (results);
  if (error_code != NULL) {
    g_printerr ("%s: %s, %s\n", "Resolving of packages failed",
		pk_error_enum_to_string (pk_error_get_code (error_code)),
		pk_error_get_details (error_code));
    err = PACKAGEKIT_ERR_RESOLVE;
    goto out;
  }

  printf("kind: PackageList\n");
  array = pk_results_get_package_array (results);
  if (array->len > 0) {
    printf("items:\n");
    for (i = 0; i < array->len; i++) {
      item = g_ptr_array_index (array, i);
      printf("  - name: \"%s\"\n    version: \"%s\"\n    arch: \"%s\"\n", pk_package_get_name(item), pk_package_get_version(item), pk_package_get_arch(item));
    }
  } else {
    printf("items: {}\n");
  }

 out:
  g_object_unref (task);
  if (error_code != NULL)
    g_object_unref (error_code);
  if (array != NULL)
    g_ptr_array_unref (array);
  if (results != NULL)
    g_object_unref (results);

  return err;
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    return PACKAGEKIT_ERR_PEBKAC;
  }
  int get_type = -1;
  if (strcmp(argv[1], "installed") == 0) {
    get_type = PKH_GET_INSTALLED;
  }
  else if (strcmp(argv[1], "updates") == 0) {
    get_type = PKH_GET_UPDATES;
  } else {
    return PACKAGEKIT_ERR_PEBKAC;
  }
  return enum_packages(get_type);
}
