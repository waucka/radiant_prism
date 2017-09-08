#include <stdlib.h>
#include <stdio.h>
#include <flatpak.h>

#define FLATPAK_APPS_ERR_NONE       0
#define FLATPAK_APPS_ERR_INCOMPLETE 1
#define FLATPAK_APPS_ERR_UNKNOWN    2

/*
YAML FORMAT
kind: FlatpakAppList
items:
  - origin: "blahblahblah"
    commit: "whatever"
    latest_commit: "stuff"
  - origin: "differentblah"
    commit: "whatever2"
    latest_commit: "lulz"
...
 */

int enum_apps_for_installation(FlatpakInstallation *flatpakInstallation) {
  GError* installation_error = NULL;
  GPtrArray* refs = NULL;

  int err = FLATPAK_APPS_ERR_NONE;

  refs = flatpak_installation_list_installed_refs_by_kind(flatpakInstallation, FLATPAK_REF_KIND_APP, NULL, &installation_error);
  if (!refs) {
    g_free(installation_error);
    return FLATPAK_APPS_ERR_INCOMPLETE;
  }

  for (uint i = 0; i < refs->len; i++) {
    FlatpakInstalledRef* ref = FLATPAK_INSTALLED_REF(g_ptr_array_index(refs, i));
    const gchar* latest_commit = flatpak_installed_ref_get_latest_commit(ref);
    const gchar* origin = flatpak_installed_ref_get_origin(ref);

    if (!latest_commit) {
      err = FLATPAK_APPS_ERR_INCOMPLETE;
    }

    const gchar* commit = flatpak_ref_get_commit(FLATPAK_REF(ref));

    printf("  - origin: \"%s\"\n", origin);
    printf("    commit: \"%s\"\n", commit);
    printf("    latest_commit: \"%s\"\n", latest_commit);
  }

  g_free(installation_error);
  g_ptr_array_free(refs, TRUE);
  return err;
}

int enum_flatpak_apps() {
  GError* system_error = NULL;
  int err = FLATPAK_APPS_ERR_NONE;

  printf("kind: FlatpakAppList\nitems:\n");
  
  GPtrArray* installations = flatpak_get_system_installations(NULL, &system_error);
  for (uint i = 0; i < installations->len; i++) {
    FlatpakInstallation* installation = FLATPAK_INSTALLATION(g_ptr_array_index(installations, i));
    if (installation) {
      int result = enum_apps_for_installation(installation);
      if (result != 0) {
        err = FLATPAK_APPS_ERR_INCOMPLETE;
      }
    }
  }
  g_free(system_error);
  g_ptr_array_free(installations, TRUE);

  GError* user_error = NULL;
  FlatpakInstallation* user = flatpak_installation_new_user(NULL, &user_error);
  if (user) {
    int result = enum_apps_for_installation(user);
    if (result != 0) {
      err = FLATPAK_APPS_ERR_INCOMPLETE;
    }
  }

  g_free(user_error);
  g_object_unref(user);
  return err;
}

int main() {
  return enum_flatpak_apps();
}
