#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <flatpak.h>

#include "utillib.h"

void fill_netif_data(int sock, struct ifreq* ifr, netif_t* netif) {
  memcpy(netif->name, ifr->ifr_name, IFNAMSIZ);

  if (ioctl(sock, SIOCGIFFLAGS, ifr) == 0) {
    if (ifr->ifr_flags & IFF_LOOPBACK) {
      netif->is_loopback = 1;
    } else {
      netif->is_loopback = 0;
    }
  } else {
    // Assume non-loopback if the ioctl fails.
    netif->is_loopback = 0;
  }
  if (netif->is_loopback) {
    memset(netif->macaddr, 0, 6);
  } else {
    if (ioctl(sock, SIOCGIFHWADDR, ifr) == 0) {
      memcpy(netif->macaddr, ifr->ifr_hwaddr.sa_data, 6);
    } else {
      // All 0xff if we failed to get the MAC address
      memset(netif->macaddr, 0xff, 6);
    }
  }
}

int free_netifs(netif_t** netifs) {
  if (*netifs == NULL) {
    return 0;
  }

  free(*netifs);
  *netifs = NULL;
  return 0;
}

int enum_netifs(netif_t** netifs, size_t* num_netifs) {
  struct ifreq ifr;
  struct ifconf ifc;

  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sock == -1) {
    return NETIF_ERR_SOCKOPEN;
  }

  ifc.ifc_len = 0;
  ifc.ifc_buf = NULL;
  int sizeget_result = ioctl(sock, SIOCGIFCONF, &ifc);
  if (sizeget_result == -1) {
    return NETIF_ERR_IFCONF;
  }
  ifc.ifc_buf = malloc(ifc.ifc_len);

  if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
    free(ifc.ifc_buf);
    ifc.ifc_buf = NULL;
    return NETIF_ERR_IFCONF;
  }

  struct ifreq* it = ifc.ifc_req;
  const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));
  *netifs = malloc(sizeof(netif_t) * (ifc.ifc_len / sizeof(struct ifreq)));
  netif_t* netifs_it = *netifs;
  *num_netifs = (ifc.ifc_len / sizeof(struct ifreq));

  for (; it != end; ++it) {
    strcpy(ifr.ifr_name, it->ifr_name);
    fill_netif_data(sock, &ifr, netifs_it);
    // This is probably a bad idea.
    ++netifs_it;
  }

  free(ifc.ifc_buf);
  ifc.ifc_buf = NULL;
  return NETIF_ERR_NONE;
}

struct flatpak_app {
  char* origin;
  char* latest_commit;
  char* commit;
  struct flatpak_app* next;
};

const char* flatpak_app_get_origin(const flatpak_app_t* app) {
  return app->origin;
}

const char* flatpak_app_get_latest_commit(const flatpak_app_t* app) {
  return app->latest_commit;
}

const char* flatpak_app_get_commit(const flatpak_app_t* app) {
  return app->commit;
}


struct flatpak_app_list{
  flatpak_app_t* apps;
  flatpak_app_t* curr;
  size_t num_apps;
};

int enum_apps_for_installation(FlatpakInstallation *flatpakInstallation, flatpak_app_list_t* apps) {
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

    if (apps->apps == NULL) {
      apps->apps = malloc(sizeof(flatpak_app_t));
      apps->curr = apps->apps;
    } else {
      apps->curr->next = malloc(sizeof(flatpak_app_t));
      apps->curr = apps->curr->next;
    }
    memset(apps->curr, 0, sizeof(flatpak_app_t));

    apps->curr->origin = g_strdup(origin);
    apps->curr->latest_commit = g_strdup(latest_commit);
    apps->curr->commit = g_strdup(commit);
    apps->curr->next = NULL;
    apps->num_apps++;
  }

  g_free(installation_error);
  g_ptr_array_free(refs, TRUE);
  return err;
}

int enum_flatpak_apps(flatpak_app_list_t** apps) {
  GError* system_error = NULL;
  *apps = malloc(sizeof(flatpak_app_list_t));
  memset(*apps, 0, sizeof(flatpak_app_list_t));
  int err = FLATPAK_APPS_ERR_NONE;
  
  GPtrArray* installations = flatpak_get_system_installations(NULL, &system_error);
  for (uint i = 0; i < installations->len; i++) {
    FlatpakInstallation* installation = FLATPAK_INSTALLATION(g_ptr_array_index(installations, i));
    if (installation) {
      int result = enum_apps_for_installation(installation, *apps);
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
    int result = enum_apps_for_installation(user, *apps);
    if (result != 0) {
      err = FLATPAK_APPS_ERR_INCOMPLETE;
    }
  }

  g_free(user_error);
  g_object_unref(user);
  (*apps)->curr = (*apps)->apps;
  return err;
}

flatpak_app_t* flatpak_apps_list_iter_start(flatpak_app_list_t* apps) {
  apps->curr = apps->apps;
  return apps->curr;
}
flatpak_app_t* flatpak_apps_list_iter_next(flatpak_app_list_t* apps) {
  apps->curr = apps->curr->next;
  return apps->curr;
}

int flatpak_app_free(flatpak_app_t* app) {
  g_free(app->origin);
  g_free(app->latest_commit);
  g_free(app->commit);
  app->next = NULL;
  free(app);

  return 1;
}

int free_flatpak_apps(flatpak_app_list_t* apps) {
  flatpak_app_t* app = flatpak_apps_list_iter_start(apps);
  do {
    flatpak_app_t* target = app;
    app = flatpak_apps_list_iter_next(apps);
    flatpak_app_free(target);
  } while (app != NULL);

  free(apps);
  
  return 1;
}
