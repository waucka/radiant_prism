#ifndef UTILLIB_H
#define UTILLIB_H

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>

#define NETIF_ERR_NONE     0
#define NETIF_ERR_SOCKOPEN 1
#define NETIF_ERR_IFCONF   2

#define FLATPAK_APPS_ERR_NONE       0
#define FLATPAK_APPS_ERR_INCOMPLETE 1

typedef struct {
  char name[IFNAMSIZ];
  unsigned char macaddr[6];
  unsigned char is_loopback;
} netif_t;

int free_netifs(netif_t** netifs);
int enum_netifs(netif_t** netifs, size_t* num_netifs);


typedef struct flatpak_app flatpak_app_t;
typedef struct flatpak_app_list flatpak_app_list_t;

const char* flatpak_app_get_origin(const flatpak_app_t* app);
const char* flatpak_app_get_latest_commit(const flatpak_app_t* app);
const char* flatpak_app_get_commit(const flatpak_app_t* app);

int enum_flatpak_apps(flatpak_app_list_t** apps);
flatpak_app_t* flatpak_apps_list_iter_start(flatpak_app_list_t* apps);
flatpak_app_t* flatpak_apps_list_iter_next(flatpak_app_list_t* apps);
int free_flatpak_apps(flatpak_app_list_t* apps);

#endif
