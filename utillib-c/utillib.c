#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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
