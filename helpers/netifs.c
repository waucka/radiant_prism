#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define NETIF_ERR_NONE     0
#define NETIF_ERR_SOCKOPEN 1
#define NETIF_ERR_IFCONF   2

/*
YAML FORMAT
kind: NetworkInterfaceList
items:
  - name: "lo"
    loopback: True
    mac: ""
  - name: "eth0"
    loopback: False
    mac: "12:34:56:78:90:ab"
...
 */


void write_netif_data(int sock, struct ifreq* ifr) {
  printf("  - name: \"%s\"\n", ifr->ifr_name);

  int is_loopback = 0;
  if (ioctl(sock, SIOCGIFFLAGS, ifr) == 0) {
    if (ifr->ifr_flags & IFF_LOOPBACK) {
      printf("    loopback: True\n");
      is_loopback = 1;
    } else {
      printf("    loopback: False\n");
      is_loopback = 0;
    }
  } else {
    // Assume non-loopback if the ioctl fails.
    printf("    loopback: False\n");
      is_loopback = 0;
  }
  if (is_loopback) {
    printf("    mac: \"\"\n");
  } else {
    if (ioctl(sock, SIOCGIFHWADDR, ifr) == 0) {
      printf("    mac: \"%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx\"\n",
	     ifr->ifr_hwaddr.sa_data[0],
	     ifr->ifr_hwaddr.sa_data[1],
	     ifr->ifr_hwaddr.sa_data[2],
	     ifr->ifr_hwaddr.sa_data[3],
	     ifr->ifr_hwaddr.sa_data[4],
	     ifr->ifr_hwaddr.sa_data[5]);
    } else {
      // All 0xff if we failed to get the MAC address
      printf("    mac: \"00:00:00:00:00:00\"\n");
    }
  }
}

int enum_netifs() {
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

  printf("kind: NetworkInterfaceList\nitems:\n");
  for (; it != end; ++it) {
    strcpy(ifr.ifr_name, it->ifr_name);
    write_netif_data(sock, &ifr);
  }

  free(ifc.ifc_buf);
  ifc.ifc_buf = NULL;
  return NETIF_ERR_NONE;
}

int main() {
  return enum_netifs();
}
