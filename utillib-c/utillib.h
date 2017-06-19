#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>

#define NETIF_ERR_NONE     0
#define NETIF_ERR_SOCKOPEN 1
#define NETIF_ERR_IFCONF   2

typedef struct {
  char name[IFNAMSIZ];
  unsigned char macaddr[6];
  unsigned char is_loopback;
} netif_t;

int free_netifs(netif_t** netifs);
int enum_netifs(netif_t** netifs, size_t* num_netifs);
