#include <arpa/inet.h>
#include <fcntl.h>
// #include <linux/if.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

int tun_open(const char* devname) {
    struct ifreq ifr;
    int fd, err;

    fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        perror("Couldn't open /dev/net/tun");
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN;
    strncpy(ifr.ifr_name, devname, IFNAMSIZ);

    err = ioctl(fd, TUNSETIFF, (void*)&ifr);
    if (err == -1) {
        perror("Couldn't create tun/tap device");
        close(fd);
        exit(1);
    }

    return fd;
}

int main(int argc, char** argv) {
    int fd;
    int32_t nbytes;
    uint8_t buf[256];

    const char* dev_name = "tun0";
    fd = tun_open(dev_name);
    printf("Device tun0 opened\n");

    // Configure tun device
    int socket_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);
    // Address
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, "10.0.7.1", &addr->sin_addr);
    ioctl(socket_fd, SIOCSIFADDR, (void*)&ifr);
    // Netmask
    addr = (struct sockaddr_in*)&ifr.ifr_netmask;
    inet_pton(AF_INET, "255.255.255.0", &addr->sin_addr);
    ioctl(socket_fd, SIOCSIFNETMASK, (void*)&ifr);
    // Flags
    ioctl(socket_fd, SIOCGIFFLAGS, (void*)&ifr);
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    ioctl(socket_fd, SIOCSIFFLAGS, (void*)&ifr);
    close(socket_fd);

    printf("Configured tun0\n");

    while (1) {
        nbytes = read(fd, buf, sizeof(buf));
        if (nbytes > 0) {
            printf("Read %d bytes\n", nbytes);
        }
    }

    return 0;
}
