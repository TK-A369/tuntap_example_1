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

#include <chrono>
#include <functional>
#include <iostream>
#include <map>
#include <string>
#include <thread>
#include <utility>
#include <vector>

int tun_open(const char* devname) {
    struct ifreq ifr;
    int fd, err;

    fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        std::cerr << "Couldn't open /dev/net/tun\n";
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN;
    strncpy(ifr.ifr_name, devname, IFNAMSIZ);

    err = ioctl(fd, TUNSETIFF, (void*)&ifr);
    if (err == -1) {
        std::cerr << "Couldn't create tun/tap device\n";
        close(fd);
        exit(1);
    }

    return fd;
}

struct cmd_flag_entry {
    std::vector<std::string> names;
    uint32_t arg_count;
    std::function<void(uint32_t)> callback;
};

int main(int argc, char** argv) {
    std::string tun_name("tun0");
    std::string usb_name("/dev/ttyUSB0");
    std::string addr_str("10.0.7.1");

    std::vector<cmd_flag_entry> cmd_flags{
        {{"t", "tunname"},
         1,
         [&argv, &tun_name](uint32_t pos) {
             tun_name = argv[pos + 1];
             std::cout << "Setting tun device name: " << tun_name << '\n';
         }},
        {{"u", "usbname"},
         1,
         [&argv, &usb_name](uint32_t pos) {
             usb_name = argv[pos + 1];
             std::cout << "Setting USB device name: " << usb_name << '\n';
         }},
        {{"a", "addr"}, 1, [&argv, &addr_str](uint32_t pos) {
             addr_str = argv[pos + 1];
             std::cout << "Setting address: " << addr_str << '\n';
         }}};
    std::map<char, cmd_flag_entry*> cmd_flags_by_short_name;
    std::map<std::string, cmd_flag_entry*> cmd_flags_by_long_name;
    for (cmd_flag_entry& flag : cmd_flags) {
        for (std::string& name : flag.names) {
            if (name.length() == 1) {
                cmd_flags_by_short_name[name[0]] = &flag;
            } else {
                cmd_flags_by_long_name[name] = &flag;
            }
        }
    }

    for (uint32_t i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            // Flag
            if (argv[i][1] == '-') {
                // Long flag
                if (cmd_flags_by_long_name.count(argv[i] + 2) == 0) {
                    std::cerr << "Unrecognized command line flag: " << argv[i]
                              << '\n';
                    exit(2);
                }
                cmd_flag_entry* flag = cmd_flags_by_long_name[argv[i] + 2];
                flag->callback(i);
                i += flag->arg_count;
            } else {
                // Short flag
                for (uint32_t j = 1; argv[i][j] != '\0'; j++) {
                    if (cmd_flags_by_short_name.count(argv[i][j]) == 0) {
                        std::cerr << "Unrecognized command line flag: -"
                                  << argv[i][j] << '\n';
                        exit(2);
                    }
                    cmd_flag_entry* flag = cmd_flags_by_short_name[argv[i][j]];
                    flag->callback(i);
                    if (flag->arg_count > 0) {
                        i += flag->arg_count;
                        break;
                    }
                }
            }
        }
    }

    int tun_fd;
    int32_t nbytes;
    uint8_t buf[256];

    tun_fd = tun_open(tun_name.c_str());
    std::cout << "Device " << tun_name << " opened\n";

    // Configure tun device
    int socket_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, tun_name.c_str(), IFNAMSIZ);
    // Address
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, addr_str.c_str(), &addr->sin_addr);
    ioctl(socket_fd, SIOCSIFADDR, (void*)&ifr);
    // Netmask
    addr = (struct sockaddr_in*)&ifr.ifr_netmask;
    inet_pton(AF_INET, "255.255.255.0", &addr->sin_addr);
    ioctl(socket_fd, SIOCSIFNETMASK, (void*)&ifr);
    // Flags
    ioctl(socket_fd, SIOCGIFFLAGS, (void*)&ifr);
    strncpy(ifr.ifr_name, tun_name.c_str(), IFNAMSIZ);
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    ioctl(socket_fd, SIOCSIFFLAGS, (void*)&ifr);
    close(socket_fd);

    std::cout << "Configured " << tun_name << "\n";

    int usb_fd = open(usb_name.c_str(), O_RDWR | O_NONBLOCK);

    while (1) {
        nbytes = read(tun_fd, buf, sizeof(buf));
        if (nbytes > 0) {
            write(usb_fd, buf, nbytes);
            std::cout << "Read " << nbytes << " bytes from tun\n";
        }

        nbytes = read(usb_fd, buf, sizeof(buf));
        if (nbytes > 0) {
            write(tun_fd, buf, nbytes);
            std::cout << "Read " << nbytes << " bytes from USB\n";
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    return 0;
}
