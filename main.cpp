#define termio asmtermio
#define termios asmtermios
#define winsize asmwinsize
#include <asm/termios.h>
#undef winsize
#undef termios
#undef termio

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <chrono>
#include <functional>
#include <iomanip>
#include <ios>
#include <iostream>
#include <map>
#include <string>
#include <thread>
#include <vector>

int tun_open(const char* devname) {
    struct ifreq ifr;
    int fd, err;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        std::cerr << "Couldn't open /dev/net/tun\n";
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
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
    std::string tun_name("tun2uart");
    std::string usb_name("/dev/ttyUSB0");
    std::string addr_str("10.0.7.1");
    uint32_t baud_rate = 9600;

    std::vector<cmd_flag_entry> cmd_flags{
        {{"t", "tunname"},
         1,
         [&argv, &tun_name](uint32_t pos) { tun_name = argv[pos + 1]; }},
        {{"u", "usbname"},
         1,
         [&argv, &usb_name](uint32_t pos) { usb_name = argv[pos + 1]; }},
        {{"a", "addr"},
         1,
         [&argv, &addr_str](uint32_t pos) { addr_str = argv[pos + 1]; }},
        {{"b", "baud"}, 1, [&argv, &baud_rate](uint32_t pos) {
             baud_rate = std::stoi(argv[pos + 1]);
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

    std::cout << "tun device name: " << tun_name << '\n';
    std::cout << "USB device name: " << usb_name << '\n';
    std::cout << "Address: " << addr_str << '\n';
    std::cout << "Baud rate: " << baud_rate << '\n';

    int tun_fd;
    int32_t nbytes;
    uint8_t buf[3000];

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

    int usb_fd = open(usb_name.c_str(), O_RDWR);
    struct termios2 tio;
    ioctl(usb_fd, TCGETS2, &tio);
    //    memset(&tio, 0, sizeof(tio));
    tio.c_cflag &= ~(CBAUD        // To use any baud
                     | PARENB     // No parity
                     | CSTOPB     // One stop bit
                     | CRTSCTS);  // Disable RTS/CTS hardware flow control
    tio.c_cflag |= BOTHER         // To use any baud
                   | CS8          // 8 data bits
                   | CREAD        // So we can read
                   | CLOCAL;      // Disable mode-specific signal lines
    tio.c_lflag &= ~(ICANON       // Disable canonical mode (line-by-line)
                     | ECHO       // Disable echo
                     | ECHOE      // Disable erasure
                     | ECHONL     // Disable new-line echo
                     | ISIG);  // Don't interpret certain characters as special
    tio.c_iflag &= ~(IXON | IXOFF | IXANY  // Disable s/w flow control
                     | IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR |
                     ICRNL);  // Disable handling certain characters as special
    tio.c_oflag &= ~(
        OPOST |
        ONLCR);  // Don't interpret certain characters (e.g. newline) as special
    tio.c_ispeed = baud_rate;
    tio.c_ospeed = baud_rate;
    if (ioctl(usb_fd, TCSETS2, &tio) != 0) {
        std::cerr << "Couldn't configure USB\n";
        exit(3);
    }

    struct pollfd pollfds[] = {{.fd = tun_fd, .events = POLLIN, .revents = 0},
                               {.fd = usb_fd, .events = POLLIN, .revents = 0}};

    int32_t usb_data_expected_count = 0;
    uint32_t usb_data_received_count = 0;
    uint8_t usb_buf[3000];

    while (1) {
        poll(pollfds, sizeof(pollfds) / sizeof(*pollfds), 1000);

        if (pollfds[0].revents & POLLIN) {
            // Received data from tun
            nbytes = read(tun_fd, buf, sizeof(buf));

            std::cout << std::hex;
            for (uint32_t i = 0; i < nbytes; i++) {
                std::cout << (uint16_t)buf[i] << ' ';
            }
            std::cout << std::dec << '\n';

            uint8_t tmp_buf[6] = {'A',
                                  'T',
                                  (uint8_t)((nbytes >> 24) & 0xFF),
                                  (uint8_t)((nbytes >> 16) & 0xFF),
                                  (uint8_t)((nbytes >> 8) & 0xFF),
                                  (uint8_t)(nbytes & 0xFF)};
            write(usb_fd, tmp_buf, 6);
            write(usb_fd, buf, nbytes);
            uint8_t checksum = 0;
            for (uint32_t i = 0; i < nbytes; i++) {
                checksum ^= buf[i];
            }
            write(usb_fd, &checksum, 1);
            std::cout << "Read " << nbytes << " bytes from tun\n";
            pollfds[0].revents = 0;
        }

        if (pollfds[1].revents & POLLIN) {
            // Received data from USB
            nbytes = read(usb_fd, buf, sizeof(buf));
            std::cout << std::hex;
            for (uint32_t i = 0; i < nbytes; i++) {
                std::cout << (uint16_t)buf[i] << ' ';

                bool should_reset = false;
                if (usb_data_received_count == 0) {
                    if (buf[i] != 'A') {
                        should_reset = true;
                    }
                } else if (usb_data_received_count == 1) {
                    if (buf[i] != 'T') {
                        should_reset = true;
                    }
                } else if (usb_data_received_count < 6) {
                    usb_data_expected_count |=
                        buf[i] << ((5 - usb_data_received_count) * 8);

                    if (usb_data_received_count == 5) {
                        std::cout << '\n'
                                  << std::dec << usb_data_expected_count
                                  << std::hex << " bytes should be received\n";
                    }
                } else if (usb_data_received_count - 6 <
                           usb_data_expected_count) {
                    usb_buf[usb_data_received_count - 6] = buf[i];
                } else {
                    uint8_t received_checksum = buf[i];
                    uint8_t calculated_checksum = 0;
                    for (uint32_t j = 0; j < usb_data_expected_count; j++) {
                        calculated_checksum ^= usb_buf[j];
                    }

                    if (received_checksum == calculated_checksum) {
                        write(tun_fd, usb_buf, usb_data_expected_count);
                        std::cout << "Read " << std::dec
                                  << usb_data_received_count << std::hex
                                  << " bytes from USB\n";
                        should_reset = true;
                    } else {
                        std::cout << "Checksum error\n";
                        should_reset = true;
                    }
                }
                if (should_reset) {
                    std::cout << "Resetting USB frame parsing\n";
                    usb_data_received_count = 0;
                    usb_data_expected_count = 0;
                } else {
                    usb_data_received_count++;
                }
            }
            std::cout << std::dec << '\n';
            pollfds[1].revents = 0;
        }

        // std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    return 0;
}
