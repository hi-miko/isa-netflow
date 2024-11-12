// Patrik Uher
// xuherp02

#ifndef CLIENT_ARGS_HPP
#define CLIENT_ARGS_HPP

#include <string>
#include <cstdint>

class ClientArgs
{
    public:
    std::string hostname;
    std::string pcap_file_path;
	int port;
    uint32_t active_timeout;
    uint32_t inactive_timeout;
    
    public:
    ClientArgs();
    void print_args();
    void check_args(int, char **);
    
    private:
    void check_arg_number(std::string, const char *);
    void check_arg_range(int, int, int, const char *);
    void valid_port(std::string);
    int32_t valid_timeout(std::string);
    bool is_host_and_port(std::string);
};

#define NO_DEFAULT_NUM -1

#endif // CLIENT_ARGS_HPP
