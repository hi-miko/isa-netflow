// Patrik Uher
// xuherp02

#ifndef CLIENT_ARGS_HPP
#define CLIENT_ARGS_HPP

#include <string>

class ClientArgs
{
    public:
    std::string hostname;
    std::string pcap_file_path;
	int port;
    int active_timeout;
    int inactive_timeout;
    
    public:
    ClientArgs();
    void print_args();
    void check_args(int, char **);
    
    private:
    void check_arg_number(std::string, const char *);
    void check_arg_range(int, int, int, const char *);
    void valid_port(std::string);
};

#define NO_DEFAULT_NUM -1

#endif // CLIENT_ARGS_HPP
