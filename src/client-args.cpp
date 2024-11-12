// Patrik Uher
// xuherp02

#include <cstdint>
#include <iostream>
#include <getopt.h>
#include <string.h>
#include <stdexcept>
#include "client-args.hpp"

using ca = ClientArgs;

ca::ClientArgs()
{
    ca::hostname = "";
    ca::pcap_file_path = "";
    ca::port = -1;
    ca::active_timeout = 60;
    ca::inactive_timeout = 60;
}

const float VERSION = 0.1;

/** A function that prints out a help menu.
*/
void help_menu()
{
    std::cout << "Usage:" << std::endl;
    std::cout << "./p2nprobe <host>:<port> <pcap_file_path> [-a <active_timeout> -i <inactive_timeout>]" << std::endl;

    std::cout << "\nArguments: " << std::endl;
    std::cout << "\t<host> -> ip address or the domain name of a netflow V5 collector" << std::endl;
    std::cout << "\t<port> -> port of the netflow V5 collector" << std::endl;

    std::cout << "\nFlags:" << std::endl;
    std::cout << "\t[--help] -> Displays this help message and exits" << std::endl;
    std::cout << "\t[--version | -v] -> Displays the version of this program and exits" << std::endl;
    std::cout << "\t[-a | --active <active timeout>] -> number of seconds for the active timeout of the netflow V5 exporter (default 60 seconds)" << std::endl;
    std::cout << "\t[-i | --inactive <inactive timeout>] -> number of seconds for the inactive timeout of the netflow V5 exporter (default 60 seconds)" << std::endl;
}

/** A function that checks if the argument is a valid number.
*/
void ca::check_arg_number(std::string num, const char *arg_name)
{
	for(unsigned int i = 0; i < num.length(); i++)
	{
		if(!isdigit(num[i]))
		{
            std::cout << "Error: " << arg_name <<" parameter expects only positive numbers" << std::endl;
            std::cerr << "see ./p2nprobe --help" << std::endl;
            // TODO rethink exit(1)
			exit(1);
		}
	}
}

/** A function that checks if the argument is in a valid range.
*/
void ca::check_arg_range(int l_bound, int u_bound, int num, const char *arg_name)
{
	if(num < l_bound or num > u_bound)
	{
        std::cout << "Error: argument: " << arg_name << " has to be in range <" << l_bound << ", " << u_bound <<">" << std::endl;
		exit(1);
	}
}

/** A function that checks if the port is valid
*/
void ca::valid_port(std::string port)
{
    if (port == "")
    {
        std::cerr << "Error: Missing port" << std::endl;
        exit(1);
    }

	check_arg_number(port, "port");

	int new_port = stoi(port);

    // TODO get default port
    check_arg_range(128, 65535, new_port, "port");
    
    ca::port = new_port;
}

int32_t ca::valid_timeout(std::string timeout)
{
    long temp_conv;

    try
    {
        temp_conv = stol(timeout);
        std::cout << "trying: " << temp_conv << " < " << INT32_MIN << std::endl;
        std::cout << "trying: " << temp_conv << " > " << INT32_MAX << std::endl;
        if(temp_conv < INT32_MIN or temp_conv > INT32_MAX)
        {
            throw std::out_of_range("Argument out of range of 32 signed bits");
        }
    }
    catch(std::out_of_range& e)
    {
        if(strcmp(e.what(), "stol") == 0)
        {
            std::cout << "Argument out of range of 32 signed bits" << std::endl;
        }
        else
        {
            std::cout << "Error: " << e.what() << std::endl;
        }

        exit(1);
    }

    return static_cast<int32_t>(temp_conv);
}

/** A function that checks the arguments and saves the results into an array
*/
void ca::check_args(int argc, char **argv)
{
    using namespace std;

	const struct option longopts[] =
	{
		{"version", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
        {"active", required_argument, NULL, 'a'},
        {"inactive", required_argument, NULL, 'i'},
		{0,0,0,0} //last element of the array has to be filled with 0s as per man 3 getopts
	};

	int index;
	int opt;
    int argcnt = 0;

	//turn off getopt error message
	opterr=1;

	while((opt = getopt_long(argc, argv, ":vha:i:", longopts, &index)) != -1)
	{
		switch(opt)
		{
            case 'a':
                ca::active_timeout = ca::valid_timeout(optarg);
                argcnt++;
                break;
            case 'i':
                ca::inactive_timeout = ca::valid_timeout(optarg);
                argcnt++;
                break;
			case 'v':
				cout << argv[0] << " " << VERSION << endl;
				exit(0);
            case 'h':
                help_menu();
                exit(0);
			case '?':
				cout << "Error: wrong usage, unknown option" << endl;
				cout << "see ./p2nprobe --help" << endl;
				exit(1);
			case ':':
				cout << "Error: wrong usage, missing parameters" << endl;
				cout << "see ./p2nprobe --help" << endl;
				exit(1);
			case 0:
				// is returned when getopt_long has a variable address
				continue;
			default:
				cout << "Error: wrong usage, unknown option" << endl;
				cout << "see ./p2nprobe --help" << endl;
				exit(1);
		}
	}
    
    // every flag counts as 2 arguments cause both flags have a mandatory argument
    // and 3 because the 2 positional arguments are also mandatory and with the name of the program, thats 3
    if(argc-(argcnt*2) != 3)
    {
        cerr << "Error: wrong amount of arguments" << endl;
        cerr << "see ./p2nprobe --help" << endl;
        exit(1);
    }

    for(int i = 0; i < argc; i++)
    {
        cout << "arg " << i << " : " << argv[i] << endl;
    }
    
    string host_and_port;
    string pcap_file;
        
    // -1 cause of 0 indexing
    // arguments not part of flags are at the end of argv
    if(ca::is_host_and_port(argv[argc-1]))
    {
        host_and_port = argv[argc-1];
        pcap_file = argv[argc-2];
    }
    else
    {
        host_and_port = argv[argc-2];
        pcap_file = argv[argc-1];
    }

    cout << "host & port: " << host_and_port << endl;
    cout << "pcap file: " << pcap_file << endl;

    string delimitor = ":";

    string hostname = host_and_port.substr(0, host_and_port.find(delimitor));
    // +1 to lose the delimitor
    string port = host_and_port.substr(host_and_port.find(delimitor)+1, host_and_port.size());

    ca::pcap_file_path = pcap_file;
    ca::hostname = hostname;
    ca::valid_port(port);
}

bool ca::is_host_and_port(std::string arg)
{
    // looks through the string for the ':' character
    if(arg.find(':') == std::string::npos)
    {
        return false;
    }

    return true;
}

void ca::print_args()
{
    using namespace std;

    cout << "hostname: " << ca::hostname << endl;
    cout << "pcap file path: " << ca::pcap_file_path << endl;
    cout << "port: " << ca::port << endl;
    cout << "active timeout: " << ca::active_timeout << endl;
    cout << "inactive timeout: " << ca::inactive_timeout << endl;

    exit(0);
}
