/*
 * TODO parse command line arguments and call proper
 * VSD_IOCTL_* using C function ioctl (see man ioctl).
 */

#include <linux/kernel.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <vsd_ioctl.h>


const char* VSD_FILENAME = "/dev/vsd";

void print_help(std::string msg = "") 
{
	std::cout << msg << std::endl;
	std::cout << "USAGE: vsd_userspace COMMAND [SIZE]" << std::endl;
	std::cout << "	     - COMMAND can be size_get OR size_set" << std::endl;
	std::cout << "       - SIZE (integer) must be specified if size_set command used." << std::endl;
}

enum operation {
	GET_SIZE,
	SET_SIZE,
	NO_OPERATION
};

struct cmd_options {
	operation op;
	int size;
};

std::string parse_args(int argc, char** argv, cmd_options& opts) 
{
	opts.op = NO_OPERATION;

	if (argc < 2) {
		return "ERROR: not enough arguments.";
	}
	std::string command = argv[1];
	if (argc == 2 && command == "size_get") {
		opts.op = GET_SIZE;

	} else if (argc == 3 && command == "size_set") {
		try {
			opts.size = std::stoi(argv[2]);
		} catch (...) {
			return "ERROR: SIZE must be integer.";
		}
		opts.op = SET_SIZE;

	} else {
		return "ERROR: bad arguments.";
	}

	return "";
}

int get_size(int fd) 
{
	vsd_ioctl_get_size_arg_t arg;
	int res = ioctl(fd, VSD_IOCTL_GET_SIZE, &arg);
	if (res < 0) {
		std::cout << "Error occured during size_get, code = " << res << std::endl;
		return res;
	}
	std::cout << arg.size << std::endl;
	return EXIT_SUCCESS;
}

int set_size(int fd, int size) 
{
	vsd_ioctl_set_size_arg_t arg;
	arg.size = size;
	int res = ioctl(fd, VSD_IOCTL_SET_SIZE, &arg);
	if (res < 0) {
		std::cout << "Error occured during size_set, code = " << res << std::endl;
		return res;
	}
	std::cout << arg.size << std::endl;
	return EXIT_SUCCESS;
}

int main(int argc, char **argv) 
{
	cmd_options opts;
	std::string err = parse_args(argc, argv, opts);
	if (!err.empty() || opts.op == NO_OPERATION) {
		print_help(err);
		return EXIT_FAILURE;
	}

	int fd = open(VSD_FILENAME, O_RDWR);
	if (fd < 0) {
		std::cout << "Can't open device file: [ " << VSD_FILENAME << " ]" << std::endl;
		return EXIT_FAILURE;
	}


	int res = EXIT_SUCCESS;
	switch (opts.op) {
		case SET_SIZE:
			res = set_size(fd, opts.size);
			break;
		case GET_SIZE:
			res = get_size(fd);
			break;
		default:
			break;
	}

	res = -res;
	switch(res) {
        case EFAULT:
            std::cout << "ERROR: efault" << std::endl;
            break;
        case ENOMEM:
        	std::cout << "ERROR: enomem" << std::endl;
        default:
            break;
	}

	return res;
}
