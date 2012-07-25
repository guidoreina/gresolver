#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "resolver.h"

static void usage(const char* program);

int main(int argc, char** argv)
{
	if (argc != 3) {
		usage(argv[0]);
		return -1;
	}

	resolver::rr_type type;
	if (strcasecmp(argv[1], "A") == 0) {
		type = resolver::RR_TYPE_A;
	} else if (strcasecmp(argv[1], "CNAME") == 0) {
		type = resolver::RR_TYPE_CNAME;
	} else if (strcasecmp(argv[1], "PTR") == 0) {
		type = resolver::RR_TYPE_PTR;
	} else if (strcasecmp(argv[1], "MX") == 0) {
		type = resolver::RR_TYPE_MX;
	} else if (strcasecmp(argv[1], "DNAME") == 0) {
		type = resolver::RR_TYPE_DNAME;
	} else {
		usage(argv[0]);
		return -1;
	}

	resolver resolver;
	if (!resolver.resolve(argv[2], type)) {
		fprintf(stderr, "Couldn't resolve.\n");
		return -1;
	}

	return 0;
}

void usage(const char* program)
{
	fprintf(stderr, "Usage: %s <type> <domain>\n", program);
	fprintf(stderr, "<type> ::= \"A\" | \"CNAME\" | \"PTR\" | \"MX\" | \"DNAME\"\n");
}
