/* xdag main, T13.654-T13.895 $DVS:time$ */

#include "init.h"
int main(int argc, char **argv)
{
	fprintf(stdout, "->into xdag\n");

	xdag_init(argc, argv, 0);
	return 0;
}
