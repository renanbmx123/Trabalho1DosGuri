#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // *POSIX* Para o getopt() original
#include <ctype.h>

/* Show Help from Program */
void show_help(char *name)
{
	fprintf(stderr, "\n\
            [usage] %s <options>\n\n\
            -h                                      Show this help.\n\
            -i initial_port                         Initial port range.\n\
            -f final_port                           Final port range. \n\
            -a connect | half | stealth | syn_ack   Type of attack \n\
                TCP (connect) \n\
                TCP (half)-opening \n\
                (stealth) scan or TCP FIN \n\
                (syn_ack) SYN/ACK \n\
            -t attempts                             Number of attempts.\n\n\
  	    -s IPv6 source                          Source.\n\
	    -d IPv6 destination                     Destination.\n\
	    -n network_interface                    Network Interface.\n\n",
			name);
	exit(-1);
}

/* Check for letters in the input */
int check_alphabets(char *input, char *message)
{
	for (int i = 0; input[i] != '\0'; i++)
	{
		// check for alphabets
		if (isalpha(input[i]) != 0)
		{
			fprintf(stderr, "\n%s: %s\n\n", message, input);
			return -1;
		}
	}
	return 0;
}

/* Check for digits in the input */
int check_digits(char *input, char *message)
{
	for (int i = 0; input[i] != '\0'; i++)
	{
		// check for digits
		if (isdigit(input[i]) != 0)
		{
			fprintf(stderr, "\n%s: %s\n\n", message, input);
			return -1;
		}
	}
	return 0;
}

/* Convert input string to lower */
void convert_lower(char *input)
{
	for (int i = 0; input[i]; i++)
	{
		input[i] = tolower(input[i]);
	}
}
