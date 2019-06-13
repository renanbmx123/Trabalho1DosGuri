///// https://www.onlinegdb.com/online_c_compiler (To test online)
//https://github.com/rbaron/raw_tcp_socket/blob/master/raw_tcp_socket.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h> // *POSIX* Para o getopt() original
#include <ctype.h>
#include "../headers/functions.h"

#define TCP_CONNECT "TCP Connect"
#define TCP_HALF_OPENING "TCP Half-Opening"
#define STEALTH_SCAN "Stealth Scan or TCP FIN"
#define SYN_ACK "SYN/ACK"

#define SIZE 2000

int main(int argc, char **argv)
{
    int opt;

    /*  Variables to store options arguments. */
    char *interface = NULL, *start_port = NULL, *end_port = NULL, *attack = NULL, *attempts = NULL, *source = NULL, *dest = NULL;
    int int_start_port, int_end_port, int_attempts;
    int retAlp = 1;
    int retDig = 1;
    /* Call Help from program. */
    if (argc < 2)
        show_help(argv[0]);

    /* getopt() Returns the character of an option at each 
	* i	teration and -1 to mark the end of the process. */
    while ((opt = getopt(argc, argv, "hi:f:a:t:s:d:n:")) > 0)
    {
        switch (opt)
        {
        case 'h': /* help */
            show_help(argv[0]);
            break;
        case 'i': /* opção -i initial_port*/
            retAlp = check_alphabets(optarg, "Invalid port");
            if (retAlp < 0)
                return retAlp;
            start_port = optarg;
            int_start_port = atoi(start_port);
            break;
        case 'f': /* opção -e final_port*/
            retAlp = check_alphabets(optarg, "Invalid port");
            if (retAlp < 0)
                return retAlp;
            end_port = optarg;
            int_end_port = atoi(end_port);
            break;
        case 'a': /* opção -a attack*/
            retDig = check_digits(optarg, "Invalid attack");
            if (retDig < 0)
                return retDig;
            convert_lower(optarg);
            if (strcmp(optarg, "connect") == 0)
            {
                attack = TCP_CONNECT;
            }
            else if (strcmp(optarg, "half") == 0)
            {
                attack = TCP_HALF_OPENING;
            }
            else if (strcmp(optarg, "stealth") == 0)
            {
                attack = STEALTH_SCAN;
            }
            else if (strcmp(optarg, "syn_ack") == 0)
            {
                attack = SYN_ACK;
            }
            else
            {
                fprintf(stderr, "\nInvalid attack: %s\n\n", optarg);
                return -1;
            }
            break;
        case 't': /* opção -t attempts*/
            retAlp = check_alphabets(optarg, "Invalid number of attepts");
            if (retAlp < 0)
                return retAlp;
            attempts = optarg;
            int_attempts = atoi(attempts);
            break;
        case 's': /* opção -s IPv6 source*/
            source = optarg;
            break;
        case 'd': /* opção -d IPv6 destination*/
            dest = optarg;
            break;
        case 'n': /* opção -n Interface*/
            convert_lower(optarg);
            interface = optarg;
            break;
        default:
            //fprintf(stderr, "Invalid dsdsd: `%c'\n", optopt) ;
            return -1;
        }
    }

    /* Mostra os argumentos em excesso */
    if (argv[optind] != NULL)
    {
        int i;

        puts("** Excess of arguments **");
        for (i = optind; argv[i] != NULL; i++)
        {
            fprintf(stderr, "-- %s\n", argv[i]);
        }
        return -1;
    }

    /* Mostra os dados na tela. */
    printf("\tInformations: \n\
            Interface \t: %s\n\
            Port Range \t: %s, %s\n\
            Attack  \t: %s\n\
            Attempts \t: %s\n\
            Source \t: %s\n\
            Destination : %s\n\n\n",
           interface, start_port, end_port, attack, attempts, source, dest);

    for (int i = int_start_port; i <= int_end_port; i++)
    {
        for (int j = 0; j < int_attempts; j++)
        {
            if (strcmp(attack, TCP_CONNECT) == 0)
            {
                char *tmp = "./bin/tcp_connect ";
                char command[SIZE];
                strcpy(command, tmp);
                char port[5];
                sprintf(port, "%d", i);

                strcat(command, port);
                strcat(command, " ");
                strcat(command, interface);
                strcat(command, " ");
                strcat(command, source);
                strcat(command, " ");
                strcat(command, dest);
                int status = system(command);
            }
            else if (strcmp(attack, TCP_HALF_OPENING) == 0)
            {
                char *tmp = "./bin/tcp_half_opening ";
                char command[SIZE];
                strcpy(command, tmp);
                char port[5];
                sprintf(port, "%d", i);

                strcat(command, port);
                strcat(command, " ");
                strcat(command, interface);
                strcat(command, " ");
                strcat(command, source);
                strcat(command, " ");
                strcat(command, dest);
                int status = system(command);
            }
            else if (strcmp(attack, STEALTH_SCAN) == 0)
            {
                char *tmp = "./bin/stealth_scan_fin ";
                char command[SIZE];
                strcpy(command, tmp);
                char port[5];

                sprintf(port, "%d", i);

                strcat(command, port);
                strcat(command, " ");
                strcat(command, interface);
                strcat(command, " ");
                strcat(command, source);
                strcat(command, " ");
                strcat(command, dest);
                int status = system(command);
            }
            else
            {
                char *tmp = "./bin/syn_ack ";
                char command[SIZE];
                strcpy(command, tmp);
                char port[5];

                sprintf(port, "%d", i);

                strcat(command, port);
                strcat(command, " ");
                strcat(command, interface);
                strcat(command, " ");
                strcat(command, source);
                strcat(command, " ");
                strcat(command, dest);
                int status = system(command);
            }
        }
    }

    return 0;
}
/* EOF */
