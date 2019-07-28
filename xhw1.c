#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include "arg_struct.h"
#include <openssl/md5.h>
#include <openssl/hmac.h>
#define MD5_LENGTH 16

#ifndef __NR_cpenc
#error cpenc system call not defined
#endif


int main(int argc, char *argv[])
{
	int rc=0;
	unsigned char *hash = NULL;
	INPUT_ARGUMENTS args;
	args.flag = 0;
	args.infile = NULL;
	args.outfile = NULL;
	args.infile_length = 0;
	args.outfile_length = 0;
	args.keybuf = NULL;
	args.keylen = 0;
	int arg_in_out_flag = 1;
	int option;
	
	
	hash = (unsigned char *)malloc(sizeof(char) * 16);
	if(hash == NULL)
	{
		printf("Unable to allocate memory for hash\n");
		goto end;
	}
	while ((option = getopt (argc, argv, "dcC:p:he")) != -1)
	{
		switch (option)
		{
			case 'e':
				args.flag |= 1;
				break;
			case 'd':
				args.flag |= 2;
				break;
			case 'c':
				args.flag |= 4;
				break;
			case 'C':
				break;
			case 'p':
				args.keybuf = optarg;
				if(strlen(args.keybuf) < 6)
				{
					printf("The keybuf/password should be more than 6 characters\n");
        //                              exit(0);  
       					goto end;
				}
				MD5((const unsigned char *)args.keybuf, strlen(args.keybuf), hash);
				args.keylen = MD5_LENGTH;
				args.keybuf = (char *)hash;
				break;
			case 'h':
				printf("Help message\n");
				printf("The system call performs the following tasks and arguments are as follows: \n");
				printf("1. For copy : ./xcpenc inputfile outputfile\n");
				printf("2. For encryption : ./xcpenc -p password -e inputfile outputfile\n");
				printf("3. For decryption : ./xcpenc -p password -d inputfile outputfile\n");
				goto end;
		}
	}
        if(args.flag == 4 && args.keylen > 0)	
	{
		printf("Password and copy cannot be given together\n");
		goto end;
	}
	for(; optind < argc; optind++){ 
		printf("Hello world %s\n", argv[optind]);
		if(arg_in_out_flag)
		{	
			arg_in_out_flag = 0;
			args.infile = argv[optind];
                        args.infile_length = strlen(args.infile);
		}
		else
		{	
			args.outfile = argv[optind];
    	                args.outfile_length = strlen(args.outfile);
		}
    	}
/*	for (index = optind; index < argc; index++)
	{
		
		if(index == argc - 2)
		{
			args.infile = argv[index];
			args.infile_length = strlen(args.infile);
		}
		if(index == argc - 1)
		{
			args.outfile = argv[index];
			args.outfile_length = strlen(args.outfile);
		}		

	}*/
//	printf("The value of hash is : %s\n", hash);
	if (args.flag == 0|| args.infile_length == 0 || args.outfile_length == 0)
	{
		printf("(Encrpyt, Decrypt, Copy Flag), Infile, Outfile are mandatory arguments");
	//	exit(0);
		goto end;
	}
	if(!(args.flag == 1 || args.flag == 2 || args.flag == 4))
	{
		printf("Encryption -e, Decryption -d, Copy -c independently possible");
		goto end;
		
	}
	if(args.flag == 4 && args.keylen != 0)
	{
		printf("The copy operation doesn't require password");
		goto end;	
	}
	void *dummy = (void *) (&args);
	rc = syscall(__NR_cpenc, dummy);
	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);
end:
	if(hash)
	{
		free(hash);
	}
	exit(rc);
}
