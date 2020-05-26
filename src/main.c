#include "aes.h"
#include "cmac.h"
#include "encrypt.h"
#include "utils.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define ACCENTCOLOR "\033[1;36m"
#define DEFAULT "\033[0m"

void perform(char* argv[]);
void run(char* argv[]);

const int INPUT_BYTES_LIMIT = 1024;
const char *helpMessage = R"(aes-cmac - calculator for aes-cmac-128. Get 16 bytes of result for some binary data and 16-bytes of KEY.
usage: aes-cmac <filepath-to-data-file> <KEY>
example: aes-cmac my-data.hex 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f

Run without any arguments to run tests.
--help - help message will be printed instead of running. No matter of other arguments.

file with data must contain HEX-presentation of binary data. KEY must be a HEX-presentation of key.
All non-hex symbols will be ignored. If hex-symbols count is odd then last hex-symbol will be ignored (because of two hex-symbols presents a single byte).
Non ASCII-symbols in arguments is not supported.
)";

static int putSymbol__state = 0;
static char putSymbol__dataCharCand;
int putSymbol(char ch, unsigned char *data, int *dataLength, int dataLengthLimit)
{
	unsigned char cand;
	if (ch >= '0' && ch <= '9')
	{
		cand = ch - '0';
	}
	else if (ch >= 'a' && ch <= 'f')
	{
		cand = ch - 'a' + 10;
	}
	else if (ch >= 'A' && ch <= 'F')
	{
		cand = ch - 'A' + 10;
	}
	else{
		return 0;
	}
	if (putSymbol__state == 0)
	{
		putSymbol__dataCharCand = cand;
		putSymbol__state = 1;
	}
	else
	{
		if (*dataLength == dataLengthLimit)
			return 1;
		cand |= putSymbol__dataCharCand << 4;
		data[(*dataLength)++] = cand;
		putSymbol__state = 0;
	}
	return 0;
}

int main(int argc, char* argv[])
{
    /*if (argc == 1) {
        printf("\033[1;35m");
        printf("TEST CASES\n");
        printf("\033[0m");
        test();
        printf("\n");
        run(argv);
    } else if (argc == 3) {
        perform(argv);
    } else {
        printf("Usage: %s MESSAGE KEY\n", argv[0]);
    }*/

	unsigned char data[INPUT_BYTES_LIMIT];
	int dataLength = 0;
	
	unsigned char key[16];

	int state = 0;
	int counter = 0;
	/* States:
		0 - tests (no arguments passed)
		1 - data-file (HEX) presented, reading key
	*/
	for (int iArg = 1 ; iArg < argc ; ++iArg)
	{
		char *arg = argv[iArg];
		if (!strcmp(arg, "--help"))
		{
			puts(helpMessage);
			return 0;
		}
		if (state == 0)
		{
			int file = open(arg, O_RDONLY);
			if (file < 0)
			{
				puts("can not open file with data");
				return 1;
			}
			putSymbol__state = 0;
			const int BUFFER_SIZE = 128;
			char buffer[BUFFER_SIZE];
			int chunkSize;
			do
			{
				chunkSize = read(file, buffer, BUFFER_SIZE);
				if (chunkSize < 0)
				{
					puts("can not read file...");
					return 1;
				}
				for (int i = 0 ; i < chunkSize ; ++i)
				{
					char ch = buffer[i];
					if (ch < 0){
						puts("data: non-ASCII symbols not supported");
						return 1;
					}
					if (putSymbol(ch, data, &dataLength, INPUT_BYTES_LIMIT))
					{
						puts("too many data");
						return 1;
					}
				}
			}
			while (chunkSize == BUFFER_SIZE);
			state = 1;
		}
		else if (state == 1)
		{
			putSymbol__state = 0;
			for (int i = 0, c = strlen(arg) ; i < c ; ++i)
			{
				char ch = arg[i];
				if (ch < 0){
					puts("key: non-ASCII symbols not supported");
					return 1;
				}
				if (putSymbol(ch, key, &counter, 16))
				{
					puts("too many bytes taken for key: 16 only expected.");
					return 1;
				}
			}
		}
	}
	if (state == 0)
	{
		// test
		printf("\033[1;35m");
		printf("TEST CASES\n");
		printf("\033[0m");
		test();
		printf("\n");
		run(argv);
	}
	else if (state == 1)
	{
		// calculate aes-cmac for pointed data
		if (counter < 16)
		{
			puts("too little bytes taken for key: 16 expected.");
			return 1;
		}
		printf("%sKey%s\n", ACCENTCOLOR, DEFAULT);
		print_bytes(key, 16);
		printf("%sData%s\n", ACCENTCOLOR, DEFAULT);
		print_bytes(data, dataLength);

		unsigned char out[16];
		aes_cmac(data, dataLength, out, key);
		printf("%sAES-128-CMAC Result%s\n", ACCENTCOLOR, DEFAULT);
		print_bytes(out, 16);

		//=======================
		unsigned int n = 0;
		unsigned char* C;

		C = ecb_encrypt((unsigned char*)argv[1], (unsigned char*)argv[2], aes_128_encrypt, &n);
		printf("%sAES-128-ECB Encrypt Result%s\n", ACCENTCOLOR, DEFAULT);
		for (auto i = 0; i < n; i++) {
			print_bytes(C + i * 16, 16);
		}

		C = ecb_decrypt(C, (unsigned char*)argv[2], aes_128_decrypt, &n);
		printf("%sAES-128-ECB Decrypt Result%s\n", ACCENTCOLOR, DEFAULT);
		printf("\"%s\"", C);
	}

    return 0;
}

void run(char* argv[])
{
	unsigned char key[] = {
        0x31, 0x50, 0x10, 0x47,
        0x17, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    unsigned char message[] = {
        "Information Security is a multidisciplinary area of study and professional activity which is concerned with the development and implementation of security mechanisms of all available types (technical, organizational, human-oriented and legal) to keep information in all its locations (within and outside the organization's perimeter) and, consequently, information systems, where information is created, processed, stored, transmitted and destroyed, free from threats. This project is finished by GUORUI XU."
    };

    unsigned char out[16];

    printf("%sInput message%s\n", ACCENTCOLOR, DEFAULT);
    printf("\"%s\"\n", message);
    printf("%sKey%s\n", ACCENTCOLOR, DEFAULT);
    print_bytes(key, 16);
    aes_cmac(message, strlen((char*)message) + 1, (unsigned char*)out, key);
    printf("%sAES-128-CMAC Result%s\n", ACCENTCOLOR, DEFAULT);
    print_bytes(out, 16);

    unsigned int n = 0;
    unsigned char* C;

    C = ecb_encrypt(message, key, aes_128_encrypt, &n);
    printf("%sAES-128-ECB Encrypt Result%s\n", ACCENTCOLOR, DEFAULT);
    for (auto i = 0; i < n; i++) {
        print_bytes(C + i * 16, 16);
    }

    C = ecb_decrypt(C, key, aes_128_decrypt, &n);
    printf("%sAES-128-ECB Decrypt Result%s\n", ACCENTCOLOR, DEFAULT);
    printf("\"%s\"\n", C);

    printf("\nUsage: %s MESSAGE KEY\n", argv[0]);
}

void perform(char* argv[])
{
    printf("%sInput message%s\n", ACCENTCOLOR, DEFAULT);
    printf("\"%s\"\n", argv[1]);
    unsigned char key[16];
    unsigned char out[16];
    memset(out, 0x00, 16);
    memset(key, 0x00, 16);
    if (strlen(argv[2]) > 16) {
        memcpy(key, argv[2], 16);
    } else {
        memcpy(key, argv[2], strlen(argv[2]));
    }
    printf("%sKey%s\n", ACCENTCOLOR, DEFAULT);
    print_bytes(key, 16);
    aes_cmac((unsigned char*)(argv[1]), strlen(argv[1]) + 1, (unsigned char*)out, key);
    printf("%sAES-128-CMAC Result%s\n", ACCENTCOLOR, DEFAULT);
    print_bytes(out, 16);

    unsigned int n = 0;
    unsigned char* C;

    C = ecb_encrypt((unsigned char*)argv[1], (unsigned char*)argv[2], aes_128_encrypt, &n);
    printf("%sAES-128-ECB Encrypt Result%s\n", ACCENTCOLOR, DEFAULT);
    for (auto i = 0; i < n; i++) {
        print_bytes(C + i * 16, 16);
    }

    C = ecb_decrypt(C, (unsigned char*)argv[2], aes_128_decrypt, &n);
    printf("%sAES-128-ECB Decrypt Result%s\n", ACCENTCOLOR, DEFAULT);
    printf("\"%s\"", C);
}
