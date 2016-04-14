//#include "config.h"

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nfc/nfc.h>

#include <freefare.h>
#include <openssl/hmac.h>

#define MIFARE_CLASSIC_BLOCK_SIZE 16

typedef enum {
	ACTION_CHECK_MAC,
	ACTION_WRITE_MAC
} Action;

const MifareClassicKey NUS_DEFAULT_KEY_A = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5},
		KEY_Ab_NICK = {0x8d, 0x8a, 0xbd, 0xc9, 0xd1, 0x44},
		KEY_B7_NICK = {0x1f, 0xa3, 0x6b, 0x3d, 0xce, 0xfd},
		KEY_Bb_NICK = {0x8d, 0x8a, 0xbd, 0xc9, 0xd1, 0x44};

//Dummy function that returns the keys by checking the UID, should be replaced by NUS implementation
void get_sector1keyA_from_uid (char *tag_uid, MifareClassicKey *key)
{
	const MifareClassicKey KEY_A_LEON = {0x5e, 0x87, 0x98, 0xec, 0x78, 0x0c},
		KEY_A_NICK = {0x8d, 0x8a, 0xbd, 0xc9, 0xd1, 0x44},
		KEY_A_SN = {0x31, 0x61, 0x7b, 0x53, 0x30, 0x0b};

	const char *UID_LEON = "70f98a48",
		*UID_NICK = "a68a6077",
		*UID_SN = "a0fc8e4d";

	if (0 == strncmp(tag_uid, UID_LEON, 8))
		memcpy (key, KEY_A_LEON, 6);
	else if (0 == strncmp(tag_uid, UID_NICK, 8))
		memcpy (key, KEY_A_NICK, 6);
	else if (0 == strncmp(tag_uid, UID_SN, 8))
		memcpy (key, KEY_A_SN, 6);
	else printf ("We don't have the key for this UID\n");
}

void usage (char *progname) 
{
    fprintf (stderr, "\nOptions:\n");
    fprintf (stderr, "  -c     Check the validity of the MAC\n");
    fprintf (stderr, "  -w     Write the MAC onto an NUS card\n");
    fprintf (stderr, "Please choose exactly one (c or w) option\n");
}

int main (int argc, char *argv[])
{
    int ch;
    int error = EXIT_SUCCESS;
    nfc_device *device = NULL;
    FreefareTag *tags = NULL;
    MifareClassicKey nuskeyA;
    MifareClassicBlock data[3];
    int device_count;
    Action action;

    //the contents of 3 blocks of NUS information
    unsigned char card_data[3 * MIFARE_CLASSIC_BLOCK_SIZE];

    const char *tag_friendly_name;

    /*This is a demonstration. In practice, do not hard
     *code keys
     */
    //A 256 bit key
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

    unsigned char mac[3 * MIFARE_CLASSIC_BLOCK_SIZE] = { 0 } ;
    int mac_len;

    //reads the first option only
    if ((ch = getopt (argc, argv, "cwh")) != -1) {
		switch (ch) {
		case 'c':
			action = ACTION_CHECK_MAC;
			break;
		case 'w':
			action = ACTION_WRITE_MAC;
			break;
		case 'h':
		default:
		    usage (argv[0]);
		    exit (EXIT_SUCCESS);
			break;
		}
    } else {
    	usage (argv[0]);
    	exit (EXIT_SUCCESS);
    }

    nfc_connstring devices[1];

    nfc_context *context;
    nfc_init (&context);
    if (context == NULL)
	errx(EXIT_FAILURE, "Unable to init libnfc (malloc)");

    device_count = nfc_list_devices (context, devices, 1);
    if (device_count <= 0)
	errx (EXIT_FAILURE, "No NFC device found.");


	device = nfc_open (context, devices[0]);
	if (!device) {
	    nfc_close (device);
	    errx (EXIT_FAILURE, "nfc_open() failed.");
	}

	tags = freefare_get_tags (device);
	if (!tags) {
	    nfc_close (device);
	    errx (EXIT_FAILURE, "Error listing Mifare Classic tag.");
	}

	for (int i = 0; (!error) && tags[i]; i++) {
	    switch (freefare_get_tag_type (tags[i])) {
		    case MIFARE_CLASSIC_1K:
			break;

		    default:
			continue;
	    }

	    char *tag_uid = freefare_get_tag_uid (tags[i]);
	    tag_friendly_name = freefare_get_tag_friendly_name (tags[i]);

	    get_sector1keyA_from_uid (tag_uid, &nuskeyA);

	    printf ("Found %s with UID %s. \n", tag_friendly_name, tag_uid);

		if (mifare_classic_connect(tags[i]) < 0) {
	    	printf ("Cannot connect to %s with UID %s. \n", tag_friendly_name, tag_uid);
            error = EXIT_FAILURE;
            goto error;
	    }

        printf ("Connected to card. \n");
        printf ("Attempting to authenticate... \n");

	    if (mifare_classic_authenticate (tags[i], 0x07, nuskeyA, MFC_KEY_A) < 0) {
	    	printf ("Cannot authenticate with %s with UID %s. \n", tag_friendly_name, tag_uid);
            error = EXIT_FAILURE;
            goto error;
	    }

        printf ("Authentication successful. \n");
        
        printf ("Reading card data... \n");

	    //all relevant NUS information (that we know of) is stored in blocks 4 through 6 
	    for (int j = 0; j < 3; j++) {
		    if (mifare_classic_read (tags[i], 0x04 + j, &data[j]) < 0) {
		    	printf ("Cannot read from block %d for %s with UID %s. \n", 4+j, tag_friendly_name, tag_uid);
                error = EXIT_FAILURE;
			    goto error;
		    }
	    }

        printf ("Data read successful. \n");

        memcpy (card_data, data[0], MIFARE_CLASSIC_BLOCK_SIZE);
        memcpy (&card_data[MIFARE_CLASSIC_BLOCK_SIZE], data[1], MIFARE_CLASSIC_BLOCK_SIZE);
        memcpy (&card_data[2*MIFARE_CLASSIC_BLOCK_SIZE], data[2], MIFARE_CLASSIC_BLOCK_SIZE);

	    //HMAC (EVP_sha256 (), key, 32, card_data, 3*MIFARE_CLASSIC_BLOCK_SIZE, mac, &mac_len);

	    // printf ("mac is of length %d\n", mac_len);

	    // for (int j = 0; j < mac_len; j++)
	    // 	printf ("%02x ", mac[j]);
	    // printf ("\n");

	    if (action == ACTION_WRITE_MAC) {
	    	
	    	/*// fill in a special array instead of the mac array
	    	unsigned char notamac[3 * MIFARE_CLASSIC_BLOCK_SIZE] = { 0 } ;
	    	for (int j = 0; j < 3*MIFARE_CLASSIC_BLOCK_SIZE; j++) {
	    		notamac[j] = 0xaa;
	    	}
        
		    printf ("Authing for mac block... \n");
		    
			//we propose storing a message authentocation code at blocks 60 through 62, the next few lines
			//authenticates block 63 to write to blocks 60 through 62
			if (mifare_classic_authenticate (tags[i], 0x3f, NUS_DEFAULT_KEY_A, MFC_KEY_A) < 0) {
				printf ("Cannot authenticate with %s with UID %s. \n", tag_friendly_name, tag_uid);
		        error = EXIT_FAILURE;
		        goto error;
			}
	    
	    	// modify to write shit to the mac place
		    for (int j = 0; j < 3; j++) {
			    //if (mifare_classic_write (tags[i], 0x3c + j, &mac[j * MIFARE_CLASSIC_BLOCK_SIZE]) < 0) {
			    if (mifare_classic_write (tags[i], 0x3c + j, &notamac[j * MIFARE_CLASSIC_BLOCK_SIZE]) < 0) {
			    	printf ("Cannot write to block %d for %s with UID %s", 0x3c+j, tag_friendly_name, tag_uid);
				    error = EXIT_FAILURE;
				    goto error;
			    }
			}

			printf ("Not a MAC written \n");
	    	
	    	// fill in another array of shit bits
	    	unsigned char alsonotamac[MIFARE_CLASSIC_BLOCK_SIZE] = { 0 } ;
	    	for (int j = 0; j < MIFARE_CLASSIC_BLOCK_SIZE; j++) {
	    		alsonotamac[j] = 0xbb;
	    	}
        
		    printf ("authing for shit block... \n");

			if (mifare_classic_authenticate (tags[i], 0x0f, NUS_DEFAULT_KEY_A, MFC_KEY_A) < 0) {
				printf ("Cannot authenticate block %d with %s with UID %s. \n", 0x0f, tag_friendly_name, tag_uid);
		        error = EXIT_FAILURE;
		        goto error;
			}
	    
	    	// now write it to the shit block
	    	int esult = mifare_classic_write (tags[i], 0x0d, &alsonotamac[0]);
		    if (esult < 0) {
		    	printf ("%d Cannot write to block %d for %s with UID %s. \n", esult, 0x0d, tag_friendly_name, tag_uid);
			    error = EXIT_FAILURE;
			    goto error;
		    }

			printf ("Also not a MAC written \n");*/
	    	
	    	// fill in yet another array of shit bits
	    	unsigned char matricbuster[16] = { 0x41, 0x30, 0x31, 0x30, 
	    										0x38, 0x33, 0x35, 0x38, 
	    										0x42, 0x00, 0x00, 0x00,
	    										0x00, 0x00, 0x00, 0x00 } ;
//	    	for (int j = 0; j < MIFARE_CLASSIC_BLOCK_SIZE; j++) {
//	    		matricbuster[j] = 0xbb;
//	    	}
        
		    printf ("authing for matric block... \n");

			if (mifare_classic_authenticate (tags[i], 0x07, KEY_B7_NICK, MFC_KEY_B) < 0) {
				printf ("Cannot authenticate block %d with %s with UID %s. \n", 0x07, tag_friendly_name, tag_uid);
		        error = EXIT_FAILURE;
		        goto error;
			}
	    
	    	// now write it to the matric block
	    	int mesult = mifare_classic_write (tags[i], 0x04, &matricbuster[0]);
		    if (mesult < 0) {
		    	printf ("%d Cannot write to block %d for %s with UID %s. \n", mesult, 0x04, tag_friendly_name, tag_uid);
			    error = EXIT_FAILURE;
			    goto error;
		    }

			printf ("Matricbuster is not a MAC written \n");
			
			printf ("MAC written \n");
		
		} else if (action == ACTION_CHECK_MAC) {
			for (int j = 0; j < 3; j++) {
			    if (mifare_classic_read (tags[i], 0x3c + j, &data[j]) < 0) {
			    	printf ("Cannot read from block %d for %s with UID %s. \n", 60+j, tag_friendly_name, tag_uid);
	                error = EXIT_FAILURE;
				    goto error;
			    }
		    }

		    memcpy (card_data, data[0], MIFARE_CLASSIC_BLOCK_SIZE);
	        memcpy (&card_data[MIFARE_CLASSIC_BLOCK_SIZE], data[1], MIFARE_CLASSIC_BLOCK_SIZE);
	        memcpy (&card_data[2*MIFARE_CLASSIC_BLOCK_SIZE], data[2], MIFARE_CLASSIC_BLOCK_SIZE);

	        if (0 == strncmp(mac, card_data, 3*MIFARE_CLASSIC_BLOCK_SIZE))
	        	printf("The MAC is correct\n");
	        else printf("The MAC is incorrect\n");
		}


        //the tag_uid should be freed at the end of an iteration, whether or not there is an error
        error:
        free (tag_uid);

	}

	freefare_free_tags (tags);
	nfc_close (device);

    nfc_exit (context);
    exit (error);
}
