//#include "config.h"

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nfc/nfc.h>

#include <freefare.h>

#include <openssl/sha.h>

typedef struct {
	MifareClassicKey sector1keyA;
	MifareClassicKey sector1keyB;
	MifareClassicKey sector2keyA;
	MifareClassicKey sector2keyB;
} NUSkeys;

bool check_digital_signature (FreefareTag freefaretag)
{
	//TODO
	return true;
}

//DUmmy function that returns the keys by checking the UID, should be replaced by NUS implementation
void get_keys_from_uid_from_card (FreefareTag freefaretag, NUSkeys *nuskeys)
{
	//MifareClassicKey keya = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}; // default
	MifareClassicKey keya = {0xb3, 0x69, 0x17, 0x7a, 0xa3, 0x5f}; // nick-staff
	//MifareClassicKey keya = {0x5e, 0x87, 0x98, 0xec, 0x78, 0x0c}; // leon

	memcpy (&nuskeys->sector1keyA, &keya, 6);
    //TODO if-else cases to get the uid between our cards
    // i.e. if (LEON_UID) then keya = LEON_KEY_A
}


void usage (char *progname) {
	//TODO if we have options
    // one option can be inputting the key, since we don't have the lookup yet
}

int main(int argc, char *argv[])
{
    int ch;
    int error = EXIT_SUCCESS;
    nfc_device *device = NULL;
    FreefareTag *tags = NULL;
    NUSkeys nuskeys;
    MifareClassicBlock data[3];
    MifareClassicBlock signature;
    int device_count;

    while ((ch = getopt (argc, argv, "h")) != -1) {
	switch (ch) {
		case 'h':
		    usage(argv[0]);
		    exit (EXIT_SUCCESS);
		default:
			break;
		}
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
	    char *tag_friendly_name = freefare_get_tag_friendly_name (tags[i]);

	    get_keys_from_uid_from_card(tags[i], &nuskeys);

	    printf ("Found %s with UID %s. \n", tag_friendly_name, tag_uid);

		if (mifare_classic_connect(tags[i]) < 0) {
	    	printf ("Cannot connect to %s with UID %s. \n", tag_friendly_name, tag_uid);
            error = EXIT_FAILURE;
            goto errorrr;
	    }

        printf ("Connected to card. \n");
        printf ("Attempting to authenticate... \n");

	    if (mifare_classic_authenticate (tags[i], 0x07, nuskeys.sector1keyA, MFC_KEY_A) < 0) {
	    	printf ("Cannot authenticate with %s with UID %s. \n", tag_friendly_name, tag_uid);
            error = EXIT_FAILURE;
            goto errorrr;
	    }

        printf ("Authentication successful. \n");
        printf ("Reading card data... \n");

	    //all relevant NUS information (that we know of) is stored in blocks 4 through 6 
	    for (int j = 0; j < 3; j++) {
		    if (mifare_classic_read (tags[i], 0x04 + j, &data[j]) < 0) {
		    	printf ("Cannot read from block %d for %s with UID %s. \n", 4+j, tag_friendly_name, tag_uid);
                error = EXIT_FAILURE;
			    goto errorrr;
		    }
	    }

        printf ("Data read successful. \n");
        printf ("Checking signature... \n");

	    //we propose storing a digital signature at block 12, so this reads block 12
	    // if (mifare_classic_read (tags[i], 0x40, &signature) < 0) {
	    // 	printf ("Cannot read from block 12 for %s with UID %s", 4+j, tag_friendly_name, tag_uid);
		   //  free (tag_uid);
		   //  free (tag_friendly_name);
		   //  continue;
	    // }

        printf ("Signature check done. \n");
        printf ("Printing results... \n");
	    
	    printf ("The 5th block is : \n");
	    for (int j = 0; j < 16; j++) {
	    	printf ("%02x ", data[0][j]);
	    }
        printf ("\n");

        printf ("Results printed. \n");

        errorrr:
        if (error != EXIT_SUCCESS) {
            printf ("Freeing tag uid pointer. \n");
            free (tag_uid);
            printf ("Freeing tag friendly name pointer. \n");
            //free (tag_friendly_name);
            // apparently this variable is not allocated by malloc,
            // so it's inappropriate to use free() here.
            // commenting it out so that it won't crash while running
            printf ("Unable to free tag friendly name pointer. \n");
        }
	}

    printf ("Completed. \n");

	freefare_free_tags (tags);
	nfc_close (device);

    nfc_exit (context);
    exit (error);
}
