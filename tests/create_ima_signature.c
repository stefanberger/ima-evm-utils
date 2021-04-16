/*
 * create_ima_signature - Test program for imaevm_create_ima_signature
 *
 * Copyright (C) 2021 IBM Corporation
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * As a special exception, the copyright holders give permission to link the
 * code of portions of this program with the OpenSSL library under certain
 * conditions as described in each individual source file and distribute
 * linked combinations including the program with the OpenSSL library. You
 * must comply with the GNU General Public License in all respects
 * for all of the code used other than as permitted herein. If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so. If you do not
 * wish to do so, delete this exception statement from your version. If you
 * delete this exception statement from all source files in the program,
 * then also delete it in the license file.
 *
 */

#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include <openssl/pem.h>

#include "imaevm.h"

int main(int argc, char *argv[]) {
	unsigned char ima_signature[MAX_SIGNATURE_SIZE];
	static struct option long_options[] = {
		{"key", required_argument, NULL, 'k'},
		{"hashalgo", required_argument, NULL, 'a'},
		{NULL, 0, NULL, 0}
	};
	const char *hash_algo = "sha1";
	const char *keyfile = NULL;
	const char *file_to_sign;
	EVP_PKEY *pkey = NULL;
	char *error = NULL;
	int option_index;
	int siglen;
	size_t i;
	FILE *fp;
	int opt;

	while ((opt = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1) {
		switch (opt) {
		case 'k':
			keyfile = optarg;
			break;
		case 'a':
			hash_algo = optarg;
			break;
		default:
			fprintf(stderr, "Unhandled option %d.\n", opt);
			return 1;
		}
	}
	if (keyfile == NULL) {
		fprintf(stderr, "Missing --key option.\n");
		return 1;
	}

	if (optind == argc) {
		fprintf(stderr, "Missing filename for file to sign.");
	}

	file_to_sign = argv[optind];

	fp = fopen(keyfile, "r");
	if (fp == NULL) {
		fprintf(stderr, "Could not open private key file: %s\n", strerror(errno));
		return 1;
	}

	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (pkey == NULL) {
		fprintf(stderr, "Could not read private key!\n");
		return 1;
	}

	/* the library doesn't prepend this! */
	ima_signature[0] = EVM_IMA_XATTR_DIGSIG;
	siglen = imaevm_create_ima_signature(file_to_sign, pkey, 0, hash_algo, &ima_signature[1],
	                                     sizeof(ima_signature) - 1, &error);
	if (siglen < 0) {
		fprintf(stderr, "Failed to created IMA signature: %s\n", error);
	} else {
		fprintf(stdout, "Successfully created IMA signature!\n");
		for (i = 0; i < siglen + 1; i++)
			fprintf(stdout, "%02x", ima_signature[i]);
		fprintf(stdout, "\n");
	}

	free(error);
	EVP_PKEY_free(pkey);

	return siglen < 0;
}
