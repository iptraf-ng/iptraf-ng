/* For terms of usage/redistribution/modification see the LICENSE file */
/* For authors and contributors see the AUTHORS file */

/*
 * parseports.c - code to extract the protocol codes or ranges thereof from
 *                the user-defined string.
 *
 */

#include "iptraf-ng-compat.h"
#include "parseproto.h"


/*
 * Extracts next token from the buffer.
 */
static char *get_next_token(char **cptr)
{
	static char rtoken[32];
	int i;

	i = 0;

	skip_whitespace(*cptr);

	if (**cptr == ',' || **cptr == '-') {
		rtoken[0] = **cptr;
		rtoken[1] = '\0';
		(*cptr)++;
	} else {
		while (!isspace(**cptr) && **cptr != '-' && **cptr != ','
		       && **cptr != '\0') {
			rtoken[i] = **cptr;
			(*cptr)++;
			i++;
		}
		rtoken[i] = '\0';
	}

	return rtoken;
}

void get_next_protorange(char **cptr, unsigned int *proto1,
			 unsigned int *proto2, int *parse_result,
			 char **badtokenptr)
{
	char toktmp[5];
	char prototmp1[5];
	char prototmp2[5];
	char *cerr_ptr;
	static char bad_token[5];
	unsigned int tmp;

	memset(toktmp, 0, 5);
	memset(prototmp1, 0, 5);
	memset(prototmp2, 0, 5);
	memset(bad_token, 0, 5);

	memcpy(prototmp1, get_next_token(cptr), 5-1);
	if (prototmp1[0] == '\0') {
		*parse_result = NO_MORE_TOKENS;
		return;
	}

	memcpy(toktmp, get_next_token(cptr), 5-1);

	*parse_result = RANGE_OK;

	switch (toktmp[0]) {
	case '-':
		memcpy(prototmp2, get_next_token(cptr), 5-1);

		/*
		 * Check for missing right-hand token for -
		 */
		if (prototmp2[0] == '\0') {
			*parse_result = INVALID_RANGE;
			strcpy(bad_token, "-");
			*badtokenptr = bad_token;
			break;
		}
		*proto2 = (unsigned int) strtoul(prototmp2, &cerr_ptr, 10);
		/*
		 * First check for an invalid character
		 */
		if (*cerr_ptr != '\0') {
			*parse_result = INVALID_RANGE;
			strcpy(bad_token, prototmp2);
			*badtokenptr = bad_token;
		} else {
			/*
			 * Then check for the validity of the token
			 */

			if (*proto2 > 255) {
				strcpy(bad_token, prototmp2);
				*badtokenptr = bad_token;
				*parse_result = OUT_OF_RANGE;
			}

			/*
			 * Then check if the next token is a comma
			 */
			memcpy(toktmp, get_next_token(cptr), 5-1);
			if (toktmp[0] != '\0' && toktmp[0] != ',') {
				*parse_result = COMMA_EXPECTED;
				strcpy(bad_token, toktmp);
				*badtokenptr = bad_token;
			}
		}

		break;
	case ',':
	case '\0':
		*proto2 = 0;
		break;
	default:
		*parse_result = COMMA_EXPECTED;
		strcpy(bad_token, toktmp);
		*badtokenptr = bad_token;
		break;
	}

	if (*parse_result != RANGE_OK)
		return;

	*proto1 = (unsigned int) strtoul(prototmp1, &cerr_ptr, 10);
	if (*cerr_ptr != '\0') {
		*parse_result = INVALID_RANGE;
		strcpy(bad_token, prototmp1);
		*badtokenptr = bad_token;
	} else if (*proto1 > 255) {
		*parse_result = OUT_OF_RANGE;
		strcpy(bad_token, prototmp1);
		*badtokenptr = bad_token;
	} else
		*badtokenptr = NULL;

	if (*proto2 != 0 && *proto1 > *proto2) {
		tmp = *proto1;
		*proto1 = *proto2;
		*proto2 = tmp;
	}
}

int validate_ranges(char *samplestring, int *parse_result, char **badtokenptr)
{
	unsigned int proto1, proto2;
	char *cptr = samplestring;

	do {
		get_next_protorange(&cptr, &proto1, &proto2,
				    parse_result, badtokenptr);
	} while (*parse_result == RANGE_OK);

	if (*parse_result != NO_MORE_TOKENS)
		return 0;

	return 1;
}
