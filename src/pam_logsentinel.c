#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <syslog.h>
#include <stdbool.h>


/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	pam_syslog(pamh, LOG_INFO, "SetCred called for LogSentinel module");
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	pam_syslog(pamh, LOG_INFO, "AcctMgmt called for LogSentinel module");
	return PAM_SUCCESS;
}


char** str_split(char* a_str, const char a_delim) {


    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    count += last_comma < (a_str + strlen(a_str) - 1);


    count++;

    result = malloc(sizeof(char*) * count);

    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);

        while (token)
        {
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }

        *(result + idx) = 0;
    }

    return result;
}


/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {

	char c[1000];
	FILE *fptr;

	pam_syslog(pamh, LOG_INFO, "Logging authentication events to LogSentinel");
	
	// assuming first param is path to configurtation
	if ((fptr = fopen(argv[0], "r")) == NULL){
		// config is wrong - allow access
		pam_syslog(pamh, LOG_ERR, "Couldn't open Logsentinel PAM config. Check file %s\n", argv[0]);
		return PAM_SUCCESS;
	}


	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	char aliveUrl[1000];
	char checkDomainCerts[1000];
	char authorizationHeader[1000];
	char applicationId[1000];
	char logUrl[1000];
	char pushTo[100];

	while ((read = getline(&line, &len, fptr)) != -1) {
		if ( startsWith("aliveUrl", line) != 0) {
			strcpy(aliveUrl, line + 9);
			strtok(aliveUrl, "\n");
		}
		if ( startsWith("checkDomainCerts", line) != 0) {
			strcpy(checkDomainCerts, line + 17);
			strtok(checkDomainCerts, "\n");
		}
		if ( startsWith("authorizationHeader", line) != 0) {
			strcpy(authorizationHeader, line + 20);
			strtok(authorizationHeader, "\n");
		}
		if ( startsWith("applicationId", line) != 0) {
			strcpy(applicationId, line + 14);
			strtok(applicationId, "\n");
		}
		if ( startsWith("logUrl", line) != 0) {
			strcpy(logUrl, line + 7);
			strtok(logUrl, "\n");
		}
		if ( startsWith("pushTo", line) != 0) {
			strcpy(pushTo, line + 7);
			strtok(pushTo, "\n");
		}

	}

	free(line);
	fclose(fptr);


	int retval;

	const char* pUsername;

	retval = pam_get_user(pamh, &pUsername, "Username: ");

	// if there is no such user continue normal auth flow
	if (retval != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_INFO, "No such user %s", pUsername);
		return retval;
	}
	
	int alive;
	char aliveCommand[1000];
	strcpy(aliveCommand, "curl -sL -w '%{http_code}\\n' '");
	strcat(aliveCommand, aliveUrl);
	strcat(aliveCommand, "' -o /dev/null");

	alive = system(aliveCommand);
	pam_syslog(pamh, LOG_INFO, "%s is %s\n", aliveUrl, alive == 0 ? "alive" : "not alive" );
	// if logsentinel is down allow access. It's not logging anyway
	if (alive != 0) {
		return PAM_SUCCESS;
	}

	char** domains;
	domains = str_split(checkDomainCerts, '|');

	if (domains) {
		int i;
		for (i = 0; *(domains + i); i++) {
			int certValid;
			char certCommand[1000];
			strcpy(certCommand, "openssl s_client -CApath /etc/ssl/certs/ -showcerts -connect ");
			strcat(certCommand, *(domains + i));
			strcat(certCommand, " | grep \"Verify return code: 0\"");
			certValid = system(certCommand);

			pam_syslog(pamh, LOG_INFO, "%s has %s certificate\n", *(domains + i), certValid == 0 ? "valid" : "invalid");
			// if certificate is not valid block access (possible malicious actions)
			if (certValid != 0) {
				pam_syslog(pamh, LOG_ERR, "invalid certificate for %s", *(domains + i));
				return PAM_AUTH_ERR;
			}
			free(*(domains + i));
		}
		free(domains);
	}

	int logResult;

	char curlCommand[1000];
	strcpy(curlCommand, "curl -H 'Authorization:");
	strcat(curlCommand, authorizationHeader);
	strcat(curlCommand, "' -H 'Application-Id:");
	strcat(curlCommand, applicationId);
	strcat(curlCommand, "' -H 'Content-Type:application/json' -d '{}' -X POST ");
	strcat(curlCommand, logUrl);
	strcat(curlCommand, pUsername);
	strcat(curlCommand, "/LOGSENTINEL_LOGIN/SYSTEM/0?directExternalPush=");
	strcat(curlCommand, pushTo);


	logResult = system(curlCommand);

	pam_syslog(pamh, LOG_INFO, "Login attempt is %s logged in logsentinel\n", logResult == 0 ? "sucessfully" : "not successfully");
	if (logResult != 0) {
		pam_syslog(pamh, LOG_ERR, "Cannot log login event in Logsentinel instance %s", logUrl);
		return PAM_AUTH_ERR;
	}

	return  PAM_SUCCESS;
}

int startsWith(const char *pre, const char *str) {
    size_t lenpre = strlen(pre),
           lenstr = strlen(str);
    return lenstr < lenpre ? 0 : strncmp(pre, str, lenpre) == 0 ? 1 : 0;
}
