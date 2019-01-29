# logsentinel-PAM
PAM module performing some checks and logs before ssh login
- checks if logsentinel application is alive (if not allows access)
- checks configurable list of domains for their certificates to be valid (Ethereum, time stamping service).
If some of them are not valid there is a possibility of malicious actions, so access is not allowed
- logs login attempts in logsentinel
- allows access if everything is ok

# Usage

1. run build.sh or commands in it (different linux distributions have different paths, so check it)
    - compile
`gcc -fPIC -fno-stack-protector -c src/pam_logsentinel.c`
    - check where pam modules are
`sudo ld -x --shared -o /lib/i386-linux-gnu/security/pam_logsentinel.so pam_logsentinel.o`
    - this file can be located anywhere. Other pam modules' configs are in /etc/security/
`cp logsentinel.conf /etc/security/logsentinel.conf`
    - edit logsentinel.conf with appropriate properties:
         aliveUrl - url which will be hit to check if logsentinel app is working
         checkDomainCerts - domains certificates to check before login (ex Ethereum, timestamping service etc.)
         authorizationHeader - base64(organizationId:organizationSecret) can be found in logsentinel dashboard
         applicationId - can be found in logsentinel dashboard
         logUrl - url of the API where logs will be sent

2. The PAM config files are located in `/etc/pam.d/
    - open /etc/pam.d/sshd and append at the end of it
`auth requisite pam_logsentinel.so /etc/security/logsentinel.conf`
/etc/security/logsentinel.conf is the path to the conf file (change it if it is somewhere else)
    - try to ssh

NOTE: if you use ssh to do this, always keep one terminal with root logged in, in case something goes wrong.
It's possible to lock yourself out and you won't be able to ssh even with correct root credentials