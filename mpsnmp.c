/*-
 *
 * DISTRIBUITION OR REDISTRIBUTION IN ANY FORM IS PROHIBITED! 
 * Copyright(c)2005 Nikolay Denev <nike_d@cytexbg.com>
 *
-*/

/*-
 *   TODO and FIXME:
 * o  what to do with unknown OIDs from the query?
 *    how we can understand which response var corresponds to
 *    which oid from the query?
-*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <unistd.h>
#include <pwd.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <rrd.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#define _REENTRANT

const char Rev[] = "$Id: mpsnmp.c 4910 2008-05-30 14:00:15Z ndenev $";

#define LISTFILE			"./hostlist.txt"
#define CONFFILE			"./mpsnmp.conf"
#define MAXHOSTNAME			255							/* max hostname len */
#define MAXFILENAME			255							/* max rrd file name */
#define MAXOBJ				1024						/* max total obj lan */
#define MAXUSER				30							/* max username len */
#define MAXPASS				30							/* max password len */
#define THR_MAX				256							/* max concurrent threads */
#define THR_DEF				20							/* default concurrent threads */
#define SNMP_RETRY			3							/* snmp session retry count */
#define	SNMP_TIMEOUT	    3000000						/* snmp session timeout */
#define MAXRESULT			1024						/* max len of the result string  */
#define LOCKFILE_NAME		"/tmp/mpsnmp-srvmon.lock"	/* lock file name */

typedef struct host
{
	char	name[MAXHOSTNAME];
	char	user[MAXUSER];
	char	pass[MAXPASS];
	struct	host	*head;
	struct	host	*next;
} host;

typedef struct conf
{
	char	rrdfile[MAXFILENAME];
	char	obj[MAXOBJ];
	struct	conf *head;
	struct	conf *next;
} conf;

int	hostcount = 0;
int	maxhostname = 0;
char	*user	= NULL;
char	*pass	= NULL;
int	verbose = 0;
int	quiet	= 0;
int	updaterrd = 0;
int	pctlen = 0;
int	threads	= THR_DEF;
static	host	*hstglob;
static	conf	*config;

pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

host* host_new()
{
	host *hst;
	hst = calloc(1, sizeof(host));
	if (hst == NULL) {
		fprintf(stderr, "%s\n", strerror(errno));
		exit(-1);
	}
	hst->head = hst;
	return(hst);
}

host* host_add(host *hst)
{
	if (hst == NULL) return(host_new());
	hst->next = host_add(hst->next);
	hst->next->head = hst->head;
	return(hst->next);
}

host* host_readlist(char *list_file)
{
	FILE    *hstlist;
	host	*head, *hst;
	char	 line[MAXHOSTNAME];

	if (list_file == NULL) list_file = LISTFILE;
	hstlist = fopen(list_file, "r");
	if (hstlist == NULL) return(NULL);

	hst = head = host_new();

	while (fgets(line, sizeof(line), hstlist)) {
		if(line[0] == '#') continue;
		if(line[0] == '\n') continue;
		memset(strchr(line, '\n'), 0, 1);
		hst = host_add(hst);
		strncpy(hst->name, line, sizeof(hst->name));
		strncpy(hst->user, user, sizeof(hst->user));
		strncpy(hst->pass, pass, sizeof(hst->pass));
		if (strlen(line) > maxhostname) maxhostname = strlen(line);
		++hostcount;
	}
	fclose(hstlist);
	return(head);
}

conf* conf_new()
{
	conf *cfg;
	cfg = calloc(1, sizeof(conf));
	if (cfg == NULL) {
		fprintf(stderr, "%s\n", strerror(errno));
		exit(-1);
	}
	cfg->head = cfg;
	return(cfg);
}

conf* conf_add(conf *cfg)
{
	if (cfg == NULL) return(conf_new());
	cfg->next = conf_add(cfg->next);
	cfg->next->head = cfg->head;
	return(cfg->next);
}

conf* parse_config(char *conf_file)
{
	FILE    *cfgfile;
	conf	*cfg;
	char	 line[1024];

	if (conf_file == NULL) conf_file = CONFFILE;
	cfgfile = fopen(conf_file, "r");
	if (cfgfile == NULL) return (NULL);

	cfg =  conf_new();

	while (fgets(line, sizeof(line), cfgfile)) {
		if(line[0] == '#') continue;
		if(line[0] == '\n') continue;
		if(line[0] == ' ') continue;
		memset(strchr(line, '\n'), 0, 1); /* no new lines */
		memset(strchr(line, ':'), 0, 1);
		cfg = conf_add(cfg);
		strncpy(cfg->rrdfile, line, sizeof(config->rrdfile));
		strncpy(cfg->obj, line + (strlen(cfg->rrdfile)+1), sizeof(cfg->obj));
	}
	fclose(cfgfile);
	return(cfg->head);
}


void usage(char *msg)
{
	printf("\n");
	printf("  %s\n\n", msg?msg:"");
	printf("mpsnmp (c) 2005 by Niki Denev <niki@totalterror.net>\n"
		"%s\n\n"
		"  Usage: mpsnmp [-v] [-q] [-r] [-t threads] [-f filename] [-c filename] <-u username> <-p password>\n"
		" -v : verbose output\n"
		" -q : quiet output (except errors)\n"
		" -r : update the rrd files\n"
		" -o : terminate after this number of seconds\n"
		" -t : threads to start (default %d, max %d)\n"
		" -f : host list file (default %s)\n"
		" -c : config file (default %s)\n",
		Rev, THR_DEF, THR_MAX, LISTFILE, CONFFILE);
	printf("\n");
	exit(0);
}

void cleanup_handler()
{
	unlink(LOCKFILE_NAME);
	return;
}

void main_cleanup_handler()
{
	cleanup_handler();
	return;
}

void term_cleanup_handler()
{
	printf("%s called\n", __func__);
	cleanup_handler();
	exit(-1);
}

void intr_cleanup_handler()
{
	printf("%s called\n", __func__);
	cleanup_handler();
	exit(-1);
}

void alrm_cleanup_handler()
{
	printf("%s called\n", __func__);
	cleanup_handler();
	exit(-1);
}

void worker_cleanup_handler()
{
	return;
}

void worker()
{
	char	*result[128];
	int	index;
	int	var_index;
	int	res_index;
	int	oidcnt[128];
	char	rrd_fname[MAXFILENAME];
	char	*temp_result;
	char	*objp;
	char	*last;
	char	*temp_obj[128];
	char	*dummy;
	int	status;
	int	retry;
	struct	snmp_session sess;
	struct	snmp_session *sptr;
	void	*sessp;
	struct	snmp_pdu *query;
	struct	snmp_pdu *response;
	struct	variable_list *vars;
	oid	oid_name[MAX_OID_LEN];
	size_t	oid_name_len;
	host	*hst;
	conf	*cfg;

	hst = NULL;

	/* register the cleanup routine */
	pthread_cleanup_push(worker_cleanup_handler, (void *)NULL);

	for (;;) {
		/* get a host to work on */
		pthread_mutex_lock(&mtx);
		if (hstglob->next) {
			hst = hstglob = hstglob->next;
		} else {
			hst = NULL;
		}
		pthread_mutex_unlock(&mtx);

		/* check if we don't have more work to do, and exit */
		if (!hst) pthread_exit(NULL);

		temp_result = NULL;
		status = 0;
		retry = 0;
		memset(&sess, 0, sizeof(struct snmp_session));
		memset(oidcnt, 0, sizeof(int) * 128);
		sptr = NULL;
		query = NULL;
		objp = NULL;
		last = NULL;
		dummy = NULL;
		memset(oid_name, 0, sizeof(oid) * MAX_OID_LEN);
		memset(&oid_name_len, 0, sizeof(size_t));

		/* SNMP Voodoo */
		snmp_sess_init(&sess);
		sess.peername = strdup(hst->name);
		sess.version = SNMP_VERSION_3;
		sess.retries = SNMP_RETRY;
		sess.timeout = SNMP_TIMEOUT;
		sess.securityName = strdup(hst->user);
		sess.securityNameLen = strlen(sess.securityName);
		sess.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
		sess.securityAuthProto = usmHMACSHA1AuthProtocol;
		sess.securityAuthProtoLen = sizeof(usmHMACSHA1AuthProtocol)/sizeof(oid);
		sess.securityAuthKeyLen = USM_AUTH_KU_LEN;
			if (generate_Ku(sess.securityAuthProto, sess.securityAuthProtoLen,
				hst->pass, strlen(hst->pass), sess.securityAuthKey,
				&sess.securityAuthKeyLen) != SNMPERR_SUCCESS) {
			fprintf(stderr, "error generating ku 1\n");
			continue; /* XXX cleanup? */
			}
		sess.securityPrivProto = usmDESPrivProtocol;
		sess.securityPrivProtoLen = sizeof(usmDESPrivProtocol)/sizeof(oid);
		sess.securityPrivKeyLen = USM_PRIV_KU_LEN;
			if (generate_Ku(sess.securityAuthProto, sess.securityAuthProtoLen,
				hst->pass, strlen(hst->pass), sess.securityPrivKey,
				&sess.securityPrivKeyLen) != SNMPERR_SUCCESS) {
			fprintf(stderr, "error generating ku 2\n");
			continue; /* XXX cleanup? */
			}
		sessp = snmp_sess_open(&sess);
		sptr = snmp_sess_session(sessp);
		query = snmp_pdu_create(SNMP_MSG_GET);
		/* ENDOF SNMP Voodoo */

		index = 0;
		cfg = config->head;
		while ((cfg = cfg->next)) {
			/* prepare the result strings */
			result[index] = (char *)calloc(1, MAXRESULT);
			sprintf(result[index],"N");
			temp_obj[index] = (char *)calloc(1, strlen(cfg->obj) + 1);
			memcpy(temp_obj[index], cfg->obj, strlen(cfg->obj));
			dummy = temp_obj[index];
			while ((objp = strtok_r(dummy, ":", &last))) {
				oid_name_len = MAX_OID_LEN;
				snmp_parse_oid(objp, oid_name, &oid_name_len);
				snmp_add_null_var(query, oid_name, oid_name_len);
				dummy = NULL;
				oidcnt[index]++;
			}
			index++;
		}

		var_index = 0;
		res_index = 0;

		status = snmp_sess_synch_response(sessp, query, &response);

		if (status == STAT_SUCCESS) {
			if (response->errstat == SNMP_ERR_NOERROR) {
				for(vars = response->variables; vars; vars = vars->next_variable) {
					if (var_index >= oidcnt[res_index]) {
						res_index++;
						var_index = 0;
					}
					switch (vars->type) {
						case ASN_OCTET_STR:
							strcat(result[res_index], ":");
							temp_result = (char *)calloc(1, vars->val_len + 1);
							memcpy(temp_result, vars->val.string, vars->val_len);
							temp_result[vars->val_len] = '\0';
							strncat(result[res_index], temp_result,
								MAXRESULT - strlen(result[res_index]) - 1);
							free(temp_result);
							break;
						case ASN_INTEGER:
						case ASN_GAUGE:
						case ASN_COUNTER:
						case ASN_TIMETICKS:
							strcat(result[res_index], ":");
							temp_result = (char *)calloc(1, 32);
							sprintf(temp_result, "%u", (uint)*vars->val.integer);
							strncat(result[res_index], temp_result,
								MAXRESULT - strlen(result[res_index] - 1));
							free(temp_result);
							break;
						case SNMP_NOSUCHINSTANCE:
							fprintf(stderr, "no such instance for %s\n",
								hst->name);
							strncat(result[res_index], ":U",
								sizeof(result[res_index])
									- strlen(result[res_index]) - 1);
							break;
						default:
							fprintf(stderr, "unknown value type: %d for %s\n",
								vars->type, hst->name);
							strncat(result[res_index], ":U",
								sizeof(result[res_index])
									- strlen(result[res_index]) - 1);
					}
					var_index++;
				}
			} else {
				fprintf(stderr,"packet error : %s for %s\n",
					snmp_errstring(response->errstat), hst->name);
				continue;
			}
		} else if (status == STAT_TIMEOUT) {
			fprintf(stderr, "timeout waiting response from : %s\n",
				hst->name);
			continue; /* XXX Cleanup? */
		} else {
			fprintf(stderr, "snmp_sess_sync_response() failed for : %s\n",
				hst->name);
			snmp_sess_perror("error: ", sptr);
			continue; /* XXX Cleanup ? */
		}

		index = 0;
		cfg = config->head;
		while ((cfg = cfg->next)) {
			if (verbose && !quiet) {
				printf("host: %s\nrrd: %s\nresult: %s\n\n",
					hst->name, cfg->rrdfile, result[index]);
			}
			if (updaterrd) {
				rrd_get_context();
				rrd_clear_error();
				temp_result = result[index];
				sprintf(rrd_fname, "%s-%s.rrd", cfg->rrdfile, hst->name);
				if (rrd_update_r(rrd_fname, NULL, 1, (const char **)&temp_result) < 0) {
						fprintf(stderr, "rrd error : %s for %s\n",
						rrd_get_error(), hst->name);
				}
			}
			free(temp_obj[index]);
			free(result[index]);
			index++;
		}
		snmp_free_pdu(response);
		snmp_sess_close(sessp);
		sessp = NULL;
		response = NULL;
		free(sess.peername);
		free(sess.securityName);
	}
}

int main(int argc, char *argv[])
{
	int		i;
	int		timeout;
	char		*conf_file;
	char		*list_file;
	pthread_t	thread;
	pthread_attr_t	attr;
	struct snmp_session dummy_snmpsess;
	sigset_t	sigmask;
	FILE 		*lockfile;

	conf_file = NULL;
	list_file = NULL;
	timeout = 0;

	while ((i = getopt(argc, argv, "c:f:o:p:qrt:u:v")) != -1) {
		switch (i) {
			case 'c':
				if (conf_file)
					usage("*** only one config file allowed");
				conf_file = optarg;
				break;
			case 'f':
				if (list_file)
					usage("*** only one host list file allowed");
				list_file = optarg;
				break;
			case 'o':
				if (timeout)
					usage("*** only one timeout value is allowed");
				timeout = (int)strtol(optarg, (char **)NULL, 10);
				if (timeout <= 0 || timeout > 3600)
					usage("*** timeout value out of range");
				break;
			case 'p':
				if (pass)
					usage("*** only one password allowed");
				pass = optarg;
				if (strlen(pass) > MAXPASS)
					usage("*** password too long");
				break;
			case 'q':
				quiet++;
				break;
			case 'r':
				updaterrd++;
				break;
			case 't':
				threads	= (int)strtol(optarg, (char **)NULL, 10);
				if (threads > THR_MAX) usage("*** too many threads specified");
				if (threads <= 0) usage("*** negative or zero threads specified");
				break;
			case 'u':
				if (user) usage("*** only one username allowed");
				user = optarg;
				if (strlen(user) > MAXUSER)
					usage("*** username too long");
				break;
			case 'v':
				verbose++;
				break;
			case '?':
				usage("*** unrecognized option");
			default:
			        usage(NULL);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc > 1)	usage("*** too many arguments");
	if (!user)	usage("*** username required");
	if (!pass)	usage("*** password required");

	/* install a signal handler */
	sigfillset(&sigmask);
	sigdelset(&sigmask, SIGTERM);
	sigdelset(&sigmask, SIGINT);
	if (timeout)
		sigdelset(&sigmask, SIGALRM);
	sigprocmask(SIG_BLOCK, &sigmask, NULL);
	signal(SIGTERM, term_cleanup_handler);
	signal(SIGINT, intr_cleanup_handler);
	if (timeout) {
		signal(SIGALRM, alrm_cleanup_handler);
		alarm(timeout);
	}

	/* use lockfile only if we are updating the rrd file */
	if (updaterrd) {
		if (!(lockfile = fopen(LOCKFILE_NAME, "w+"))) {
			fprintf(stderr, "unable to open/create lockfile : %s\n", LOCKFILE_NAME);
			fprintf(stderr, "reason : %s\n", strerror(errno));
			exit(-1);
		}
		if (lockf(fileno(lockfile), F_TLOCK, 0) == -1) {
			fprintf(stderr, "lock file is locked\n");
			fprintf(stderr, "probably another instance is running\n");
			exit(-1);
		}
	}

	hstglob = host_readlist(list_file);
	if (hstglob == NULL)
		usage("*** host list file problem");

	config = parse_config(conf_file);
	if (config == NULL)
		usage("*** config file problem");

	/* disable buffering */
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	if (!quiet) {
		printf("\n%s\n", Rev);
		printf("mpsnmp - mass parallel snmp by Niki Denev\n");
		printf("(c)2005 <niki@totalterror.net>\n\n");
		printf("  [*] read (%d) hosts from the list\n", hostcount);
		printf("  [*] starting %d threads\n", threads);
		if (timeout)
			printf("  [*] will terminate after %d seconds\n", timeout);
		printf("\n");
	}

	/*
	 * init some net-snmp internal data structures which
	 * are not thread safe, before starting the threads
	 */
	init_snmp("mpsnmp");
	snmp_sess_init(&dummy_snmpsess);

	/* cleanup handler, currently only removes lock file */
	pthread_cleanup_push(main_cleanup_handler, (void *)NULL);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setscope(&attr, PTHREAD_SCOPE_PROCESS);

	/* net-snmp sock startup */
	SOCK_STARTUP;
	for (i=1; i < threads; i++) {
		pthread_create(&thread, &attr, (void *)worker, (void *)NULL);
	}

	/* we're done starting the worker threads, so let's get to work and help them :) */
	worker();

	pthread_exit(NULL);
	SOCK_CLEANUP;

	exit(0);
}
