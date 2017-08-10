#include <sys/wait.h>
#include <unistd.h>
#include <uci.h>
#include <sys/stat.h>
#include <libubox/list.h>

#include <sysrepo.h>
#include <sysrepo/plugins.h>

#include "common.h"
#include "sip.h"

#define XPATH_MAX_LEN 100

/* name of the uci config file. */
//static const char *config_file = "voice_client";
static const char *yang_model = "ietf-interfaces";

static int rpc_start(const char *xpath, const sr_val_t *input, const size_t input_cnt,
              sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    pid_t pid=fork();
    if (pid==0) {
        execl("/etc/init.d/asterisk", "asterisk", "start", (char *) NULL);
        exit(127);
    } else {
        waitpid(pid, 0, 0);
    }

    return SR_ERR_OK;
}

static int rpc_stop(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                    sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    pid_t pid=fork();
    if (pid==0) {
        execl("/etc/init.d/asterisk", "asterisk", "stop", (char *) NULL);
        exit(127);
    } else {
        waitpid(pid, 0, 0);
    }

    return SR_ERR_OK;
}

static int rpc_restart(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                       sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    pid_t pid=fork();
    if (pid==0) {
        execl("/etc/init.d/asterisk", "asterisk", "restart", (char *) NULL);
        exit(127);
    } else {
        waitpid(pid, 0, 0);
    }

    return SR_ERR_OK;
}

static int rpc_reload(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                      sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    pid_t pid=fork();
    if (pid==0) {
        execl("/etc/init.d/asterisk", "asterisk", "reload", (char *) NULL);
        exit(127);
    } else {
        waitpid(pid, 0, 0);
    }

    return SR_ERR_OK;
}

static int rpc_disable(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                       sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    pid_t pid=fork();
    if (pid==0) {
        execl("/etc/init.d/asterisk", "asterisk", "disable", (char *) NULL);
        exit(127);
    } else {
        waitpid(pid, 0, 0);
    }

    return SR_ERR_OK;
}

static int rpc_enable(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                      sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    pid_t pid = fork();
    if (pid == 0) {
        execl("/etc/init.d/asterisk", "asterisk", "enable", (char *) NULL);
        exit(127);
    } else {
        waitpid(pid, 0, 0);
    }

    return SR_ERR_OK;
}

//static int
//module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx) {
//	int rc = SR_ERR_OK;
//	ctx_t *ctx = private_ctx;
//	INF("%s configuration has changed.", yang_model);
//
//	ctx->sess = session;
//
//	if (SR_EV_APPLY == event) {
//		/* copy running datastore to startup */
//
//		rc = sr_copy_config(ctx->startup_sess, module_name, SR_DS_RUNNING, SR_DS_STARTUP);
//		if (SR_ERR_OK != rc) {
//			WRN_MSG("Failed to copy running datastore to startup");
//			/* TODO handle this error */
//			return rc;
//		}
//		return SR_ERR_OK;
//	}
//
//	//rc = parse_config(session, module_name, ctx, event);
//	CHECK_RET(rc, error, "failed to apply sysrepo changes to snabb: %s", sr_strerror(rc));
//
//error:
//	return rc;
//}

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    int rc = SR_ERR_OK;
    ctx_t *ctx = private_ctx;

    return rc;
}

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    /* INF("sr_plugin_init_cb for sysrepo-plugin-dt-network"); */

    ctx_t *ctx = calloc(1, sizeof(*ctx));
	ctx->sub = subscription;
	ctx->sess = session;
    *private_ctx = ctx;

    /* Allocate UCI context for uci files. */
    ctx->uctx = uci_alloc_context();
    if (!ctx->uctx) {
        fprintf(stderr, "Can't allocate uci\n");
        goto error;
    }
INF_MSG("TEST");
    rc = sr_module_change_subscribe(session, yang_model, module_change_cb, *private_ctx,
                                    0, SR_SUBSCR_DEFAULT, &subscription);
    CHECK_RET(rc, error, "initialization error: %s", sr_strerror(rc));
INF_MSG("TEST");

	/* subscribe for handling RPC */
/*
    rc = sr_rpc_subscribe(session, "/sip:start", rpc_start, (void *)session, SR_SUBSCR_DEFAULT, &ctx->sub);
    CHECK_RET(rc, error, "rpc start initialization error: %s", sr_strerror(rc));
    rc = sr_rpc_subscribe(session, "/sip:stop", rpc_stop, (void *)session, SR_SUBSCR_DEFAULT, &subscription);
    CHECK_RET(rc, error, "rpc stop initialization error: %s", sr_strerror(rc));
    rc = sr_rpc_subscribe(session, "/sip:restart", rpc_restart, (void *)session, SR_SUBSCR_DEFAULT, &subscription);
    CHECK_RET(rc, error, "rpc restart initialization error: %s", sr_strerror(rc));
    rc = sr_rpc_subscribe(session, "/sip:reload", rpc_reload, (void *)session, SR_SUBSCR_DEFAULT, &subscription);
    CHECK_RET(rc, error, "rpc reload initialization error: %s", sr_strerror(rc));
    rc = sr_rpc_subscribe(session, "/sip:disable", rpc_disable, (void *)session, SR_SUBSCR_DEFAULT, &subscription);
    CHECK_RET(rc, error, "rpc disable initialization error: %s", sr_strerror(rc));
    rc = sr_rpc_subscribe(session, "/sip:enable", rpc_enable, (void *)session, SR_SUBSCR_DEFAULT, &subscription);
    CHECK_RET(rc, error, "rpc enable initialization error: %s", sr_strerror(rc));

*/
    SRP_LOG_DBG_MSG("Plugin initialized successfully");

    return SR_ERR_OK;

  error:
    SRP_LOG_ERR("Plugin initialization failed: %s", sr_strerror(rc));
    sr_unsubscribe(session, subscription);
    free(ctx);
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    INF("Plugin cleanup called, private_ctx is %s available.", private_ctx ? "" : "not");
    if (!private_ctx) return;

    ctx_t *ctx = private_ctx;
    sr_unsubscribe(session, ctx->sub);
    free(ctx);

    SRP_LOG_DBG_MSG("Plugin cleaned-up successfully");
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

static void
sigint_handler(__attribute__((unused)) int signum) {
	INF_MSG("Sigint called, exiting...");
	exit_application = 1;
}

int
main() {
	INF_MSG("Plugin application mode initialized");
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL;
	void *private_ctx = NULL;
	int rc = SR_ERR_OK;

	/* connect to sysrepo */
	rc = sr_connect(yang_model, SR_CONN_DEFAULT, &connection);
	CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

	/* start session */
	rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
	CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

	rc = sr_plugin_init_cb(session, &private_ctx);
	CHECK_RET(rc, cleanup, "Error by sr_plugin_init_cb: %s", sr_strerror(rc));

	/* loop until ctrl-c is pressed / SIGINT is received */
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);
	while (!exit_application) {
		sleep(1);  /* or do some more useful work... */
	}

	sr_plugin_cleanup_cb(session, private_ctx);
cleanup:
	if (NULL != session) {
		sr_session_stop(session);
	}
	if (NULL != connection) {
		sr_disconnect(connection);
	}
}
#endif
