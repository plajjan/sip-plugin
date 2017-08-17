#include <sys/wait.h>
#include <unistd.h>
#include <uci.h>
#include <sys/stat.h>

#include <sysrepo.h>
#include <sysrepo/plugins.h>

#include "common.h"
#include "sip.h"
#include "parse.h"

/* name of the uci config file. */
static const char *config_file = "voice_client";
static const char *yang_model = "sip";

static int parse_change(sr_session_ctx_t *session, const char *module_name, ctx_t *ctx, sr_notif_event_t event)
{
	sr_change_iter_t *it = NULL;
	int rc = SR_ERR_OK;
	sr_change_oper_t oper;
	sr_val_t *old_value = NULL;
	sr_val_t *new_value = NULL;
	char xpath[XPATH_MAX_LEN] = {
		0,
	};

	snprintf(xpath, XPATH_MAX_LEN, "/%s:*", module_name);

	rc = sr_get_changes_iter(session, xpath, &it);
	if (SR_ERR_OK != rc) {
		printf("Get changes iter failed for xpath %s", xpath);
		goto error;
	}

	while (SR_ERR_OK == sr_get_change_next(session, it, &oper, &old_value, &new_value)) {
		rc = sysrepo_to_uci(ctx, oper, old_value, new_value, event);
		sr_free_val(old_value);
		sr_free_val(new_value);
		CHECK_RET(rc, error, "failed to add operation: %s", sr_strerror(rc));
	}

	pid_t pid=fork();
	if (pid==0) {
		execl("/etc/init.d/voice_client", "voice_client", "restart", (char *) NULL);
		exit(127);
	} else {
		waitpid(pid, 0, 0);
	}

error:
	if (NULL != it) {
		sr_free_change_iter(it);
	}
	return rc;
}

static int module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	ctx_t *ctx = private_ctx;
	INF("%s configuration has changed.", yang_model);

	ctx->sess = session;

	if (SR_EV_APPLY == event) {
		/* copy running datastore to startup */

		rc = sr_copy_config(ctx->startup_sess, module_name, SR_DS_RUNNING, SR_DS_STARTUP);
		if (SR_ERR_OK != rc) {
			WRN_MSG("Failed to copy running datastore to startup");
			/* TODO handle this error */
			return rc;
		}
		return SR_ERR_OK;
	}

	rc = parse_change(session, module_name, ctx, event);
	CHECK_RET(rc, error, "failed to apply sysrepo changes to snabb: %s", sr_strerror(rc));

error:
	return rc;
}

static int state_data_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    int rc = SR_ERR_OK;
	ctx_t *ctx = private_ctx;

	rc = fill_state_data(ctx, (char *) xpath, values, values_cnt);
	CHECK_RET(rc, error, "failed to load state data: %s", sr_strerror(rc));

	/*
	for (int i = 0; i < *values_cnt; i++) {
		sr_print_val(&(*values)[i]);
	}
	*/

error:
    return rc;
}

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
	sr_subscription_ctx_t *subscription = NULL;
	int rc = SR_ERR_OK;

	/* INF("sr_plugin_init_cb for sysrepo-plugin-dt-network"); */

	ctx_t *ctx = calloc(1, sizeof(*ctx));
	ctx->sub = subscription;
	ctx->sess = session;
	ctx->startup_conn = NULL;
	ctx->startup_sess = NULL;
	ctx->yang_model = yang_model;
	ctx->config_file = config_file;
	*private_ctx = ctx;

	/* Allocate UCI context for uci files. */
	ctx->uctx = uci_alloc_context();
	if (NULL == ctx->uctx) {
		rc = SR_ERR_NOMEM;
	}
	CHECK_RET(rc, error, "Can't allocate uci context: %s", sr_strerror(rc));

	/* load the startup datastore */
	INF_MSG("load sysrepo startup datastore");
	rc = load_startup_datastore(ctx);
	CHECK_RET(rc, error, "failed to load startup datastore: %s", sr_strerror(rc));

	/* sync sysrepo datastore and uci configuration file */
	rc = sync_datastores(ctx);
	CHECK_RET(rc, error, "failed to sync sysrepo datastore and cui configuration file: %s", sr_strerror(rc));

	rc = sr_module_change_subscribe(ctx->sess, yang_model, module_change_cb, *private_ctx, 0, SR_SUBSCR_DEFAULT, &ctx->sub);
	CHECK_RET(rc, error, "initialization error: %s", sr_strerror(rc));

	rc = sr_dp_get_items_subscribe(ctx->sess, "/sip:sip-status", state_data_cb, ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
	CHECK_RET(rc, error, "failed sr_dp_get_items_subscribe: %s", sr_strerror(rc));

	INF_MSG("Plugin initialized successfully");

	return SR_ERR_OK;

error:
	ERR("Plugin initialization failed: %s", sr_strerror(rc));
	sr_unsubscribe(ctx->sess, ctx->sub);
	free(ctx);
	return rc;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
	INF("Plugin cleanup called, private_ctx is %s available.", private_ctx ? "" : "not");
	if (!private_ctx)
		return;

	ctx_t *ctx = private_ctx;
	sr_unsubscribe(session, ctx->sub);
	free(ctx);

	DBG_MSG("Plugin cleaned-up successfully");
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

static void sigint_handler(__attribute__((unused)) int signum)
{
	INF_MSG("Sigint called, exiting...");
	exit_application = 1;
}

int main()
{
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
		sleep(1); /* or do some more useful work... */
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
