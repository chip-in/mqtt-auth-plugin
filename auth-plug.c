#include <mosquitto.h>
#include <mosquitto_plugin.h>

#if LIBMOSQUITTO_VERSION_NUMBER >= 1004090
int conv_code(int val){
	if(val == MOSQ_ERR_AUTH) return MOSQ_ERR_PLUGIN_DEFER;
	if(val == MOSQ_ERR_ACL_DENIED) return MOSQ_ERR_PLUGIN_DEFER;
	return val;
}
#else
int conv_code(int val){
	return val;
}
#endif

#if MOSQ_AUTH_PLUGIN_VERSION >= 3
# define mosquitto_auth_opt mosquitto_opt
#endif

int proc_mosquitto_auth_plugin_init(void **userdata, struct mosquitto_auth_opt *auth_opts, int auth_opt_count);
int proc_mosquitto_auth_plugin_cleanup(void *userdata, struct mosquitto_auth_opt *auth_opts, int auth_opt_count);
int proc_mosquitto_auth_security_init(void *userdata, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload);
int proc_mosquitto_auth_security_cleanup(void *userdata, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload);
#if MOSQ_AUTH_PLUGIN_VERSION >= 3
int proc_mosquitto_auth_unpwd_check_v3(void *userdata, const struct mosquitto *client, const char *username, const char *password);
int proc_mosquitto_auth_acl_check_v3(void *userdata, int access, const struct mosquitto *client, const struct mosquitto_acl_msg *msg);
#else
int proc_mosquitto_auth_unpwd_check_v2(void *userdata, const char *username, const char *password);
int proc_mosquitto_auth_acl_check_v2(void *userdata, const char *clientid, const char *username, const char *topic, int access);
#endif

int mosquitto_auth_plugin_version(void)
{
	return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **userdata, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
	return proc_mosquitto_auth_plugin_init(userdata, auth_opts, auth_opt_count);
}

int mosquitto_auth_plugin_cleanup(void *userdata, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
	return proc_mosquitto_auth_plugin_cleanup(userdata, auth_opts, auth_opt_count);
}

int mosquitto_auth_security_init(void *userdata, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
	return proc_mosquitto_auth_security_init(userdata, auth_opts, auth_opt_count, reload);
}

int mosquitto_auth_security_cleanup(void *userdata, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
	return proc_mosquitto_auth_security_cleanup(userdata, auth_opts, auth_opt_count, reload);
}

#if MOSQ_AUTH_PLUGIN_VERSION >=3
int mosquitto_auth_unpwd_check(void *userdata, const struct mosquitto *client, const char *username, const char *password)
{
	int granted = proc_mosquitto_auth_unpwd_check_v3(userdata, client, username, password);
	return conv_code(granted);
}
#else
int mosquitto_auth_unpwd_check(void *userdata, const char *username, const char *password)
{
	int granted = proc_mosquitto_auth_unpwd_check_v2(userdata, username, password);
	return conv_code(granted);
}
#endif

#if MOSQ_AUTH_PLUGIN_VERSION >= 3
int mosquitto_auth_acl_check(void *userdata, int access, const struct mosquitto *client, const struct mosquitto_acl_msg *msg)
{
	int granted = proc_mosquitto_auth_acl_check_v3(userdata, access, client, msg);
	return conv_code(granted);
}
#else
int mosquitto_auth_acl_check(void *userdata, const char *clientid, const char *username, const char *topic, int access)
{
	int granted = proc_mosquitto_auth_acl_check_v2(userdata, clientid, username, topic, access);
	return conv_code(granted);
}
#endif

#if MOSQ_AUTH_PLUGIN_VERSION >= 3
int mosquitto_auth_psk_key_get(void *userdata, const struct mosquitto *client, const char *hint, const char *identity, char *key, int max_key_len)
#else
int mosquitto_auth_psk_key_get(void *userdata, const char *hint, const char *identity, char *key, int max_key_len)
#endif
{
	return conv_code(MOSQ_ERR_AUTH);
}
