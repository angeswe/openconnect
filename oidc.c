/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * OIDC authentication support for Clavister OneConnect
 *
 * Copyright © 2008-2015 Microsoft Corp
 * Copyright © 2025 Marcus Asteborg
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <config.h>

#include "openconnect-internal.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Helper: find a string property in a json_value object */
static const char *json_get_string(json_value *obj, const char *key)
{
	if (!obj || obj->type != json_object)
		return NULL;
	for (unsigned int i = 0; i < obj->u.object.length; i++) {
		if (!strcmp(obj->u.object.values[i].name, key)) {
			json_value *v = obj->u.object.values[i].value;
			if (v && v->type == json_string)
				return v->u.string.ptr;
		}
	}
	return NULL;
}

/*
 * Handle Clavister OneConnect OIDC authentication.
 *
 * When the server responds with authenticator="oidc", it provides:
 *   - discovery-endpoint: OIDC well-known configuration URL
 *   - client-id: OAuth2 client ID
 *   - nonce: Server-generated nonce (validated in the id_token)
 *
 * Flow:
 * 1. Fetch OIDC discovery document to find authorization and token endpoints
 * 2. Open browser to authorization URL with localhost callback
 * 3. Capture authorization code from the callback
 * 4. Exchange code for id_token at the token endpoint
 * 5. Store id_token for the auth-reply (sent as <id-token> element)
 */
int handle_oidc_auth(struct openconnect_info *vpninfo)
{
	int listen_fd = -1, conn_fd = -1;
	int ret = -EINVAL;
	int port;
	char *code = NULL;
	char *redirect_uri = NULL;
	FILE *fp;
	char cmd[8192];
	char response[65536];
	json_value *json = NULL;
	struct oc_text_buf *buf;

	if (!vpninfo->oidc_discovery_endpoint || !vpninfo->oidc_client_id || !vpninfo->oidc_nonce) {
		vpn_progress(vpninfo, PRG_ERR, _("Missing OIDC parameters\n"));
		return -EINVAL;
	}

	/* Step 1: Fetch OIDC discovery document */
	vpn_progress(vpninfo, PRG_INFO, _("Fetching OIDC discovery document...\n"));
	snprintf(cmd, sizeof(cmd), "curl -s '%s'", vpninfo->oidc_discovery_endpoint);
	fp = popen(cmd, "r");
	if (!fp) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to run curl for OIDC discovery\n"));
		return -EIO;
	}
	size_t nread = fread(response, 1, sizeof(response) - 1, fp);
	response[nread] = '\0';
	pclose(fp);

	json = json_parse(response, nread);
	if (!json) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to parse OIDC discovery document\n"));
		return -EINVAL;
	}

	const char *authorization_endpoint = json_get_string(json, "authorization_endpoint");
	const char *token_endpoint = json_get_string(json, "token_endpoint");

	if (!authorization_endpoint || !token_endpoint) {
		vpn_progress(vpninfo, PRG_ERR, _("OIDC discovery missing required endpoints\n"));
		ret = -EINVAL;
		goto out;
	}

	free(vpninfo->oidc_token_endpoint);
	vpninfo->oidc_token_endpoint = strdup(token_endpoint);

	/* Step 2: Create localhost listener for OAuth callback */
	{
		struct sockaddr_in addr4 = { 0 };
		socklen_t addrlen;
		int one = 1;

		listen_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (listen_fd < 0) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to create OIDC callback socket\n"));
			ret = -EIO;
			goto out;
		}
		setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		addr4.sin_family = AF_INET;
		addr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr4.sin_port = 0;
		if (bind(listen_fd, (struct sockaddr *)&addr4, sizeof(addr4)) < 0) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to bind OIDC callback socket\n"));
			ret = -EIO;
			goto out;
		}
		addrlen = sizeof(addr4);
		getsockname(listen_fd, (struct sockaddr *)&addr4, &addrlen);
		port = ntohs(addr4.sin_port);
		listen(listen_fd, 1);
	}

	/* Build redirect URI */
	buf = buf_alloc();
	buf_append(buf, "http://127.0.0.1:%d/oneconnect/oauth/", port);
	redirect_uri = strdup((char *)buf->data);

	/* Build authorization URL and set as sso_login for browser spawning */
	buf_truncate(buf);
	buf_append(buf, "%s?client_id=%s&response_type=code"
		   "&redirect_uri=http%%3A%%2F%%2F127.0.0.1%%3A%d%%2Foneconnect%%2Foauth%%2F"
		   "&scope=openid&nonce=%s&state=oc_oidc",
		   authorization_endpoint, vpninfo->oidc_client_id, port, vpninfo->oidc_nonce);

	free(vpninfo->sso_login);
	vpninfo->sso_login = strdup((char *)buf->data);
	buf_free(buf);

	/* We can free the discovery JSON now */
	json_value_free(json);
	json = NULL;

	/* Step 3: Open browser */
	vpn_progress(vpninfo, PRG_INFO, _("Opening browser for OIDC authentication...\n"));

	if (vpninfo->open_ext_browser) {
		ret = vpninfo->open_ext_browser(vpninfo, vpninfo->sso_login, vpninfo->cbdata);
	} else {
		/* Launch browser as the original user if running under sudo,
		 * since browsers refuse to run as root */
		const char *sudo_user = getenv("SUDO_USER");
		const char *sudo_uid = getenv("SUDO_UID");
		const char *browser = vpninfo->external_browser ? vpninfo->external_browser : "xdg-open";
		if (sudo_user && sudo_uid) {
			snprintf(cmd, sizeof(cmd),
				 "su '%s' -c 'XDG_RUNTIME_DIR=/run/user/%s %s \"%s\"' &",
				 sudo_user, sudo_uid, browser, vpninfo->sso_login);
		} else {
			snprintf(cmd, sizeof(cmd), "%s '%s' &", browser, vpninfo->sso_login);
		}
		ret = system(cmd) ? -EIO : 0;
	}

	if (ret) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to open browser for OIDC authentication\n"));
		goto out;
	}

	/* Step 4: Wait for callback */
	vpn_progress(vpninfo, PRG_INFO, _("Waiting for OIDC callback on port %d...\n"), port);

	conn_fd = accept(listen_fd, NULL, NULL);
	if (conn_fd < 0) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to accept OIDC callback connection\n"));
		ret = -EIO;
		goto out;
	}

	nread = read(conn_fd, response, sizeof(response) - 1);
	if ((ssize_t)nread <= 0) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to read OIDC callback\n"));
		ret = -EIO;
		goto out;
	}
	response[nread] = '\0';

	/* Parse authorization code from: GET /oneconnect/oauth/?code=XXX&state=YYY */
	{
		char *code_start = strstr(response, "code=");
		if (!code_start) {
			const char *err_resp = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n"
				"<html><body><h2>Authentication failed</h2>"
				"<p>No authorization code received.</p></body></html>";
			write(conn_fd, err_resp, strlen(err_resp));
			vpn_progress(vpninfo, PRG_ERR, _("No authorization code in OIDC callback\n"));
			ret = -EPERM;
			goto out;
		}
		code_start += 5;
		char *code_end = code_start;
		while (*code_end && *code_end != '&' && *code_end != ' '
		       && *code_end != '\r' && *code_end != '\n')
			code_end++;
		code = strndup(code_start, code_end - code_start);
	}

	/* Send success page */
	{
		const char *ok_resp = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n"
			"<html><body><h2>Authentication successful</h2>"
			"<p>You can close this window and return to the VPN client.</p></body></html>";
		write(conn_fd, ok_resp, strlen(ok_resp));
	}

	vpn_progress(vpninfo, PRG_INFO, _("Authorization code received, exchanging for token...\n"));

	/* Step 5: Exchange code for id_token */
	snprintf(cmd, sizeof(cmd),
		 "curl -s -X POST '%s' "
		 "-d 'grant_type=authorization_code&client_id=%s&code=%s&redirect_uri=%s'",
		 vpninfo->oidc_token_endpoint, vpninfo->oidc_client_id, code, redirect_uri);
	fp = popen(cmd, "r");
	if (!fp) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to exchange OIDC authorization code\n"));
		ret = -EIO;
		goto out;
	}
	nread = fread(response, 1, sizeof(response) - 1, fp);
	response[nread] = '\0';
	pclose(fp);

	json = json_parse(response, nread);
	if (!json) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to parse OIDC token response\n"));
		ret = -EINVAL;
		goto out;
	}

	{
		const char *id_token = json_get_string(json, "id_token");
		if (!id_token) {
			vpn_progress(vpninfo, PRG_ERR, _("No id_token in OIDC token response\n"));
			ret = -EPERM;
			goto out;
		}

		free(vpninfo->sso_cookie_value);
		vpninfo->sso_cookie_value = strdup(id_token);
	}

	vpn_progress(vpninfo, PRG_INFO, _("OIDC authentication successful\n"));
	ret = 0;

out:
	if (json)
		json_value_free(json);
	if (conn_fd >= 0)
		close(conn_fd);
	if (listen_fd >= 0)
		close(listen_fd);
	free(code);
	free(redirect_uri);
	return ret;
}

int set_oidc_token(struct openconnect_info *vpninfo, const char *token_str)
{
	int ret;
	char *file_token = NULL;

	if (!token_str)
		return -ENOENT;

	switch (token_str[0]) {
	case '@':
		token_str++;
		/* fall through */
	case '/':
		ret = openconnect_read_file(vpninfo, token_str, &file_token);
		if (ret < 0)
			return ret;
		vpninfo->bearer_token = file_token;
		break;

	default:
		vpninfo->bearer_token = strdup(token_str);
		if (!vpninfo->bearer_token)
			return -ENOMEM;
	}

	vpninfo->token_mode = OC_TOKEN_MODE_OIDC;
	return 0;
}
