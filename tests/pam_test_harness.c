#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct app_data {
  const char *pin;
};

int conversation(int num_msg, const struct pam_message **msg,
                 struct pam_response **resp, void *appdata_ptr) {
  struct app_data *data = (struct app_data *)appdata_ptr;
  struct pam_response *reply = NULL;

  if (num_msg <= 0)
    return PAM_CONV_ERR;

  reply = (struct pam_response *)calloc(num_msg, sizeof(struct pam_response));
  if (reply == NULL)
    return PAM_BUF_ERR;

  for (int i = 0; i < num_msg; i++) {
    switch (msg[i]->msg_style) {
    case PAM_PROMPT_ECHO_OFF:
    case PAM_PROMPT_ECHO_ON:
      reply[i].resp = strdup(data->pin);
      reply[i].resp_retcode = 0;
      break;
    case PAM_ERROR_MSG:
    case PAM_TEXT_INFO:
      // Ignore info/error messages
      reply[i].resp = NULL;
      reply[i].resp_retcode = 0;
      break;
    default:
      free(reply);
      return PAM_CONV_ERR;
    }
  }

  *resp = reply;
  return PAM_SUCCESS;
}

int main(int argc, char *argv[]) {
  pam_handle_t *pamh = NULL;
  int retval;
  struct app_data data;
  struct pam_conv conv;

  if (argc != 4) {
    fprintf(stderr, "Usage: %s <service_name> <username> <pin>\n", argv[0]);
    return 1;
  }

  const char *service = argv[1];
  const char *user = argv[2];
  data.pin = argv[3];

  conv.conv = conversation;
  conv.appdata_ptr = &data;

  retval = pam_start(service, user, &conv, &pamh);

  if (retval == PAM_SUCCESS) {
    retval = pam_authenticate(pamh, 0);
  }

  if (retval == PAM_SUCCESS) {
    fprintf(stdout, "Authenticated\n");
  } else {
    fprintf(stdout, "Not Authenticated\n");
  }

  if (pam_end(pamh, retval) != PAM_SUCCESS) {
    pamh = NULL;
    fprintf(stderr, "check_user: failed to release authenticator\n");
    return 1;
  }

  return (retval == PAM_SUCCESS ? 0 : 1);
}
