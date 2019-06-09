// Copyright 2017 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define PAM_SM_ACCOUNT
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include "../compat.h"
#include "../utils/oslogin_utils.h"

using std::string;

using oslogin_utils::HttpGet;
using oslogin_utils::GetUser;
using oslogin_utils::kMetadataServerUrl;
using oslogin_utils::ParseJsonToKey;
using oslogin_utils::ParseJsonToEmail;
using oslogin_utils::ParseJsonToSuccess;
using oslogin_utils::UrlEncode;
using oslogin_utils::ValidateUserName;

static const char kSudoersDir[] = "/var/google-sudoers.d/";


extern "C" {
int thefunc(pam_handle_t *pamh, int flags, int argc, const char **argv);

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return thefunc(pamh, flags, argc, argv);
}

PAM_EXTERN int    pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return thefunc(pamh, flags, argc, argv);
}

int thefunc(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  // The return value for this module should generally be ignored. By default we
  // will return PAM_SUCCESS.
  openlog("pam_admin", LOG_PID|LOG_PERROR, LOG_DAEMON);
  syslog(LOG_ERR, "Entered authenticate\n");
  const char *user_name;
  if (pam_get_user(pamh, &user_name, NULL) != PAM_SUCCESS) {
    PAM_SYSLOG(pamh, LOG_INFO, "Could not get pam user.");
    syslog(LOG_ERR, "Could not get pam user.");
    closelog();
    return PAM_IGNORE;
  }
  syslog(LOG_ERR, "pam_get_user says %s", user_name);

  char* item;
  pam_get_item(pamh, PAM_RUSER, (const void **) &item);
  syslog(LOG_ERR, "RUSER: %s", item);

  if (!ValidateUserName(user_name)) {
    syslog(LOG_ERR, "Invalid username");
    closelog();
    // If the user name is not a valid oslogin user, don't bother continuing.
    return PAM_IGNORE;
  }

  string response;
  if (!GetUser(user_name, &response)) {
    syslog(LOG_ERR, "GetUser returned false");
    closelog();
    return PAM_IGNORE;
  }

  string email;
  if (!ParseJsonToEmail(response, &email) || email.empty()) {
    syslog(LOG_ERR, "ParseJsonToEmail returned false");
    closelog();
    return PAM_IGNORE;
  }
  syslog(LOG_ERR, "user %s becomes email %s", user_name, email.c_str());

  std::stringstream url;
  url << kMetadataServerUrl << "authorize?email=" << UrlEncode(email)
      << "&policy=adminLogin";

  long http_code;
  if (HttpGet(url.str(), &response, &http_code) && http_code == 200 &&
      ParseJsonToSuccess(response)) {
    syslog(LOG_ERR, "PAM_SUCCESS");
    closelog();
    return PAM_SUCCESS;
  }
  syslog(LOG_ERR, "Falling through");
  closelog();

  return PAM_IGNORE;
}
}
