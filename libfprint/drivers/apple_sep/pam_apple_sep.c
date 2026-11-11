// SPDX-License-Identifier: GPL-2.0-only
/*
 * pam_apple_sep: the user's password as the SEP's passcode for Touch ID, as macOS's login password is the passcode of
 * the user's keybag. Off unless a PAM file names the module; apple_sep.c keeps the identity it works on.
 *
 *   auth      optional  pam_apple_sep.so          after pam_unix: in passcode mode, the session's UNLOCK with the
 *                                                 secret the password gives, once a boot (Touch ID waits for it)
 *   password  optional  pam_apple_sep.so passcode after pam_unix: the SEP's secret follows the new password
 *                                                 (CHANGE_SECRET, the session unlocked first with the old secret
 *                                                 when no login did this boot); `passcode` switches a random-secret
 *                                                 identity to the password at the change, its absence switches one
 *                                                 back
 *
 * The secret: SHA-256 of crypt(3)'s yescrypt of the password with the identity's setting, never kept. Before the SEP
 * sees it, it is checked against the identity's verifier, HMAC-SHA-256(secret, "apple-sep verifier"): a password
 * /etc/shadow takes but the bag does not know (root's reset with no old password) never reaches the SEP, which counts
 * wrong secrets toward a lock of the bag that may be final. The verifier costs an attacker what the shadow hash does.
 *
 * STATE_DIR/identity-UID.bin (UUID, secret or zeros, uid), .kb (the bag), .pass in passcode mode ("SETTING VERIFIER\n",
 * the verifier in hex). After its UNLOCK the module writes STATE_DIR/boot as "BOOT UID pam": apple_sep.c then loads
 * the kept records at its first operation. A change the SEP's secret cannot follow (root's reset with no old password,
 * another session unlocked this boot) changes nothing on the SEP and leaves .stale.
 */
#define _GNU_SOURCE
#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <pwd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <syslog.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "apple-sep-bio.h"

#define STATE_DIR "/var/lib/libfprint/apple-sep"
#define BOOT_ID "/proc/sys/kernel/random/boot_id"
#define SECRET_LEN 32
#define IDENTITY_LEN (APPLE_SEP_BIO_UUID_LEN + SECRET_LEN + 4)
#define VERIFIER_LABEL "apple-sep verifier"
#define READY_WAIT_MS 30000

static char *
path_of (guint32 uid, const char *ext)
{
  return g_strdup_printf (STATE_DIR "/identity-%u.%s", uid, ext);
}

static gboolean
put_file (const char *path, const void *data, gsize len)
{
  return g_file_set_contents_full (path, data, len, G_FILE_SET_CONTENTS_CONSISTENT | G_FILE_SET_CONTENTS_DURABLE,
                                   0600, NULL);
}

/* the secret from the password and the identity's yescrypt setting */
static gboolean
derive (const char *password, const char *setting, guint8 secret[SECRET_LEN])
{
  struct crypt_data *cd = g_malloc0 (sizeof (*cd));
  gsize len = SECRET_LEN;
  gboolean ok = FALSE;
  const char *h = crypt_r (password, setting, cd);

  if (h && h[0] != '*')
    {
      GChecksum *c = g_checksum_new (G_CHECKSUM_SHA256);
      g_checksum_update (c, (const guchar *) h, strlen (h));
      g_checksum_get_digest (c, secret, &len);
      g_checksum_free (c);
      ok = len == SECRET_LEN;
    }
  explicit_bzero (cd, sizeof (*cd));
  g_free (cd);
  return ok;
}

static char *
verifier_of (const guint8 secret[SECRET_LEN])
{
  return g_compute_hmac_for_data (G_CHECKSUM_SHA256, secret, SECRET_LEN, (const guchar *) VERIFIER_LABEL,
                                  strlen (VERIFIER_LABEL));
}

/* .pass: the setting and the verifier */
static gboolean
read_pass (guint32 uid, char **setting, char **verifier)
{
  g_autofree char *p = path_of (uid, "pass");
  g_autofree char *s = NULL;
  g_auto(GStrv) f = NULL;

  if (!g_file_get_contents (p, &s, NULL, NULL))
    return FALSE;
  f = g_strsplit (g_strstrip (s), " ", 3);
  if (g_strv_length (f) != 2)
    return FALSE;
  *setting = g_strdup (f[0]);
  *verifier = g_strdup (f[1]);
  return TRUE;
}

/* a new setting, the secret it gives, and .pass's line for them */
static char *
new_pass (const char *password, guint8 secret[SECRET_LEN])
{
  char setting[CRYPT_GENSALT_OUTPUT_SIZE];
  g_autofree char *v = NULL;

  if (!crypt_gensalt_rn ("$y$", 0, NULL, 0, setting, sizeof (setting)) || !derive (password, setting, secret))
    return NULL;
  v = verifier_of (secret);
  return g_strdup_printf ("%s %s\n", setting, v);
}

/* the password's secret, if it is the identity's (the verifier) */
static gboolean
checked_secret (guint32 uid, const char *password, guint8 secret[SECRET_LEN])
{
  g_autofree char *setting = NULL, *verifier = NULL, *v = NULL;

  if (!password || !read_pass (uid, &setting, &verifier) || !derive (password, setting, secret))
    return FALSE;
  v = verifier_of (secret);
  if (strlen (v) == strlen (verifier) && memcmp (v, verifier, strlen (v)) == 0)
    return TRUE;
  explicit_bzero (secret, SECRET_LEN);
  return FALSE;
}

static int
open_dev (pam_handle_t *pamh, guint32 *state)
{
  struct apple_sep_bio_info info = { 0 };
  guint32 wait = READY_WAIT_MS;
  int fd = open ("/dev/apple-sep-bio", O_RDWR | O_CLOEXEC);

  if (fd < 0)
    return -1;
  if (ioctl (fd, APPLE_SEP_BIO_WAIT, &wait) != 0 || ioctl (fd, APPLE_SEP_BIO_GET_INFO, &info) != 0 ||
      info.version < 7)
    {
      pam_syslog (pamh, LOG_WARNING, "/dev/apple-sep-bio: not ready, or interface %u before 7", info.version);
      close (fd);
      return -1;
    }
  *state = info.state;
  return fd;
}

static char *
boot_id (void)
{
  char *id = NULL;

  return g_file_get_contents (BOOT_ID, &id, NULL, NULL) ? g_strstrip (id) : NULL;
}

/* whether this boot's session is uid's (apple_sep.c's or this module's STATE_DIR/boot) */
static gboolean
session_is (guint32 uid, guint32 state)
{
  g_autofree char *boot = boot_id ();
  g_autofree char *kept = NULL;
  char kid[64];
  guint kuid;

  return (state & APPLE_SEP_BIO_UNLOCKED) && boot && g_file_get_contents (STATE_DIR "/boot", &kept, NULL, NULL) &&
         sscanf (kept, "%63s %u", kid, &kuid) == 2 && g_str_equal (kid, boot) && kuid == uid;
}

static gboolean
user_uid (pam_handle_t *pamh, guint32 *uid)
{
  const char *user = NULL;
  struct passwd *pw;

  if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS || !user || !(pw = getpwnam (user)) || pw->pw_uid < 10)
    return FALSE;
  *uid = pw->pw_uid;
  return TRUE;
}

/* uid's session unlocked with secret and the kept bag, then STATE_DIR/boot for apple_sep.c: once a boot */
static gboolean
unlock_session (pam_handle_t *pamh, int fd, guint32 uid, const guint8 secret[SECRET_LEN])
{
  struct apple_sep_bio_unlock u = { 0 };
  g_autofree char *id_path = path_of (uid, "bin"), *bag_path = path_of (uid, "kb"), *boot = NULL, *line = NULL;
  g_autofree guint8 *identity = NULL, *bag = NULL, *buf = NULL;
  gsize len = 0, bag_len = 0;
  int r;

  if (!g_file_get_contents (id_path, (gchar **) &identity, &len, NULL) || len != IDENTITY_LEN ||
      GUINT32_FROM_LE (*(guint32 *) (identity + 48)) != uid ||
      !g_file_get_contents (bag_path, (gchar **) &bag, &bag_len, NULL) || bag_len == 0 ||
      bag_len > APPLE_SEP_BIO_BAG_MAX)
    {
      pam_syslog (pamh, LOG_ERR, "uid %u: no identity and bag to unlock", uid);
      return FALSE;
    }
  buf = g_malloc0 (APPLE_SEP_BIO_BAG_MAX);
  memcpy (buf, bag, bag_len);
  u.uid = uid;
  u.bag_len = bag_len;
  u.bag = (guintptr) buf;
  memcpy (u.uuid, identity, APPLE_SEP_BIO_UUID_LEN);
  memcpy (u.secret, secret, SECRET_LEN);
  r = ioctl (fd, APPLE_SEP_BIO_UNLOCK, &u);
  explicit_bzero (u.secret, sizeof (u.secret));
  explicit_bzero (identity, len);
  if (r != 0)
    {
      pam_syslog (pamh, LOG_ERR, "uid %u: UNLOCK: %s", uid, g_strerror (errno));
      return FALSE;
    }
  boot = boot_id ();
  line = g_strdup_printf ("%s %u pam\n", boot ? boot : "?", uid);
  if (!put_file (STATE_DIR "/boot", line, strlen (line)))
    pam_syslog (pamh, LOG_ERR, "uid %u: unlocked, but %s/boot not written", uid, STATE_DIR);
  return TRUE;
}

/* auth: in passcode mode, the session's UNLOCK once a boot */
PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  g_autofree char *pass_path = NULL;
  guint8 secret[SECRET_LEN];
  const char *tok = NULL;
  guint32 uid, state;
  int fd;

  if (!user_uid (pamh, &uid))
    return PAM_IGNORE;
  pass_path = path_of (uid, "pass");
  if (!g_file_test (pass_path, G_FILE_TEST_EXISTS))
    return PAM_IGNORE;
  if ((fd = open_dev (pamh, &state)) < 0)
    return PAM_IGNORE;
  if (state & APPLE_SEP_BIO_UNLOCKED)
    goto out;
  /* pam_unix's token (asked for when no module before took one) */
  if (pam_get_authtok (pamh, PAM_AUTHTOK, &tok, NULL) != PAM_SUCCESS || !checked_secret (uid, tok, secret))
    {
      /* a wrong password, or one the bag does not know: nothing goes to the SEP */
      pam_syslog (pamh, LOG_NOTICE, "uid %u: the password is not the SEP's passcode: no unlock", uid);
      goto out;
    }
  unlock_session (pamh, fd, uid, secret);
  explicit_bzero (secret, SECRET_LEN);
out:
  close (fd);
  return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_IGNORE;
}

/* password: the SEP's secret follows the password */
PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  struct apple_sep_bio_secret s = { 0 };
  g_autofree char *id_path = NULL, *bag_path = NULL, *pass_path = NULL, *stale_path = NULL, *pass = NULL;
  g_autofree guint8 *identity = NULL, *buf = NULL;
  const char *old = NULL, *now = NULL;
  gboolean want = FALSE, is_pass, ok;
  gsize len = 0;
  guint32 uid, state;
  int fd, r;

  if (!(flags & PAM_UPDATE_AUTHTOK) || !user_uid (pamh, &uid))
    return PAM_IGNORE;
  for (int i = 0; i < argc; i++)
    want |= g_str_equal (argv[i], "passcode");
  id_path = path_of (uid, "bin");
  bag_path = path_of (uid, "kb");
  pass_path = path_of (uid, "pass");
  stale_path = path_of (uid, "stale");
  is_pass = g_file_test (pass_path, G_FILE_TEST_EXISTS);
  if (!is_pass && !want)
    return PAM_IGNORE;
  if (!g_file_get_contents (id_path, (gchar **) &identity, &len, NULL) || len != IDENTITY_LEN)
    return PAM_IGNORE;
  if ((fd = open_dev (pamh, &state)) < 0)
    return PAM_IGNORE;
  /* pam_unix's tokens (asked for when no module before took them); the old one only for a passcode identity */
  if ((is_pass && pam_get_authtok (pamh, PAM_OLDAUTHTOK, &old, NULL) != PAM_SUCCESS) ||
      pam_get_authtok (pamh, PAM_AUTHTOK, &now, NULL) != PAM_SUCCESS || !now)
    {
      old = NULL;
      if (!now)
        goto out;
    }

  /* the old secret: the password's, or the identity's random one */
  if (is_pass)
    ok = checked_secret (uid, old, s.old_secret);
  else
    {
      memcpy (s.old_secret, identity + APPLE_SEP_BIO_UUID_LEN, SECRET_LEN);
      ok = TRUE;
    }
  if (!ok && !old)
    {
      /* root's reset (no old password): the SEP keeps the old secret, the identity is marked */
      put_file (stale_path, "", 0);
      pam_syslog (pamh, LOG_WARNING, "uid %u: no old passcode: the SEP's secret is not changed (%s)", uid, stale_path);
      goto out;
    }
  if (!ok)
    {
      /* a wrong old password: pam_unix refuses the change too */
      pam_syslog (pamh, LOG_NOTICE, "uid %u: the old password is not the passcode: the SEP's secret is not changed", uid);
      goto out;
    }
  /*
   * CHANGE_SECRET needs the session unlocked: with no password login this boot (a key over SSH) the module unlocks
   * it with the old secret first, so a passcode cannot stay behind the password. Another session this boot (the SEP
   * holds one) leaves a passcode identity behind: marked.
   */
  if (!session_is (uid, state) &&
      ((state & APPLE_SEP_BIO_UNLOCKED) || !unlock_session (pamh, fd, uid, s.old_secret)))
    {
      if (is_pass)
        put_file (stale_path, "", 0);
      pam_syslog (pamh, LOG_WARNING, "uid %u: %s this boot: the SEP's secret is not changed", uid,
                  (state & APPLE_SEP_BIO_UNLOCKED) ? "another session is unlocked" : "no unlock");
      explicit_bzero (s.old_secret, SECRET_LEN);
      goto out;
    }
  /* the new one: the new password's, or with the option gone a random one */
  if (want)
    pass = new_pass (now, s.new_secret);
  else if (getrandom (s.new_secret, SECRET_LEN, 0) != SECRET_LEN)
    goto out;
  if (want && !pass)
    goto out;

  buf = g_malloc0 (APPLE_SEP_BIO_BAG_MAX);
  s.uid = uid;
  s.bag = (guintptr) buf;
  r = ioctl (fd, APPLE_SEP_BIO_CHANGE_SECRET, &s);
  explicit_bzero (s.old_secret, SECRET_LEN);
  if (r != 0)
    {
      int e = errno;

      /* ENODATA: the SEP holds the new secret until the reboot, the kept bag the old one */
      if (e == ENODATA)
        put_file (stale_path, "", 0);
      pam_syslog (pamh, LOG_ERR, "uid %u: CHANGE_SECRET: %s", uid, g_strerror (e));
      explicit_bzero (s.new_secret, SECRET_LEN);
      goto out;
    }
  /* the bag first, then the identity: a crash between leaves the new bag with the old file, the SEP's state */
  if (!put_file (bag_path, buf, s.bag_len))
    pam_syslog (pamh, LOG_ERR, "uid %u: the rewrapped bag not written", uid);
  if (want)
    {
      memset (identity + APPLE_SEP_BIO_UUID_LEN, 0, SECRET_LEN);
      put_file (pass_path, pass, strlen (pass));
    }
  else
    {
      memcpy (identity + APPLE_SEP_BIO_UUID_LEN, s.new_secret, SECRET_LEN);
      g_unlink (pass_path);
    }
  if (!put_file (id_path, identity, IDENTITY_LEN))
    pam_syslog (pamh, LOG_ERR, "uid %u: the identity not written", uid);
  explicit_bzero (s.new_secret, SECRET_LEN);
  explicit_bzero (identity, IDENTITY_LEN);
  g_unlink (stale_path);
  pam_syslog (pamh, LOG_INFO, "uid %u: the SEP's secret is now %s", uid, want ? "the password's" : "a random one");
out:
  close (fd);
  return PAM_IGNORE;
}
