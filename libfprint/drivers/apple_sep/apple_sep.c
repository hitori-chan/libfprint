// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Apple Touch ID on the M3 MacBook Pros, through the SEP: the kernel's /dev/apple-sep-bio (drivers/soc/apple/sep).
 *
 * Match on chip: the SEP enrols and matches, and seals for the host what the host keeps across a restart: each
 * component's catacomb (a user's, the system's -1) and the lockout record. They live in STATE_DIR beside each user's
 * identity, which unlocks that user's session in the SEP once a boot (UNLOCK): its UUID and secret, made at the
 * user's first enrolment, and the wrapped key bag the SEP returns for it. Linux has no passcode-derived bag as macOS
 * has: the secret is random and root-only.
 *
 * At a boot's first operation: UNLOCK for the operation's user, then every kept catacomb loaded back (the system's
 * first, the user's last) and the lockout record. One user's session a boot: another user's operation fails until a
 * reboot. A print is the identity the SEP names in a match, {uid, UUID}. Each operation ends with the SEP's save:
 * every record it hands out is on the disk (fsync'd) before the SEP is told so; the lockout record changes with
 * every match, and only the newest loads after a restart.
 *
 * A match names one of the session user's identities, any of their fingers: verify checks it is the print's,
 * identify finds it in the gallery. An enrolment adds a finger to the user's component (loaded at the session's
 * start); delete removes one identity, then saves the catacombs. While the SEP reports the user's matches locked out
 * (after its failed-match limit), a match fails at once, across boots (the saved lockout record restores it); the
 * host's accepting the user's password re-arms them (the password-accepted signal: REARM, then the record saved).
 *
 * The node is there from the kernel's probe (interface version 4): an operation first WAITs for the SEP's bring-up.
 * Version 5 adds REARM and PRESENCE; on an older kernel they answer ENOTTY and the driver goes without.
 */
#define FP_COMPONENT "apple_sep"

#include "drivers_api.h"
#include "apple-sep-bio.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <unistd.h>
#include <glib/gstdio.h>

/* fprintd reads each directory in /var/lib/fprint as a user: the driver keeps its own, a StateDirectory of fprintd too */
#define STATE_DIR "/var/lib/libfprint/apple-sep"
#define BOOT_ID "/proc/sys/kernel/random/boot_id"
/* one CAPTURE's window, for a touch; the operation goes on until a result or a cancel (CANCEL ends a window at once) */
#define CAPTURE_MS 30000
/* the SEP's bring-up after a boot: the sensor and the calibration */
#define READY_WAIT_MS 60000
/* the SEP's enrolment progress runs 0 to 255 (6 used images on this sensor): libfprint's stages */
#define ENROLL_STAGES 6
#define PROGRESS_DONE 255
#define SECRET_LEN 32
/* identity-<uid>.bin: the UUID, the secret, the uid (u32 LE) */
#define IDENTITY_LEN (APPLE_SEP_BIO_UUID_LEN + SECRET_LEN + 4)
#define UID_MIN 10

struct _FpiDeviceAppleSep
{
  FpDevice parent;
  int      fd;
  guint32  version;

  /* the operation in flight */
  guint32  uid;
  gint     stage;
  guint32  nbefore;
  guint8   before[APPLE_SEP_BIO_LIST_MAX][APPLE_SEP_BIO_UUID_LEN];
  struct apple_sep_bio_capture last;
};

G_DECLARE_FINAL_TYPE (FpiDeviceAppleSep, fpi_device_apple_sep, FPI, DEVICE_APPLE_SEP, FpDevice);
G_DEFINE_TYPE (FpiDeviceAppleSep, fpi_device_apple_sep, FP_TYPE_DEVICE);

static const FpIdEntry id_table[] = {
  { .udev_types = FPI_DEVICE_UDEV_SUBTYPE_MISC, .misc_name = "apple-sep-bio" },
  { .udev_types = 0 }
};

/* ---- files ---- */

static gboolean
write_record (const char *path, const guint8 *data, gsize len, GError **error)
{
  g_autofree char *prev = g_strconcat (path, ".prev", NULL);

  /* the record it replaces kept once more; then on the disk before the SEP hears the host holds it */
  if (g_rename (path, prev) != 0 && errno != ENOENT)
    fp_warn ("%s: %s", prev, g_strerror (errno));
  return g_file_set_contents_full (path, (const gchar *) data, len,
                                   G_FILE_SET_CONTENTS_CONSISTENT | G_FILE_SET_CONTENTS_DURABLE, 0600, error);
}

static char *
identity_path (guint32 uid, const char *ext)
{
  return g_strdup_printf (STATE_DIR "/identity-%u.%s", uid, ext);
}

static char *
catacomb_path (gint32 component)
{
  return g_strdup_printf (STATE_DIR "/catacomb-%d.bin", component);
}

static char *
boot_id (void)
{
  char *id = NULL;

  if (!g_file_get_contents (BOOT_ID, &id, NULL, NULL))
    return NULL;
  return g_strstrip (id);
}

/* ---- the device's calls ---- */

static GError *
locked_out_error (void)
{
  return fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                   "Touch ID is locked out after too many failed matches: the user's password re-arms it");
}

static GError *
sep_error (const char *what)
{
  int e = errno;

  return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "%s: %s", what, g_strerror (e));
}

static gboolean
uid_of_name (const char *name, guint32 *uid, GError **error)
{
  struct passwd pw, *res = NULL;
  char buf[1024];

  if (!name || getpwnam_r (name, &pw, buf, sizeof (buf), &res) != 0 || !res)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID, "no such user (%s)",
                   name ? name : "none named");
      return FALSE;
    }
  if (pw.pw_uid < UID_MIN)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED, "user %s: uid %u is a system account",
                   name, (guint) pw.pw_uid);
      return FALSE;
    }
  *uid = pw.pw_uid;
  return TRUE;
}

static gboolean
uid_of_print (FpPrint *print, guint32 *uid, GError **error)
{
  return uid_of_name (fp_print_get_username (print), uid, error);
}

static gboolean
print_identity (FpPrint *print, guint32 *uid, guint8 *uuid)
{
  g_autoptr(GVariant) data = NULL;
  g_autoptr(GVariant) id = NULL;
  const guint8 *p;
  gsize n = 0;

  g_object_get (print, "fpi-data", &data, NULL);
  if (!data || !g_variant_check_format_string (data, "(u@ay)", FALSE))
    return FALSE;
  g_variant_get (data, "(u@ay)", uid, &id);
  p = g_variant_get_fixed_array (id, &n, 1);
  if (n != APPLE_SEP_BIO_UUID_LEN)
    return FALSE;
  memcpy (uuid, p, n);
  return TRUE;
}

static void
print_set_identity (FpPrint *print, guint32 uid, const guint8 *uuid)
{
  GVariant *id = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, uuid, APPLE_SEP_BIO_UUID_LEN, 1);

  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, TRUE);
  g_object_set (print, "fpi-data", g_variant_new ("(u@ay)", uid, id), NULL);
}

static gint
component_order (gconstpointer a, gconstpointer b, gpointer user)
{
  gint32 x = GPOINTER_TO_INT (*(gpointer *) a), y = GPOINTER_TO_INT (*(gpointer *) b), uid = GPOINTER_TO_INT (user);

  /* the system's first, the user's last (biometrickitd's order) */
  if (x == y)
    return 0;
  if (x == -1 || y == uid)
    return -1;
  if (y == -1 || x == uid)
    return 1;
  return x < y ? -1 : 1;
}

static void
load_kept (FpiDeviceAppleSep *self, guint32 uid)
{
  g_autoptr(GDir) dir = g_dir_open (STATE_DIR, 0, NULL);
  g_autoptr(GPtrArray) comps = g_ptr_array_new ();
  g_autofree guint8 *lockout = NULL;
  const char *name;
  gsize len;

  while (dir && (name = g_dir_read_name (dir)))
    {
      gint32 c;
      char end;

      if (sscanf (name, "catacomb-%d.bi%c", &c, &end) == 2 && end == 'n' && g_str_has_suffix (name, ".bin"))
        g_ptr_array_add (comps, GINT_TO_POINTER (c));
    }
  g_ptr_array_sort_with_data (comps, component_order, GINT_TO_POINTER (uid));

  for (guint i = 0; i < comps->len; i++)
    {
      gint32 c = GPOINTER_TO_INT (g_ptr_array_index (comps, i));
      g_autofree char *path = catacomb_path (c);
      g_autofree guint8 *data = NULL;
      struct apple_sep_bio_blob b = { .kind = APPLE_SEP_BIO_CATACOMB, .component = c };

      if (!g_file_get_contents (path, (gchar **) &data, &len, NULL) || len == 0 || len > APPLE_SEP_BIO_BLOB_MAX)
        continue;
      b.len = len;
      b.data = (guintptr) data;
      if (ioctl (self->fd, APPLE_SEP_BIO_LOAD, &b) != 0)
        {
          if (errno != EALREADY)
            fp_warn ("component %d not loaded: %s", c, g_strerror (errno));
        }
      else if (b.status != 0)
        {
          /* the component is now active and empty, and the next save would replace the kept record with it:
           * keep the refused one aside (biometrickitd deletes it) */
          g_autofree char *aside = g_strconcat (path, ".refused", NULL);

          fp_warn ("component %d refused (0x%x): it starts empty; the kept record moved to %s", c, b.status, aside);
          if (g_rename (path, aside) != 0)
            fp_warn ("%s: %s", aside, g_strerror (errno));
        }
    }

  if (g_file_get_contents (STATE_DIR "/lockout.bin", (gchar **) &lockout, &len, NULL) && len > 0 &&
      len <= APPLE_SEP_BIO_BLOB_MAX)
    {
      struct apple_sep_bio_blob b = { .kind = APPLE_SEP_BIO_LOCKOUT, .len = len, .data = (guintptr) lockout };

      if (ioctl (self->fd, APPLE_SEP_BIO_LOAD, &b) != 0)
        fp_warn ("the lockout record not loaded: %s", g_strerror (errno));
      else if (b.status != 0)
        fp_warn ("the lockout record refused (0x%x)", b.status);
    }
}

/*
 * The user's session in the SEP, once a boot: UNLOCK with their identity (made first when create and they have
 * none), then the kept records loaded. STATE_DIR/boot names the boot and the user it was done for.
 */
static gboolean
session_prepare (FpiDeviceAppleSep *self, guint32 uid, gboolean create, GError **error)
{
  struct apple_sep_bio_info info = { 0 };
  struct apple_sep_bio_unlock u = { .uid = uid };
  g_autofree char *boot = boot_id ();
  g_autofree char *kept = NULL;
  g_autofree char *id_path = identity_path (uid, "bin");
  g_autofree char *bag_path = identity_path (uid, "kb");
  g_autofree char *line = NULL;
  g_autofree guint8 *identity = NULL;
  g_autofree guint8 *bag = NULL;
  g_autofree guint8 *buf = NULL;
  gsize len = 0, bag_len = 0;
  gboolean made_bag;
  guint32 wait_ms = READY_WAIT_MS;

  if (self->version >= 4 && ioctl (self->fd, APPLE_SEP_BIO_WAIT, &wait_ms) != 0)
    {
      *error = errno == ENODEV ? fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_OPEN, "the SEP's bring-up stopped") :
                                 sep_error ("WAIT for the SEP's bring-up");
      return FALSE;
    }
  if (ioctl (self->fd, APPLE_SEP_BIO_GET_INFO, &info) != 0)
    {
      *error = sep_error ("GET_INFO");
      return FALSE;
    }
  if (!boot)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL, "no boot ID");
      return FALSE;
    }

  if (info.state & APPLE_SEP_BIO_UNLOCKED)
    {
      char kid[64];
      guint kuid;

      if (g_file_get_contents (STATE_DIR "/boot", &kept, NULL, NULL) &&
          sscanf (kept, "%63s %u", kid, &kuid) == 2 && g_str_equal (kid, boot))
        {
          if (kuid == uid)
            return TRUE;
          g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_BUSY,
                       "the SEP holds user %u's session this boot: user %u's needs a reboot", kuid, uid);
          return FALSE;
        }
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_BUSY,
                   "the SEP's session was unlocked this boot outside this driver");
      return FALSE;
    }

  if (g_mkdir_with_parents (STATE_DIR, 0700) != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL, "%s: %s", STATE_DIR, g_strerror (errno));
      return FALSE;
    }

  if (!g_file_get_contents (id_path, (gchar **) &identity, &len, NULL) || len != IDENTITY_LEN)
    {
      g_clear_pointer (&identity, g_free);
      if (!create)
        {
          g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_NOT_FOUND,
                       "user %u has no Touch ID identity: enrol a finger first", uid);
          return FALSE;
        }
      /* a new identity, kept before the SEP sees it, so a crash after UNLOCK cannot lose its secret */
      identity = g_malloc0 (IDENTITY_LEN);
      if (getrandom (identity, APPLE_SEP_BIO_UUID_LEN + SECRET_LEN, 0) != APPLE_SEP_BIO_UUID_LEN + SECRET_LEN)
        {
          g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL, "getrandom: %s", g_strerror (errno));
          return FALSE;
        }
      identity[6] = (identity[6] & 0x0f) | 0x40;
      identity[8] = (identity[8] & 0x3f) | 0x80;
      identity[48] = uid;
      identity[49] = uid >> 8;
      identity[50] = uid >> 16;
      identity[51] = uid >> 24;
      if (!write_record (id_path, identity, IDENTITY_LEN, error))
        return FALSE;
      g_unlink (bag_path);
    }
  if (GUINT32_FROM_LE (*(guint32 *) (identity + 48)) != uid)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID, "%s names another uid", id_path);
      return FALSE;
    }

  buf = g_malloc0 (APPLE_SEP_BIO_BAG_MAX);
  made_bag = !g_file_get_contents (bag_path, (gchar **) &bag, &bag_len, NULL) || bag_len == 0 ||
             bag_len > APPLE_SEP_BIO_BAG_MAX;
  if (!made_bag)
    memcpy (buf, bag, bag_len);
  memcpy (u.uuid, identity, APPLE_SEP_BIO_UUID_LEN);
  memcpy (u.secret, identity + APPLE_SEP_BIO_UUID_LEN, SECRET_LEN);
  u.bag_len = made_bag ? 0 : bag_len;
  u.bag = (guintptr) buf;
  if (ioctl (self->fd, APPLE_SEP_BIO_UNLOCK, &u) != 0)
    {
      explicit_bzero (&u, sizeof (u));
      explicit_bzero (identity, IDENTITY_LEN);
      *error = sep_error (errno == EIO ? "UNLOCK refused: the identity is spent until a reboot" : "UNLOCK");
      return FALSE;
    }
  explicit_bzero (u.secret, sizeof (u.secret));
  explicit_bzero (identity, IDENTITY_LEN);
  if (made_bag && !write_record (bag_path, buf, u.bag_len, error))
    return FALSE;

  load_kept (self, uid);

  line = g_strdup_printf ("%s %u\n", boot, uid);
  return write_record (STATE_DIR "/boot", (const guint8 *) line, strlen (line), error);
}

/* the save the SEP opens at END: each record on the disk, then confirmed, until none is left */
static gboolean
save_records (FpiDeviceAppleSep *self, GError **error)
{
  g_autofree guint8 *buf = g_malloc (APPLE_SEP_BIO_BLOB_MAX);

  for (;;)
    {
      struct apple_sep_bio_blob b = { .len = APPLE_SEP_BIO_BLOB_MAX, .data = (guintptr) buf };
      g_autofree char *path = NULL;

      if (ioctl (self->fd, APPLE_SEP_BIO_SAVE_NEXT, &b) != 0)
        {
          if (errno == ENODATA)
            return TRUE;
          *error = sep_error ("SAVE_NEXT");
          return FALSE;
        }
      if (b.kind == APPLE_SEP_BIO_CATACOMB)
        path = catacomb_path (b.component);
      else if (b.kind == APPLE_SEP_BIO_LOCKOUT)
        path = g_strdup (STATE_DIR "/lockout.bin");
      else
        {
          g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, "SAVE_NEXT: a record of kind %u", b.kind);
          return FALSE;
        }
      if (!write_record (path, buf, b.len, error))
        return FALSE;
      if (ioctl (self->fd, APPLE_SEP_BIO_SAVE_CONFIRM) != 0)
        {
          *error = sep_error ("SAVE_CONFIRM");
          return FALSE;
        }
    }
}

static gboolean
list_identities (FpiDeviceAppleSep *self, guint32 uid, struct apple_sep_bio_list *l, GError **error)
{
  memset (l, 0, sizeof (*l));
  l->uid = uid;
  if (ioctl (self->fd, APPLE_SEP_BIO_LIST, l) != 0)
    {
      *error = sep_error ("LIST");
      return FALSE;
    }
  if (l->status != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, "LIST: the SEP answered 0x%x", l->status);
      return FALSE;
    }
  l->count = MIN (l->count, APPLE_SEP_BIO_LIST_MAX);
  return TRUE;
}

/* ---- the steps, each in a worker thread ---- */

static void
begin_thread (GTask *task, gpointer source, gpointer data, GCancellable *cancellable)
{
  FpiDeviceAppleSep *self = FPI_DEVICE_APPLE_SEP (source);
  FpiDeviceAction action = GPOINTER_TO_INT (data);
  struct apple_sep_bio_begin b = { .uid = self->uid };
  GError *error = NULL;

  if (!session_prepare (self, self->uid, action == FPI_DEVICE_ACTION_ENROLL, &error))
    {
      g_task_return_error (task, error);
      return;
    }
  /* a lockout record the driver holds newer than the kept one (a match it ran itself for its FIDO2 authenticator,
   * or a save cut short): kept before the operation, which a pending save would refuse */
  if (!save_records (self, &error))
    {
      g_task_return_error (task, error);
      return;
    }
  if (action == FPI_DEVICE_ACTION_ENROLL)
    {
      struct apple_sep_bio_list l;

      if (!list_identities (self, self->uid, &l, &error))
        {
          g_task_return_error (task, error);
          return;
        }
      self->nbefore = l.count;
      for (guint i = 0; i < l.count; i++)
        memcpy (self->before[i], l.id[i].uuid, APPLE_SEP_BIO_UUID_LEN);
    }
  else
    {
      b.flags = APPLE_SEP_BIO_MATCH_UNLOCK;
    }
  if (ioctl (self->fd, action == FPI_DEVICE_ACTION_ENROLL ? APPLE_SEP_BIO_ENROL : APPLE_SEP_BIO_MATCH, &b) != 0)
    {
      if (action != FPI_DEVICE_ACTION_ENROLL && errno == EPERM)
        g_task_return_error (task, locked_out_error ());
      else
        g_task_return_error (task, sep_error (action == FPI_DEVICE_ACTION_ENROLL ? "ENROL" : "MATCH"));
      return;
    }
  g_task_return_boolean (task, TRUE);
}

static void
capture_thread (GTask *task, gpointer source, gpointer data, GCancellable *cancellable)
{
  FpiDeviceAppleSep *self = FPI_DEVICE_APPLE_SEP (source);
  struct apple_sep_bio_capture c = { .timeout_ms = CAPTURE_MS };

  if (ioctl (self->fd, APPLE_SEP_BIO_CAPTURE, &c) != 0)
    {
      g_task_return_error (task, sep_error ("CAPTURE"));
      return;
    }
  self->last = c;
  g_task_return_boolean (task, TRUE);
}

/* END, the save, and after an enrolment the new identity's UUID (the one LIST did not show before) */
static void
finish_thread (GTask *task, gpointer source, gpointer data, GCancellable *cancellable)
{
  FpiDeviceAppleSep *self = FPI_DEVICE_APPLE_SEP (source);
  gboolean enrolled = GPOINTER_TO_INT (data);
  struct apple_sep_bio_list l;
  GError *error = NULL;

  if (ioctl (self->fd, APPLE_SEP_BIO_END) != 0)
    {
      g_task_return_error (task, sep_error ("END"));
      return;
    }
  if (!save_records (self, &error))
    {
      g_task_return_error (task, error);
      return;
    }
  if (enrolled)
    {
      if (!list_identities (self, self->uid, &l, &error))
        {
          g_task_return_error (task, error);
          return;
        }
      for (guint i = 0; i < l.count; i++)
        {
          gboolean seen = FALSE;

          for (guint j = 0; j < self->nbefore && !seen; j++)
            seen = memcmp (l.id[i].uuid, self->before[j], APPLE_SEP_BIO_UUID_LEN) == 0;
          if (!seen)
            {
              memcpy (self->last.uuid, l.id[i].uuid, APPLE_SEP_BIO_UUID_LEN);
              g_task_return_boolean (task, TRUE);
              return;
            }
        }
      g_task_return_new_error (task, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                               "the enrolment completed but LIST shows no new identity");
      return;
    }
  g_task_return_boolean (task, TRUE);
}

static void
run (FpiDeviceAppleSep *self, GTaskThreadFunc func, gpointer data, GAsyncReadyCallback cb)
{
  g_autoptr(GTask) task = g_task_new (self, NULL, cb, NULL);

  g_task_set_task_data (task, data, NULL);
  g_task_run_in_thread (task, func);
}

/* ---- the operations ---- */

static void capture_done (GObject *source, GAsyncResult *res, gpointer user);

static void
fail (FpiDeviceAppleSep *self, GError *error)
{
  FpDevice *dev = FP_DEVICE (self);
  FpiDeviceAction action = fpi_device_get_current_action (dev);

  if (action == FPI_DEVICE_ACTION_ENROLL)
    fpi_device_enroll_complete (dev, NULL, error);
  else if (action == FPI_DEVICE_ACTION_VERIFY)
    fpi_device_verify_complete (dev, error);
  else if (action == FPI_DEVICE_ACTION_IDENTIFY)
    fpi_device_identify_complete (dev, error);
  else
    fpi_device_action_error (dev, error);
}

static void
finish_done (GObject *source, GAsyncResult *res, gpointer user)
{
  FpiDeviceAppleSep *self = FPI_DEVICE_APPLE_SEP (source);
  FpDevice *dev = FP_DEVICE (self);
  struct apple_sep_bio_capture *c = &self->last;
  FpiDeviceAction action;
  GError *error = NULL;

  if (!g_task_propagate_boolean (G_TASK (res), &error))
    {
      fail (self, error);
      return;
    }
  if (c->result == APPLE_SEP_BIO_CANCELLED)
    {
      fail (self, g_error_new (G_IO_ERROR, G_IO_ERROR_CANCELLED, "cancelled"));
      return;
    }
  if (c->result == APPLE_SEP_BIO_LOCKED_OUT)
    {
      fail (self, locked_out_error ());
      return;
    }
  if (c->result == APPLE_SEP_BIO_FAILED)
    {
      fail (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "the SEP refused a step (0x%x)", c->status));
      return;
    }

  action = fpi_device_get_current_action (dev);
  if (action == FPI_DEVICE_ACTION_ENROLL)
    {
      FpPrint *print = NULL;

      fpi_device_get_enroll_data (dev, &print);
      print_set_identity (print, self->uid, c->uuid);
      while (self->stage < ENROLL_STAGES)
        fpi_device_enroll_progress (dev, ++self->stage, print, NULL);
      fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
    }
  else if (action == FPI_DEVICE_ACTION_VERIFY)
    {
      FpPrint *print = NULL;
      guint32 uid = 0;
      guint8 uuid[APPLE_SEP_BIO_UUID_LEN];
      gboolean ok;

      fpi_device_get_verify_data (dev, &print);
      ok = c->result == APPLE_SEP_BIO_MATCHED && print_identity (print, &uid, uuid) && uid == c->uid &&
           memcmp (uuid, c->uuid, sizeof (uuid)) == 0;
      fpi_device_verify_report (dev, ok ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL, NULL, NULL);
      fpi_device_verify_complete (dev, NULL);
    }
  else
    {
      GPtrArray *prints = NULL;
      FpPrint *match = NULL;

      fpi_device_get_identify_data (dev, &prints);
      for (guint i = 0; c->result == APPLE_SEP_BIO_MATCHED && i < prints->len && !match; i++)
        {
          FpPrint *p = g_ptr_array_index (prints, i);
          guint32 uid = 0;
          guint8 uuid[APPLE_SEP_BIO_UUID_LEN];

          if (print_identity (p, &uid, uuid) && uid == c->uid && memcmp (uuid, c->uuid, sizeof (uuid)) == 0)
            match = p;
        }
      fpi_device_identify_report (dev, match, NULL, NULL);
      fpi_device_identify_complete (dev, NULL);
    }
}

static void
capture_next (FpiDeviceAppleSep *self)
{
  run (self, capture_thread, NULL, capture_done);
}

static void
finish (FpiDeviceAppleSep *self, gboolean enrolled)
{
  run (self, finish_thread, GINT_TO_POINTER (enrolled), finish_done);
}

static void
capture_done (GObject *source, GAsyncResult *res, gpointer user)
{
  FpiDeviceAppleSep *self = FPI_DEVICE_APPLE_SEP (source);
  FpDevice *dev = FP_DEVICE (self);
  gboolean enrol = fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_ENROLL;
  struct apple_sep_bio_capture *c = &self->last;
  GError *error = NULL;

  if (!g_task_propagate_boolean (G_TASK (res), &error))
    {
      /* the operation stays open in the kernel: END closes it before the error is reported */
      c->result = APPLE_SEP_BIO_FAILED;
      c->status = 0;
      fp_warn ("%s", error->message);
      g_clear_error (&error);
      finish (self, FALSE);
      return;
    }

  switch (c->result)
    {
    case APPLE_SEP_BIO_NO_FINGER:
      capture_next (self);
      return;

    case APPLE_SEP_BIO_RETRY:
      if (enrol)
        fpi_device_enroll_progress (dev, self->stage, NULL, fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
      capture_next (self);
      return;

    case APPLE_SEP_BIO_ENROL_STEP:
      {
        gint stage = MIN ((gint) c->progress * ENROLL_STAGES / PROGRESS_DONE, ENROLL_STAGES - 1);

        if (enrol && stage > self->stage)
          {
            self->stage = stage;
            fpi_device_enroll_progress (dev, stage, NULL, NULL);
          }
        capture_next (self);
        return;
      }

    case APPLE_SEP_BIO_NO_MATCH:
      if (enrol)
        break;
      /* a usable image matched no identity: the attempt fails, as a match on macOS does */
      finish (self, FALSE);
      return;

    case APPLE_SEP_BIO_ENROL_DONE:
      finish (self, enrol);
      return;

    case APPLE_SEP_BIO_MATCHED:
      if (enrol)
        break;
      finish (self, FALSE);
      return;

    case APPLE_SEP_BIO_CANCELLED:
    case APPLE_SEP_BIO_FAILED:
    case APPLE_SEP_BIO_LOCKED_OUT:
      finish (self, FALSE);
      return;
    }

  c->status = 0;
  fp_warn ("CAPTURE: result %u out of place", c->result);
  c->result = APPLE_SEP_BIO_FAILED;
  finish (self, FALSE);
}

static void
begin_done (GObject *source, GAsyncResult *res, gpointer user)
{
  FpiDeviceAppleSep *self = FPI_DEVICE_APPLE_SEP (source);
  GError *error = NULL;

  if (!g_task_propagate_boolean (G_TASK (res), &error))
    {
      fail (self, error);
      return;
    }
  capture_next (self);
}

static void
begin (FpiDeviceAppleSep *self, FpPrint *print, FpiDeviceAction action)
{
  GError *error = NULL;

  memset (&self->last, 0, sizeof (self->last));
  self->stage = 0;
  self->nbefore = 0;
  if (!print || !uid_of_print (print, &self->uid, &error))
    {
      fail (self, error ? error : fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
      return;
    }
  run (self, begin_thread, GINT_TO_POINTER (action), begin_done);
}

static void
apple_sep_enroll (FpDevice *dev)
{
  FpPrint *print = NULL;

  fpi_device_get_enroll_data (dev, &print);
  begin (FPI_DEVICE_APPLE_SEP (dev), print, FPI_DEVICE_ACTION_ENROLL);
}

static void
apple_sep_verify (FpDevice *dev)
{
  FpPrint *print = NULL;

  fpi_device_get_verify_data (dev, &print);
  begin (FPI_DEVICE_APPLE_SEP (dev), print, FPI_DEVICE_ACTION_VERIFY);
}

/*
 * PRESENCE: one touch and its lift, nothing sent to the SEP, window after window until a touch or a cancel; ENOTTY
 * from a kernel without it
 */
static void
presence_thread (GTask *task, gpointer source, gpointer data, GCancellable *cancellable)
{
  FpiDeviceAppleSep *self = FPI_DEVICE_APPLE_SEP (source);
  struct apple_sep_bio_capture c;

  do
    {
      c = (struct apple_sep_bio_capture) { .timeout_ms = CAPTURE_MS };
      if (ioctl (self->fd, APPLE_SEP_BIO_PRESENCE, &c) != 0)
        {
          if (errno == ENOTTY)
            g_task_return_new_error (task, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED, "PRESENCE: not in this kernel");
          else
            g_task_return_error (task, sep_error ("PRESENCE"));
          return;
        }
    }
  while (c.result == APPLE_SEP_BIO_NO_FINGER);
  self->last = c;
  g_task_return_boolean (task, TRUE);
}

static void
presence_done (GObject *source, GAsyncResult *res, gpointer user)
{
  FpDevice *dev = FP_DEVICE (source);
  guint32 result = FPI_DEVICE_APPLE_SEP (source)->last.result;
  GError *error = NULL;

  if (!g_task_propagate_boolean (G_TASK (res), &error))
    {
      if (g_error_matches (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED))
        {
          /* a kernel without PRESENCE: no match, with no touch */
          g_clear_error (&error);
          fpi_device_identify_report (dev, NULL, NULL, NULL);
        }
      fpi_device_identify_complete (dev, error);
      return;
    }
  if (result == APPLE_SEP_BIO_CANCELLED)
    error = g_error_new (G_IO_ERROR, G_IO_ERROR_CANCELLED, "cancelled");
  else if (result != APPLE_SEP_BIO_TOUCH)
    error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "PRESENCE: result %u", result);
  else
    fpi_device_identify_report (dev, NULL, NULL, NULL);
  fpi_device_identify_complete (dev, error);
}

static void
apple_sep_identify (FpDevice *dev)
{
  GPtrArray *prints = NULL;

  fpi_device_get_identify_data (dev, &prints);
  if (!prints || prints->len == 0)
    {
      /* nothing to match against (fprintd's duplicate check before a first enrolment): a touch and no match, as an
       * image reader scans and compares with nothing */
      run (FPI_DEVICE_APPLE_SEP (dev), presence_thread, NULL, presence_done);
      return;
    }
  /* one user's session a boot: the gallery's first print names it */
  begin (FPI_DEVICE_APPLE_SEP (dev), g_ptr_array_index (prints, 0), FPI_DEVICE_ACTION_IDENTIFY);
}

static void
delete_thread (GTask *task, gpointer source, gpointer data, GCancellable *cancellable)
{
  FpiDeviceAppleSep *self = FPI_DEVICE_APPLE_SEP (source);
  struct apple_sep_bio_identity id = { 0 };
  GError *error = NULL;

  if (!print_identity (data, &id.uid, id.uuid))
    {
      g_task_return_new_error (task, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID, "not an apple_sep print");
      return;
    }
  if (!session_prepare (self, id.uid, FALSE, &error))
    {
      g_task_return_error (task, error);
      return;
    }
  if (ioctl (self->fd, APPLE_SEP_BIO_DELETE, &id) != 0)
    {
      if (errno == ENOENT)
        {
          /* the SEP refused it: it holds no such identity (its status is in the kernel's log) */
          fp_info ("DELETE: the SEP holds no such identity of user %u", id.uid);
          g_task_return_boolean (task, TRUE);
          return;
        }
      g_task_return_error (task, sep_error ("DELETE"));
      return;
    }
  if (!save_records (self, &error))
    {
      g_task_return_error (task, error);
      return;
    }
  g_task_return_boolean (task, TRUE);
}

static void
delete_done (GObject *source, GAsyncResult *res, gpointer user)
{
  GError *error = NULL;

  g_task_propagate_boolean (G_TASK (res), &error);
  fpi_device_delete_complete (FP_DEVICE (source), error);
}

static void
apple_sep_delete (FpDevice *dev)
{
  FpPrint *print = NULL;

  fpi_device_get_delete_data (dev, &print);
  run (FPI_DEVICE_APPLE_SEP (dev), delete_thread, print, delete_done);
}

/*
 * The host has accepted the user's password (the SEP never sees it): REARM sends their session's unlock again, as
 * macOS's lock screen does after the password, which clears a lockout of their matches; then the save it opens of
 * the lockout record alone, so that the next boot's load does not bring the lockout back. The user's session comes
 * first, as for a match (once a boot: UNLOCK and the kept records loaded, which restores a saved lockout).
 */
static gboolean
rearm (FpiDeviceAppleSep *self, guint32 uid, GError **error)
{
  if (!session_prepare (self, uid, FALSE, error))
    return FALSE;
  if (ioctl (self->fd, APPLE_SEP_BIO_REARM, &uid) != 0)
    {
      if (errno == ENOTTY)
        g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED, "REARM: not in this kernel");
      else
        *error = sep_error ("REARM");
      return FALSE;
    }
  return save_records (self, error);
}

/*
 * The "password-accepted" action signal's handler (fprintd's Device.PasswordAccepted emits it). The device must be
 * open and idle. It blocks for its ioctls, well under a second once the bring-up is done (the boot's first one
 * waits for it). TRUE when done or when there is nothing to do: a kernel without REARM, a user with no identity here
 * (never enrolled) or a system account.
 */
static gboolean
apple_sep_password_accepted (FpiDeviceAppleSep *self, const char *username, gpointer user_data)
{
  FpDevice *dev = FP_DEVICE (self);

  g_autoptr(GError) error = NULL;
  guint32 uid = 0;

  if (!fp_device_is_open (dev) || self->fd < 0 || fpi_device_get_current_action (dev) != FPI_DEVICE_ACTION_NONE)
    {
      fp_warn ("password accepted for %s: the device is not open and idle", username ? username : "none named");
      return FALSE;
    }
  if (uid_of_name (username, &uid, &error) && rearm (self, uid, &error))
    {
      fp_dbg ("password accepted for %s: uid %u re-armed, the lockout record saved", username, uid);
      return TRUE;
    }
  if (g_error_matches (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED) ||
      g_error_matches (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_NOT_FOUND))
    {
      fp_dbg ("password accepted for %s: nothing to re-arm (%s)", username, error->message);
      return TRUE;
    }
  fp_warn ("password accepted for %s: %s", username ? username : "none named", error->message);
  return FALSE;
}

static void
apple_sep_cancel (FpDevice *dev)
{
  FpiDeviceAppleSep *self = FPI_DEVICE_APPLE_SEP (dev);

  /* the blocked CAPTURE answers CANCELLED; END and the save follow as for any end */
  if (self->fd >= 0 && ioctl (self->fd, APPLE_SEP_BIO_CANCEL) != 0)
    fp_warn ("CANCEL: %s", g_strerror (errno));
}

static void
apple_sep_open (FpDevice *dev)
{
  FpiDeviceAppleSep *self = FPI_DEVICE_APPLE_SEP (dev);
  const char *path = fpi_device_get_udev_data (dev, FPI_DEVICE_UDEV_SUBTYPE_MISC);
  struct apple_sep_bio_info info = { 0 };

  self->fd = open (path, O_RDWR | O_CLOEXEC);
  if (self->fd < 0)
    {
      fpi_device_open_complete (dev, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "%s: %s", path,
                                                               g_strerror (errno)));
      return;
    }
  /* 3: the node only once the bring-up is done; 4: from probe, with WAIT. A later version only adds requests. */
  if (ioctl (self->fd, APPLE_SEP_BIO_GET_INFO, &info) != 0 || info.version < 3)
    {
      GError *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED, "%s: interface version %u, not 3 or later",
                                                path, info.version);

      close (self->fd);
      self->fd = -1;
      fpi_device_open_complete (dev, error);
      return;
    }
  self->version = info.version;
  fp_dbg ("%s: interface %u, state %#x, sensor %#x", path, info.version, info.state, info.sensor_id);
  fpi_device_open_complete (dev, NULL);
}

static void
apple_sep_close (FpDevice *dev)
{
  FpiDeviceAppleSep *self = FPI_DEVICE_APPLE_SEP (dev);

  if (self->fd >= 0)
    close (self->fd);
  self->fd = -1;
  fpi_device_close_complete (dev, NULL);
}

static void
fpi_device_apple_sep_init (FpiDeviceAppleSep *self)
{
  self->fd = -1;
}

static void
fpi_device_apple_sep_class_init (FpiDeviceAppleSepClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = "Apple Touch ID (SEP)";
  dev_class->type = FP_DEVICE_TYPE_UDEV;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = ENROLL_STAGES;
  dev_class->temp_hot_seconds = -1;

  dev_class->open = apple_sep_open;
  dev_class->close = apple_sep_close;
  dev_class->enroll = apple_sep_enroll;
  dev_class->verify = apple_sep_verify;
  dev_class->identify = apple_sep_identify;
  dev_class->delete = apple_sep_delete;
  dev_class->cancel = apple_sep_cancel;

  fpi_device_class_auto_initialize_features (dev_class);

  /*
   * password-accepted (gchar *username) -> gboolean: the host has accepted the user's password. An action signal,
   * so that fprintd reaches it by name without libfprint API: it emits it only where g_signal_lookup() finds it.
   */
  g_signal_new_class_handler ("password-accepted", G_TYPE_FROM_CLASS (klass),
                              G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
                              G_CALLBACK (apple_sep_password_accepted),
                              NULL, NULL, NULL,
                              G_TYPE_BOOLEAN, 1, G_TYPE_STRING);
}
