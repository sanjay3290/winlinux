// @winlinux/krb-session-key: a GSSAPI Kerberos initiator that can hand out
// the context session key (GSS_C_INQ_SSPI_SESSION_KEY).
//
// It drives gss_init_sec_context itself with raw KRB5 mechanism tokens.
// SPNEGO framing stays in @winlinux/auth. Every call that can reach the KDC
// or the ccache (create, step) runs on the libuv thread pool through
// napi_async_work, so the JS thread never blocks on a KDC round trip.
//
// Native exports (the TypeScript wrapper in src/index.ts is the public API):
//   load()                           -> undefined, or throws a clear error
//   create(spn, ccache?, principal?) -> Promise<handle>
//   step(handle, token?)             -> Promise<{ output: Buffer|null, complete }>
//   wrap(handle, data, protect)      -> Promise<Buffer>
//   unwrap(handle, data)             -> Promise<Buffer>
//   hasIov()                         -> boolean (gss_wrap_iov is available)
//   wrapIov(handle, data)            -> Promise<{ header: Buffer, data: Buffer }>
//   unwrapIov(handle, header, data)  -> Promise<Buffer> (gss_unwrap of header || data)
//   sessionKey(handle)               -> Buffer (local call, no I/O)
//   verifyMic(handle, message, mic)  -> boolean (local call, no I/O)
//   release(handle)                  -> undefined
//
// macOS links GSS.framework. Linux loads libgssapi_krb5.so.2 with dlopen on
// first use, so the addon itself loads on hosts without MIT krb5.
#include <node_api.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
#include <GSS/GSS.h>
#include <dlfcn.h>
#else
#include <dlfcn.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#endif

// OIDs by value. Both MIT and Heimdal compare OIDs by content.
static gss_OID_desc OID_NT_HOSTBASED = {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04"};
static gss_OID_desc OID_NT_USER_NAME = {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01"};
static gss_OID_desc OID_MECH_KRB5 = {9, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"};
// 1.2.840.113554.1.2.2.5.5 = GSS_C_INQ_SSPI_SESSION_KEY on MIT and Heimdal.
static gss_OID_desc OID_SSPI_SESSION_KEY = {11, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05"};
static gss_OID_set_desc MECHS_KRB5 = {1, &OID_MECH_KRB5};

#define REQ_FLAGS \
  (GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG)

// ---------------------------------------------------------------------------
// GSS function table. macOS: direct calls. Linux: dlopen + dlsym, once.

#define GSS_FUNCS(V)                 \
  V(gss_import_name)                 \
  V(gss_release_name)                \
  V(gss_init_sec_context)            \
  V(gss_delete_sec_context)          \
  V(gss_release_buffer)              \
  V(gss_display_status)              \
  V(gss_inquire_sec_context_by_oid)  \
  V(gss_release_buffer_set)          \
  V(gss_wrap)                        \
  V(gss_unwrap)                      \
  V(gss_verify_mic)                  \
  V(gss_acquire_cred)                \
  V(gss_release_cred)                \
  V(gss_krb5_ccache_name)

// IOV wrap (RFC 4121 with the trailer rotated into the header), the split
// MS-WSMV needs for Kerberos message encryption over HTTP. Declared here by
// value, not from a header: MIT keeps it in gssapi_ext.h, Heimdal in
// gssapi.h, and Apple GSS.framework exports it without a public prototype.
// The struct layout and the constants are the same in MIT and Heimdal.
// Resolved with dlsym, so a library without it gives hasIov() == false
// rather than a load failure.
typedef struct {
  OM_uint32 type;
  gss_buffer_desc buffer;
} wl_iov;
#define WL_IOV_TYPE_DATA 1
#define WL_IOV_TYPE_HEADER 2
#define WL_IOV_TYPE_PADDING 9
#define WL_IOV_FLAG_ALLOCATE 0x00010000
#define WL_IOV_FLAG_ALLOCATED 0x00020000
#define WL_IOV_TYPE_MASK 0x0000ffff
typedef OM_uint32 (*wl_wrap_iov_fn)(OM_uint32 *, gss_ctx_id_t, int, gss_qop_t, int *, wl_iov *, int);
typedef OM_uint32 (*wl_unwrap_iov_fn)(OM_uint32 *, gss_ctx_id_t, int *, gss_qop_t *, wl_iov *, int);
typedef OM_uint32 (*wl_release_iov_buffer_fn)(OM_uint32 *, wl_iov *, int);
static struct {
  wl_wrap_iov_fn wrap_iov;
  wl_unwrap_iov_fn unwrap_iov;
  wl_release_iov_buffer_fn release_iov_buffer;
} iov_fns;

// Apple's GSS.framework exports its "private" symbols (gssapi_private.h:
// the IOV functions among them) with an __ApplePrivate_ prefix
// (Heimdal packages/mac/build-export-files.sh), so try that name too.
static void *iov_sym(void *handle, const char *name) {
  void *p = dlsym(handle, name);
  if (p) return p;
  char apple[128];
  snprintf(apple, sizeof apple, "__ApplePrivate_%s", name);
  return dlsym(handle, apple);
}

// All three or none: a half-resolved table is treated as missing.
static void resolve_iov(void *handle) {
  iov_fns.wrap_iov = (wl_wrap_iov_fn)iov_sym(handle, "gss_wrap_iov");
  iov_fns.unwrap_iov = (wl_unwrap_iov_fn)iov_sym(handle, "gss_unwrap_iov");
  iov_fns.release_iov_buffer = (wl_release_iov_buffer_fn)iov_sym(handle, "gss_release_iov_buffer");
  if (!iov_fns.wrap_iov || !iov_fns.unwrap_iov || !iov_fns.release_iov_buffer) {
    iov_fns.wrap_iov = NULL;
    iov_fns.unwrap_iov = NULL;
    iov_fns.release_iov_buffer = NULL;
  }
}

static bool has_iov(void) { return iov_fns.wrap_iov != NULL; }

// Whether the GSSAPI library is Heimdal (GSS.framework on macOS is a
// Heimdal fork; on Linux it is a choice, WINLINUX_GSSAPI_LIBRARY). The two
// differ in how gss_krb5_ccache_name is cleared (exec_create).
static bool is_heimdal = false;

#ifdef __APPLE__
#define G(fn) fn
static pthread_once_t iov_once = PTHREAD_ONCE_INIT;
// GSS.framework is linked in, so its symbols are in the default scope;
// an explicit dlopen of the framework is the fallback.
static void resolve_iov_once(void) {
  is_heimdal = true;
  resolve_iov(RTLD_DEFAULT);
  if (has_iov()) return;
  void *h = dlopen("/System/Library/Frameworks/GSS.framework/GSS", RTLD_NOW | RTLD_LOCAL);
  if (h) resolve_iov(h);
}
static const char *load_library(void) {
  pthread_once(&iov_once, resolve_iov_once);
  return NULL;
}
#else
#define GSS_LIBRARY "libgssapi_krb5.so.2"
#define DECLARE_PTR(fn) __typeof__(fn) *fn;
static struct {
  GSS_FUNCS(DECLARE_PTR)
} gss;
#define G(fn) (gss.fn)
static pthread_once_t load_once = PTHREAD_ONCE_INIT;
static char load_error[1024];

static void load_library_once(void) {
  const char *lib = getenv("WINLINUX_GSSAPI_LIBRARY");
  if (!lib || !*lib) lib = GSS_LIBRARY;
  int flags = RTLD_NOW | RTLD_LOCAL;
#ifdef RTLD_DEEPBIND
  // Keep krb5's own symbol bindings (for example its OpenSSL) away from
  // the copies that the node binary exports.
  flags |= RTLD_DEEPBIND;
#endif
  void *h = dlopen(lib, flags);
  if (!h) {
    const char *why = dlerror();
    snprintf(load_error, sizeof load_error,
             "@winlinux/krb-session-key: cannot load the MIT Kerberos GSSAPI library %s (%s). "
             "Install it: libgssapi-krb5-2 (Debian/Ubuntu), krb5-libs (Fedora/RHEL/Alpine).",
             lib, why ? why : "unknown error");
    return;
  }
#define LOAD_SYM(fn)                                                                           \
  gss.fn = (__typeof__(fn) *)dlsym(h, #fn);                                                    \
  if (!gss.fn) {                                                                               \
    snprintf(load_error, sizeof load_error,                                                    \
             "@winlinux/krb-session-key: %s has no symbol %s. Install MIT krb5 1.11 or later.", \
             lib, #fn);                                                                        \
    return;                                                                                    \
  }
  GSS_FUNCS(LOAD_SYM)
#undef LOAD_SYM
  // gsskrb5_set_default_realm exists in Heimdal only; MIT has no such
  // entry point. Heimdal's krb5 and gssapi libraries have the symbol in
  // the same scope the dlopen handle sees.
  is_heimdal = dlsym(h, "gsskrb5_set_default_realm") != NULL;
  resolve_iov(h);
}

static const char *load_library(void) {
  pthread_once(&load_once, load_library_once);
  return load_error[0] ? load_error : NULL;
}
#endif

// gss_krb5_ccache_name changes a default that other callers share
// (process-wide on Heimdal, per thread on MIT). The lock covers the
// set / acquire / clear sequence so concurrent contexts never see each
// other's ccache. The acquired credential keeps its ccache.
static pthread_mutex_t ccache_lock = PTHREAD_MUTEX_INITIALIZER;

// ---------------------------------------------------------------------------
// Context handle.

typedef struct {
  gss_ctx_id_t ctx;
  gss_name_t target;
  gss_cred_id_t cred;
  bool complete;
  bool busy;
  // Channel bindings for every gss_init_sec_context call of this context
  //: no addresses, application_data = the caller's bytes, for
  // example the RFC 5929 tls-server-end-point binding of the TLS server
  // certificate. NULL and 0: GSS_C_NO_CHANNEL_BINDINGS.
  void *cb_data;
  size_t cb_len;
} krb_ctx;

static void release_ctx(krb_ctx *k) {
  OM_uint32 minor;
  if (k->ctx != GSS_C_NO_CONTEXT) G(gss_delete_sec_context)(&minor, &k->ctx, GSS_C_NO_BUFFER);
  if (k->target != GSS_C_NO_NAME) G(gss_release_name)(&minor, &k->target);
  if (k->cred != GSS_C_NO_CREDENTIAL) G(gss_release_cred)(&minor, &k->cred);
  k->ctx = GSS_C_NO_CONTEXT;
  k->target = GSS_C_NO_NAME;
  k->cred = GSS_C_NO_CREDENTIAL;
  k->complete = false;
  free(k->cb_data);
  k->cb_data = NULL;
  k->cb_len = 0;
}

static void finalize_ctx(napi_env env, void *data, void *hint) {
  (void)env;
  (void)hint;
  krb_ctx *k = data;
  release_ctx(k);
  free(k);
}

// ---------------------------------------------------------------------------
// Error text.

static void describe(OM_uint32 code, int type, gss_OID mech, char *out, size_t cap) {
  OM_uint32 minor, more = 0;
  gss_buffer_desc msg;
  size_t used = 0;
  out[0] = 0;
  do {
    if (G(gss_display_status)(&minor, code, type, mech, &more, &msg) != GSS_S_COMPLETE) break;
    size_t n = msg.length;
    if (used + n + 3 >= cap) n = cap - used - 3;
    if (used) {
      out[used++] = ';';
      out[used++] = ' ';
    }
    memcpy(out + used, msg.value, n);
    used += n;
    out[used] = 0;
    G(gss_release_buffer)(&minor, &msg);
  } while (more != 0 && used + 3 < cap);
}

static void format_gss_error(char *out, size_t cap, const char *what, OM_uint32 major, OM_uint32 minor) {
  char maj[400], min[400];
  describe(major, GSS_C_GSS_CODE, GSS_C_NO_OID, maj, sizeof maj);
  describe(minor, GSS_C_MECH_CODE, &OID_MECH_KRB5, min, sizeof min);
  if (minor)
    snprintf(out, cap, "%s: %s (major 0x%x); %s (minor %u)", what, maj, major, min, minor);
  else
    snprintf(out, cap, "%s: %s (major 0x%x)", what, maj, major);
}

static napi_value throw_msg(napi_env env, const char *msg) {
  napi_throw_error(env, NULL, msg);
  return NULL;
}

#define NAPI_CALL(env, call)                                          \
  do {                                                                \
    if ((call) != napi_ok) return throw_msg((env), "N-API call failed: " #call); \
  } while (0)

static napi_value make_buffer(napi_env env, const void *data, size_t len) {
  napi_value buf;
  void *dst;
  if (napi_create_buffer(env, len, &dst, &buf) != napi_ok) return NULL;
  if (len) memcpy(dst, data, len);
  return buf;
}

static napi_value make_error(napi_env env, const char *msg) {
  napi_value text, err;
  napi_create_string_utf8(env, msg, NAPI_AUTO_LENGTH, &text);
  napi_create_error(env, NULL, text, &err);
  return err;
}

static krb_ctx *get_ctx(napi_env env, napi_value v) {
  krb_ctx *k = NULL;
  napi_valuetype t;
  if (napi_typeof(env, v, &t) != napi_ok || t != napi_external ||
      napi_get_value_external(env, v, (void **)&k) != napi_ok || !k) {
    napi_throw_type_error(env, NULL, "expected a krb-session-key context handle");
    return NULL;
  }
  return k;
}

// Copies an optional Buffer argument. Returns false (with a pending
// exception) when the argument is neither a Buffer nor null/undefined.
static bool copy_buffer_arg(napi_env env, napi_value v, void **data, size_t *len) {
  napi_valuetype t;
  *data = NULL;
  *len = 0;
  if (napi_typeof(env, v, &t) != napi_ok) return false;
  if (t == napi_undefined || t == napi_null) return true;
  bool is_buf = false;
  napi_is_buffer(env, v, &is_buf);
  if (!is_buf) {
    napi_throw_type_error(env, NULL, "expected a Buffer");
    return false;
  }
  void *src;
  size_t n;
  if (napi_get_buffer_info(env, v, &src, &n) != napi_ok) return false;
  if (n) {
    *data = malloc(n);
    if (!*data) {
      napi_throw_error(env, NULL, "out of memory");
      return false;
    }
    memcpy(*data, src, n);
  }
  *len = n;
  return true;
}

// Copies an optional string argument (null/undefined -> NULL).
static bool copy_string_arg(napi_env env, napi_value v, char **out) {
  napi_valuetype t;
  *out = NULL;
  if (napi_typeof(env, v, &t) != napi_ok) return false;
  if (t == napi_undefined || t == napi_null) return true;
  if (t != napi_string) {
    napi_throw_type_error(env, NULL, "expected a string");
    return false;
  }
  size_t n;
  if (napi_get_value_string_utf8(env, v, NULL, 0, &n) != napi_ok) return false;
  *out = malloc(n + 1);
  if (!*out) {
    napi_throw_error(env, NULL, "out of memory");
    return false;
  }
  napi_get_value_string_utf8(env, v, *out, n + 1, &n);
  return true;
}

// ---------------------------------------------------------------------------
// Async jobs.

typedef enum { OP_CREATE, OP_STEP, OP_WRAP, OP_UNWRAP, OP_WRAP_IOV, OP_UNWRAP_IOV } op_kind;

typedef struct {
  op_kind op;
  napi_async_work work;
  napi_deferred deferred;
  napi_ref handle_ref;  // keeps the handle alive while the job runs
  krb_ctx *k;
  // inputs
  char *spn, *ccache, *principal;
  void *in;
  size_t in_len;
  void *in2;  // unwrapIov: the header
  size_t in2_len;
  int protect;
  // outputs
  bool failed;
  char error[1400];
  gss_buffer_desc out;
  // wrapIov: HEADER, DATA, PADDING. DATA points into `in` (sealed in
  // place); the others are GSS-allocated.
  wl_iov iov[3];
  int iov_count;
} job;

static void release_iov(wl_iov *iov, int count) {
  OM_uint32 minor;
  bool any = false;
  for (int i = 0; i < count; i++) {
    if ((iov[i].type & WL_IOV_FLAG_ALLOCATED) && iov[i].buffer.value) {
      memset(iov[i].buffer.value, 0, iov[i].buffer.length);
      any = true;
    }
  }
  if (any) iov_fns.release_iov_buffer(&minor, iov, count);
}

static void free_job(napi_env env, job *j) {
  OM_uint32 minor;
  // Wrap/unwrap buffers hold plaintext: zero them before they are freed.
  if (j->out.value) {
    memset(j->out.value, 0, j->out.length);
    G(gss_release_buffer)(&minor, &j->out);
  }
  if (j->iov_count) release_iov(j->iov, j->iov_count);
  if (j->handle_ref) napi_delete_reference(env, j->handle_ref);
  if (j->work) napi_delete_async_work(env, j->work);
  free(j->spn);
  free(j->ccache);
  free(j->principal);
  if (j->in) memset(j->in, 0, j->in_len);
  free(j->in);
  if (j->in2) memset(j->in2, 0, j->in2_len);
  free(j->in2);
  free(j);
}

static void fail(job *j, const char *what, OM_uint32 major, OM_uint32 minor) {
  j->failed = true;
  format_gss_error(j->error, sizeof j->error, what, major, minor);
}

static void exec_create(job *j) {
  krb_ctx *k = j->k;
  OM_uint32 major, minor;
  gss_buffer_desc name = {strlen(j->spn), j->spn};
  major = G(gss_import_name)(&minor, &name, &OID_NT_HOSTBASED, &k->target);
  if (GSS_ERROR(major)) return fail(j, "gss_import_name(service)", major, minor);
  if (!j->ccache && !j->principal) return;  // default credential, like the kerberos package

  gss_name_t desired = GSS_C_NO_NAME;
  if (j->principal) {
    gss_buffer_desc p = {strlen(j->principal), j->principal};
    major = G(gss_import_name)(&minor, &p, &OID_NT_USER_NAME, &desired);
    if (GSS_ERROR(major)) return fail(j, "gss_import_name(principal)", major, minor);
  }
  // Every explicit acquire runs under the lock, so it never sees another
  // context's temporary ccache override (Heimdal keeps it process-wide).
  pthread_mutex_lock(&ccache_lock);
  // The name in force before the override. Both libraries hand back the
  // effective default (for example FILE:/tmp/krb5cc_0), owned by the
  // library: valid until the next call with an out-name, so it is used
  // before any other gss_krb5_ccache_name call, under the lock.
  const char *previous = NULL;
  if (j->ccache) {
    major = G(gss_krb5_ccache_name)(&minor, j->ccache, &previous);
    if (GSS_ERROR(major)) {
      OM_uint32 m2;
      pthread_mutex_unlock(&ccache_lock);
      if (desired != GSS_C_NO_NAME) G(gss_release_name)(&m2, &desired);
      return fail(j, "gss_krb5_ccache_name", major, minor);
    }
  }
  major = G(gss_acquire_cred)(&minor, desired, GSS_C_INDEFINITE, &MECHS_KRB5, GSS_C_INITIATE, &k->cred, NULL,
                              NULL);
  if (j->ccache) {
    // Clear the override. On MIT, NULL means the library default again,
    // and that is the right call: MIT reports the effective default as
    // `previous`, and setting it would pin this pool thread to that
    // ccache and hide later KRB5CCNAME changes. Heimdal (and Apple's
    // GSS.framework) dereferences a NULL name here and crashes the
    // process, so there the previous name goes back; Heimdal's
    // default is process-wide anyway.
    OM_uint32 m2;
    if (!is_heimdal) G(gss_krb5_ccache_name)(&m2, NULL, NULL);
    else if (previous) G(gss_krb5_ccache_name)(&m2, previous, NULL);
  }
  pthread_mutex_unlock(&ccache_lock);
  if (desired != GSS_C_NO_NAME) G(gss_release_name)(&minor, &desired);
  if (GSS_ERROR(major)) {
    k->cred = GSS_C_NO_CREDENTIAL;
    return fail(j, "gss_acquire_cred", major, minor);
  }
}

static void exec_step(job *j) {
  krb_ctx *k = j->k;
  OM_uint32 major, minor;
  gss_buffer_desc in = {j->in_len, j->in};
  // RFC 2744 3.11 channel bindings: unspecified addresses and the
  // caller's application_data. MIT, Heimdal and Windows all put the MD5
  // of the packed structure in the Bnd field of the AP-REQ authenticator
  // checksum (RFC 4121 4.1.1.2), which a server that enforces channel
  // binding (WinRM with CbtHardeningLevel Strict) compares with its own
  // TLS certificate. The same bindings go into every call of the context.
  gss_channel_bindings_t cb = GSS_C_NO_CHANNEL_BINDINGS;
  struct gss_channel_bindings_struct bindings;
  if (k->cb_len) {
    memset(&bindings, 0, sizeof bindings);
    bindings.initiator_addrtype = GSS_C_AF_UNSPEC;
    bindings.acceptor_addrtype = GSS_C_AF_UNSPEC;
    bindings.application_data.length = k->cb_len;
    bindings.application_data.value = k->cb_data;
    cb = &bindings;
  }
  // With the default credential, the first call acquires it from the
  // default ccache. Take the lock so that acquire never sees another
  // context's temporary ccache override (process-wide on Heimdal).
  bool lock = k->cred == GSS_C_NO_CREDENTIAL && k->ctx == GSS_C_NO_CONTEXT;
  if (lock) pthread_mutex_lock(&ccache_lock);
  major = G(gss_init_sec_context)(&minor, k->cred, &k->ctx, k->target, &OID_MECH_KRB5, REQ_FLAGS, 0, cb,
                                  j->in_len ? &in : GSS_C_NO_BUFFER, NULL, &j->out, NULL, NULL);
  if (lock) pthread_mutex_unlock(&ccache_lock);
  if (GSS_ERROR(major)) return fail(j, "gss_init_sec_context", major, minor);
  k->complete = (major == GSS_S_COMPLETE);
}

static void exec_wrap(job *j) {
  OM_uint32 major, minor;
  gss_buffer_desc in = {j->in_len, j->in};
  major = G(gss_wrap)(&minor, j->k->ctx, j->protect, GSS_C_QOP_DEFAULT, &in, NULL, &j->out);
  if (GSS_ERROR(major)) return fail(j, "gss_wrap", major, minor);
}

static void exec_unwrap(job *j) {
  OM_uint32 major, minor;
  gss_buffer_desc in = {j->in_len, j->in};
  major = G(gss_unwrap)(&minor, j->k->ctx, &in, &j->out, NULL, NULL);
  if (GSS_ERROR(major)) return fail(j, "gss_unwrap", major, minor);
}

// gss_wrap_iov with HEADER (allocated) | DATA (in place) | PADDING
// (allocated) and no TRAILER: the mechanism rotates the trailer into the
// header (RFC 4121 4.2.5, RRC), so the DATA buffer stays exactly the
// plaintext length. This is the split MS-WSMV 2.2.9.1.1.2.2 needs, and
// what pyspnego wrap_winrm() does.
static void exec_wrap_iov(job *j) {
  OM_uint32 major, minor;
  int conf = 0;
  j->iov[0].type = WL_IOV_TYPE_HEADER | WL_IOV_FLAG_ALLOCATE;
  j->iov[1].type = WL_IOV_TYPE_DATA;
  j->iov[1].buffer.value = j->in;
  j->iov[1].buffer.length = j->in_len;
  j->iov[2].type = WL_IOV_TYPE_PADDING | WL_IOV_FLAG_ALLOCATE;
  j->iov_count = 3;
  major = iov_fns.wrap_iov(&minor, j->k->ctx, 1, GSS_C_QOP_DEFAULT, &conf, j->iov, 3);
  if (GSS_ERROR(major)) return fail(j, "gss_wrap_iov", major, minor);
  if (!conf) {
    j->failed = true;
    snprintf(j->error, sizeof j->error, "gss_wrap_iov: the context offers no confidentiality");
  }
}

// The inverse, for the MS-WSMV response: HEADER (the encryption header,
// as long as the sender's Length-Field says) and DATA (the sealed bytes
// of OriginalContent Length). header || data is one complete RFC 4121
// wrap token: its RRC field says how far the sender rotated the trailer
// into the header, its EC how much filler it used (4.2.4, 4.2.5). Plain
// gss_unwrap takes any RRC and EC (MIT kg_unseal_v3 and Heimdal
// _gssapi_unwrap_cfx both rotate by RRC, then strip EC + 16), so one
// call covers an MIT, Heimdal or Windows SSPI sender. gss_unwrap_iov with
// HEADER | DATA, the earlier path, does not: MIT accepts only
// RRC == EC + 28, and Apple's GSS.framework (Heimdal before
// heimdal/heimdal#739) refuses the call outright with EINVAL unless a
// PADDING buffer is passed, which is what a Windows reply ran into on
// macOS. A message that was only signed, not sealed, is refused, and so
// is any sequence or replay verdict (GSS_S_DUPLICATE_TOKEN and friends
// are supplementary bits, not errors): on one HTTP connection every
// reply arrives in order, and Heimdal returns no plaintext for them.
static void exec_unwrap_iov(job *j) {
  OM_uint32 major, minor;
  int conf = 0;
  gss_buffer_desc in;
  in.length = j->in2_len + j->in_len;
  in.value = malloc(in.length ? in.length : 1);
  if (!in.value) {
    j->failed = true;
    snprintf(j->error, sizeof j->error, "unwrapIov: out of memory");
    return;
  }
  if (j->in2_len) memcpy(in.value, j->in2, j->in2_len);
  if (j->in_len) memcpy((char *)in.value + j->in2_len, j->in, j->in_len);
  major = G(gss_unwrap)(&minor, j->k->ctx, &in, &j->out, &conf, NULL);
  memset(in.value, 0, in.length);
  free(in.value);
  if (major != GSS_S_COMPLETE) return fail(j, "gss_unwrap(header || data)", major, minor);
  if (!conf) {
    j->failed = true;
    snprintf(j->error, sizeof j->error, "gss_unwrap(header || data): the message was signed but not encrypted");
  }
}

static void execute(napi_env env, void *data) {
  (void)env;
  job *j = data;
  switch (j->op) {
    case OP_CREATE: exec_create(j); break;
    case OP_STEP: exec_step(j); break;
    case OP_WRAP: exec_wrap(j); break;
    case OP_UNWRAP: exec_unwrap(j); break;
    case OP_WRAP_IOV: exec_wrap_iov(j); break;
    case OP_UNWRAP_IOV: exec_unwrap_iov(j); break;
  }
}

static void complete(napi_env env, napi_status status, void *data) {
  job *j = data;
  j->k->busy = false;
  napi_value result = NULL;
  if (status != napi_ok) {
    j->failed = true;
    snprintf(j->error, sizeof j->error, "krb-session-key: async work was cancelled");
  }
  if (!j->failed) {
    switch (j->op) {
      case OP_CREATE:
        napi_get_reference_value(env, j->handle_ref, &result);
        break;
      case OP_STEP: {
        napi_value output, done;
        napi_create_object(env, &result);
        if (j->out.length) output = make_buffer(env, j->out.value, j->out.length);
        else napi_get_null(env, &output);
        napi_get_boolean(env, j->k->complete, &done);
        napi_set_named_property(env, result, "output", output);
        napi_set_named_property(env, result, "complete", done);
        break;
      }
      case OP_WRAP:
      case OP_UNWRAP:
      case OP_UNWRAP_IOV:
        result = make_buffer(env, j->out.value, j->out.length);
        break;
      case OP_WRAP_IOV: {
        // data = sealed DATA || PADDING (empty for AES; the acceptor sees
        // one DATA buffer, as pyspnego sends it).
        const wl_iov *hdr = &j->iov[0], *dat = &j->iov[1], *pad = &j->iov[2];
        size_t n = dat->buffer.length + pad->buffer.length;
        napi_value header = make_buffer(env, hdr->buffer.value, hdr->buffer.length);
        napi_value data = NULL;
        void *dst;
        if (napi_create_buffer(env, n, &dst, &data) == napi_ok) {
          if (dat->buffer.length) memcpy(dst, dat->buffer.value, dat->buffer.length);
          if (pad->buffer.length) memcpy((char *)dst + dat->buffer.length, pad->buffer.value, pad->buffer.length);
        }
        if (header && data && napi_create_object(env, &result) == napi_ok) {
          napi_set_named_property(env, result, "header", header);
          napi_set_named_property(env, result, "data", data);
        } else {
          result = NULL;
        }
        break;
      }
    }
  }
  if (j->failed || !result) {
    napi_reject_deferred(env, j->deferred, make_error(env, j->failed ? j->error : "krb-session-key: no result"));
  } else {
    napi_resolve_deferred(env, j->deferred, result);
  }
  free_job(env, j);
}

// Queues j for `handle`. Returns the promise, or NULL with a pending exception.
static napi_value queue(napi_env env, job *j, napi_value handle, const char *name) {
  napi_value promise, res_name;
  if (napi_create_reference(env, handle, 1, &j->handle_ref) != napi_ok ||
      napi_create_promise(env, &j->deferred, &promise) != napi_ok ||
      napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &res_name) != napi_ok ||
      napi_create_async_work(env, NULL, res_name, execute, complete, j, &j->work) != napi_ok) {
    free_job(env, j);
    return throw_msg(env, "krb-session-key: cannot create async work");
  }
  j->k->busy = true;
  if (napi_queue_async_work(env, j->work) != napi_ok) {
    j->k->busy = false;
    // The promise is already created; reject it so no caller hangs.
    napi_reject_deferred(env, j->deferred, make_error(env, "krb-session-key: cannot queue async work"));
    free_job(env, j);
  }
  return promise;
}

static job *new_job(napi_env env, op_kind op, krb_ctx *k) {
  job *j = calloc(1, sizeof *j);
  if (!j) {
    napi_throw_error(env, NULL, "out of memory");
    return NULL;
  }
  j->op = op;
  j->k = k;
  return j;
}

// Checks the library and that the handle is free for a new operation.
static krb_ctx *ready_ctx(napi_env env, napi_value v, bool need_complete, const char *what) {
  krb_ctx *k = get_ctx(env, v);
  if (!k) return NULL;
  char msg[200];
  if (k->busy) {
    snprintf(msg, sizeof msg, "%s: another operation is still running on this context", what);
    napi_throw_error(env, NULL, msg);
    return NULL;
  }
  if (k->target == GSS_C_NO_NAME) {
    snprintf(msg, sizeof msg, "%s: the context is released", what);
    napi_throw_error(env, NULL, msg);
    return NULL;
  }
  if (need_complete && !k->complete) {
    snprintf(msg, sizeof msg, "%s: the context is not complete", what);
    napi_throw_error(env, NULL, msg);
    return NULL;
  }
  return k;
}

// ---------------------------------------------------------------------------
// JS functions.

static napi_value js_load(napi_env env, napi_callback_info info) {
  (void)info;
  const char *err = load_library();
  if (err) return throw_msg(env, err);
  return NULL;
}

// create(service, ccache?, principal?, channelBindings?): the bindings are
// a Buffer (or null), copied into the context for every step.
static napi_value js_create(napi_env env, napi_callback_info info) {
  size_t argc = 4;
  napi_value argv[4];
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  const char *err = load_library();
  if (err) return throw_msg(env, err);
  napi_value undef;
  napi_get_undefined(env, &undef);
  for (size_t i = argc; i < 4; i++) argv[i] = undef;

  krb_ctx *k = calloc(1, sizeof *k);
  if (!k) return throw_msg(env, "out of memory");
  k->ctx = GSS_C_NO_CONTEXT;
  k->target = GSS_C_NO_NAME;
  k->cred = GSS_C_NO_CREDENTIAL;
  napi_value handle;
  if (napi_create_external(env, k, finalize_ctx, NULL, &handle) != napi_ok) {
    free(k);
    return throw_msg(env, "krb-session-key: cannot create a context handle");
  }
  job *j = new_job(env, OP_CREATE, k);
  if (!j) return NULL;
  if (!copy_string_arg(env, argv[0], &j->spn) || !j->spn || !copy_string_arg(env, argv[1], &j->ccache) ||
      !copy_string_arg(env, argv[2], &j->principal) || !copy_buffer_arg(env, argv[3], &k->cb_data, &k->cb_len)) {
    bool pending = false;
    napi_is_exception_pending(env, &pending);
    free_job(env, j);
    if (!pending) napi_throw_type_error(env, NULL, "create: the service name is required");
    return NULL;
  }
  return queue(env, j, handle, "krbSessionKey.create");
}

static napi_value js_step(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc < 1) return throw_msg(env, "step: a context handle is required");
  krb_ctx *k = ready_ctx(env, argv[0], false, "step");
  if (!k) return NULL;
  if (k->complete) return throw_msg(env, "step: the context is already complete");
  job *j = new_job(env, OP_STEP, k);
  if (!j) return NULL;
  if (argc > 1 && !copy_buffer_arg(env, argv[1], &j->in, &j->in_len)) {
    free_job(env, j);
    return NULL;
  }
  return queue(env, j, argv[0], "krbSessionKey.step");
}

static napi_value wrap_like(napi_env env, napi_callback_info info, op_kind op) {
  size_t argc = 3;
  napi_value argv[3];
  const char *what = op == OP_WRAP ? "wrap" : "unwrap";
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc < 2) return throw_msg(env, "a context handle and a Buffer are required");
  krb_ctx *k = ready_ctx(env, argv[0], true, what);
  if (!k) return NULL;
  job *j = new_job(env, op, k);
  if (!j) return NULL;
  if (!copy_buffer_arg(env, argv[1], &j->in, &j->in_len)) {
    free_job(env, j);
    return NULL;
  }
  if (op == OP_WRAP) {
    bool protect = true;
    if (argc > 2) napi_get_value_bool(env, argv[2], &protect);
    j->protect = protect ? 1 : 0;
  }
  return queue(env, j, argv[0], op == OP_WRAP ? "krbSessionKey.wrap" : "krbSessionKey.unwrap");
}

static napi_value js_wrap(napi_env env, napi_callback_info info) { return wrap_like(env, info, OP_WRAP); }
static napi_value js_unwrap(napi_env env, napi_callback_info info) { return wrap_like(env, info, OP_UNWRAP); }

static napi_value js_has_iov(napi_env env, napi_callback_info info) {
  (void)info;
  const char *err = load_library();
  if (err) return throw_msg(env, err);
  napi_value ok;
  NAPI_CALL(env, napi_get_boolean(env, has_iov(), &ok));
  return ok;
}

static napi_value iov_like(napi_env env, napi_callback_info info, op_kind op) {
  size_t argc = 3;
  napi_value argv[3];
  const char *what = op == OP_WRAP_IOV ? "wrapIov" : "unwrapIov";
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc < (op == OP_WRAP_IOV ? 2u : 3u)) {
    return throw_msg(env, op == OP_WRAP_IOV ? "wrapIov: a context handle and a Buffer are required"
                                            : "unwrapIov: a context handle, a header and a data Buffer are required");
  }
  krb_ctx *k = ready_ctx(env, argv[0], true, what);
  if (!k) return NULL;
  if (!has_iov()) {
    char msg[300];
    snprintf(msg, sizeof msg, "%s: this GSSAPI library has no gss_wrap_iov (MIT krb5 1.8 or later, or Heimdal 1.5 or later)", what);
    return throw_msg(env, msg);
  }
  job *j = new_job(env, op, k);
  if (!j) return NULL;
  bool ok;
  if (op == OP_WRAP_IOV) {
    ok = copy_buffer_arg(env, argv[1], &j->in, &j->in_len);
  } else {
    ok = copy_buffer_arg(env, argv[1], &j->in2, &j->in2_len) && copy_buffer_arg(env, argv[2], &j->in, &j->in_len);
  }
  if (!ok) {
    free_job(env, j);
    return NULL;
  }
  return queue(env, j, argv[0], op == OP_WRAP_IOV ? "krbSessionKey.wrapIov" : "krbSessionKey.unwrapIov");
}

static napi_value js_wrap_iov(napi_env env, napi_callback_info info) { return iov_like(env, info, OP_WRAP_IOV); }
static napi_value js_unwrap_iov(napi_env env, napi_callback_info info) { return iov_like(env, info, OP_UNWRAP_IOV); }

static napi_value js_session_key(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc < 1) return throw_msg(env, "sessionKey: a context handle is required");
  krb_ctx *k = ready_ctx(env, argv[0], true, "sessionKey");
  if (!k) return NULL;

  OM_uint32 major, minor;
  gss_buffer_set_t set = GSS_C_NO_BUFFER_SET;
  major = G(gss_inquire_sec_context_by_oid)(&minor, k->ctx, &OID_SSPI_SESSION_KEY, &set);
  if (GSS_ERROR(major)) {
    char msg[1400];
    format_gss_error(msg, sizeof msg, "gss_inquire_sec_context_by_oid(GSS_C_INQ_SSPI_SESSION_KEY)", major, minor);
    return throw_msg(env, msg);
  }
  if (set == GSS_C_NO_BUFFER_SET || set->count < 1 || set->elements[0].length == 0) {
    if (set != GSS_C_NO_BUFFER_SET) G(gss_release_buffer_set)(&minor, &set);
    return throw_msg(env, "sessionKey: GSS_C_INQ_SSPI_SESSION_KEY returned no key");
  }
  // elements[0] is the key. MIT adds the enctype as a second element.
  napi_value key = make_buffer(env, set->elements[0].value, set->elements[0].length);
  memset(set->elements[0].value, 0, set->elements[0].length);
  G(gss_release_buffer_set)(&minor, &set);
  return key;
}

static napi_value js_verify_mic(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value argv[3];
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc < 3) return throw_msg(env, "verifyMic: a context handle, a message and a MIC are required");
  krb_ctx *k = ready_ctx(env, argv[0], true, "verifyMic");
  if (!k) return NULL;
  bool is_buf1 = false, is_buf2 = false;
  napi_is_buffer(env, argv[1], &is_buf1);
  napi_is_buffer(env, argv[2], &is_buf2);
  if (!is_buf1 || !is_buf2) {
    napi_throw_type_error(env, NULL, "verifyMic: message and MIC must be Buffers");
    return NULL;
  }
  gss_buffer_desc msg, mic;
  NAPI_CALL(env, napi_get_buffer_info(env, argv[1], &msg.value, &msg.length));
  NAPI_CALL(env, napi_get_buffer_info(env, argv[2], &mic.value, &mic.length));
  OM_uint32 minor;
  OM_uint32 major = G(gss_verify_mic)(&minor, k->ctx, &msg, &mic, NULL);
  napi_value ok;
  NAPI_CALL(env, napi_get_boolean(env, major == GSS_S_COMPLETE, &ok));
  return ok;
}

static napi_value js_release(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc < 1) return throw_msg(env, "release: a context handle is required");
  krb_ctx *k = get_ctx(env, argv[0]);
  if (!k) return NULL;
  if (k->busy) return throw_msg(env, "release: another operation is still running on this context");
  if (load_library() == NULL) release_ctx(k);
  return NULL;
}

static napi_value init(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"load", NULL, js_load, NULL, NULL, NULL, napi_default, NULL},
      {"create", NULL, js_create, NULL, NULL, NULL, napi_default, NULL},
      {"step", NULL, js_step, NULL, NULL, NULL, napi_default, NULL},
      {"wrap", NULL, js_wrap, NULL, NULL, NULL, napi_default, NULL},
      {"unwrap", NULL, js_unwrap, NULL, NULL, NULL, napi_default, NULL},
      {"hasIov", NULL, js_has_iov, NULL, NULL, NULL, napi_default, NULL},
      {"wrapIov", NULL, js_wrap_iov, NULL, NULL, NULL, napi_default, NULL},
      {"unwrapIov", NULL, js_unwrap_iov, NULL, NULL, NULL, napi_default, NULL},
      {"sessionKey", NULL, js_session_key, NULL, NULL, NULL, napi_default, NULL},
      {"verifyMic", NULL, js_verify_mic, NULL, NULL, NULL, napi_default, NULL},
      {"release", NULL, js_release, NULL, NULL, NULL, napi_default, NULL},
  };
  napi_define_properties(env, exports, sizeof props / sizeof props[0], props);
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
