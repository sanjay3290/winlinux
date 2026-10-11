// Test-only GSS acceptor harness (the server side of a Kerberos handshake),
// built at test time by test/kdc/kdc.ts. It is the independent oracle for
// gss_wrap_iov / gss_unwrap_iov in the addon: it accepts the initiator
// token with a keytab (KRB5_KTNAME), unwraps what the client sealed, and
// seals replies for the client to unwrap. Linux (MIT krb5) only.
//
// Line protocol on stdin/stdout, base64 arguments:
//   accept <token>          -> "token <b64>" or "token -", then "complete 0|1"
//   unwrap <header> <data>  -> "plain <b64>"       (gss_unwrap_iov HEADER|DATA: the
//                              addon's earlier path, kept as the strict oracle)
//   unwrap-token <header> <data> -> "plain <b64>"  (gss_unwrap of header || data: the
//                              addon's current path)
//   wrap <plain>            -> "sealed <hdr> <data>" (gss_wrap_iov HEADER|DATA|PADDING)
//   wrap-plain <plain>      -> "token <b64>"        (gss_wrap: one token, RRC 0)
//   wrap-trailer <plain>    -> "sealed <hdr> <data> <trailer>" (gss_wrap_iov
//                              HEADER|DATA|TRAILER: RRC 0, trailer in its own buffer)
//   mech                    -> "mech <dotted oid>"  (the mechanism of the context)
// Any failure prints "error <text>".
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64_encode(const unsigned char *in, size_t n) {
  char *out = malloc(((n + 2) / 3) * 4 + 1), *p = out;
  for (size_t i = 0; i < n; i += 3) {
    unsigned v = in[i] << 16 | (i + 1 < n ? in[i + 1] << 8 : 0) | (i + 2 < n ? in[i + 2] : 0);
    *p++ = B64[v >> 18 & 63];
    *p++ = B64[v >> 12 & 63];
    *p++ = i + 1 < n ? B64[v >> 6 & 63] : '=';
    *p++ = i + 2 < n ? B64[v & 63] : '=';
  }
  *p = 0;
  return out;
}

static int b64_val(char c) {
  const char *q = strchr(B64, c);
  return q && c ? (int)(q - B64) : -1;
}

static unsigned char *b64_decode(const char *in, size_t *n) {
  size_t len = strlen(in);
  unsigned char *out = malloc(len / 4 * 3 + 3), *p = out;
  unsigned v = 0;
  int bits = 0;
  for (size_t i = 0; i < len; i++) {
    if (in[i] == '=') break;
    int d = b64_val(in[i]);
    if (d < 0) continue;
    v = v << 6 | (unsigned)d;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      *p++ = (unsigned char)(v >> bits & 0xff);
    }
  }
  *n = (size_t)(p - out);
  return out;
}

static void gss_error(const char *what, OM_uint32 major, OM_uint32 minor) {
  OM_uint32 min, ctx = 0;
  gss_buffer_desc msg;
  printf("error %s: major 0x%x minor %u", what, major, minor);
  if (gss_display_status(&min, major, GSS_C_GSS_CODE, GSS_C_NO_OID, &ctx, &msg) == GSS_S_COMPLETE) {
    printf(" (%.*s", (int)msg.length, (char *)msg.value);
    gss_release_buffer(&min, &msg);
    ctx = 0;
    if (gss_display_status(&min, minor, GSS_C_MECH_CODE, GSS_C_NO_OID, &ctx, &msg) == GSS_S_COMPLETE) {
      printf("; %.*s", (int)msg.length, (char *)msg.value);
      gss_release_buffer(&min, &msg);
    }
    printf(")");
  }
  printf("\n");
}

int main(void) {
  gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
  gss_OID mech = GSS_C_NO_OID;
  char line[1 << 20];
  setvbuf(stdout, NULL, _IOLBF, 0);
  while (fgets(line, sizeof line, stdin)) {
    line[strcspn(line, "\r\n")] = 0;
    char *cmd = strtok(line, " ");
    if (!cmd) continue;
    OM_uint32 major, minor;
    if (strcmp(cmd, "accept") == 0) {
      char *tok = strtok(NULL, " ");
      gss_buffer_desc in = GSS_C_EMPTY_BUFFER, out = GSS_C_EMPTY_BUFFER;
      if (tok) in.value = b64_decode(tok, &in.length);
      major = gss_accept_sec_context(&minor, &ctx, GSS_C_NO_CREDENTIAL, &in, GSS_C_NO_CHANNEL_BINDINGS, NULL, &mech,
                                     &out, NULL, NULL, NULL);
      free(in.value);
      if (GSS_ERROR(major)) {
        gss_error("gss_accept_sec_context", major, minor);
        continue;
      }
      if (out.length) {
        char *b = b64_encode(out.value, out.length);
        printf("token %s\n", b);
        free(b);
      } else {
        printf("token -\n");
      }
      gss_release_buffer(&minor, &out);
      printf("complete %d\n", major == GSS_S_COMPLETE ? 1 : 0);
    } else if (strcmp(cmd, "unwrap") == 0) {
      char *h = strtok(NULL, " "), *d = strtok(NULL, " ");
      if (!h || !d) {
        printf("error unwrap needs <header> <data>\n");
        continue;
      }
      gss_iov_buffer_desc iov[2];
      iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
      iov[0].buffer.value = b64_decode(h, &iov[0].buffer.length);
      iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
      iov[1].buffer.value = b64_decode(d, &iov[1].buffer.length);
      int conf = 0;
      major = gss_unwrap_iov(&minor, ctx, &conf, NULL, iov, 2);
      if (GSS_ERROR(major)) {
        gss_error("gss_unwrap_iov", major, minor);
      } else if (!conf) {
        printf("error gss_unwrap_iov: not sealed\n");
      } else {
        char *b = b64_encode(iov[1].buffer.value, iov[1].buffer.length);
        printf("plain %s\n", b);
        free(b);
      }
      free(iov[0].buffer.value);
      free(iov[1].buffer.value);
    } else if (strcmp(cmd, "wrap") == 0) {
      char *p = strtok(NULL, " ");
      gss_iov_buffer_desc iov[3];
      iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER | GSS_IOV_BUFFER_FLAG_ALLOCATE;
      iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
      iov[1].buffer.value = p ? b64_decode(p, &iov[1].buffer.length) : NULL;
      if (!p) iov[1].buffer.length = 0;
      iov[2].type = GSS_IOV_BUFFER_TYPE_PADDING | GSS_IOV_BUFFER_FLAG_ALLOCATE;
      int conf = 0;
      major = gss_wrap_iov(&minor, ctx, 1, GSS_C_QOP_DEFAULT, &conf, iov, 3);
      if (GSS_ERROR(major)) {
        gss_error("gss_wrap_iov", major, minor);
      } else {
        size_t n = iov[1].buffer.length + iov[2].buffer.length;
        unsigned char *data = malloc(n + 1);
        memcpy(data, iov[1].buffer.value, iov[1].buffer.length);
        if (iov[2].buffer.length) memcpy(data + iov[1].buffer.length, iov[2].buffer.value, iov[2].buffer.length);
        char *hb = b64_encode(iov[0].buffer.value, iov[0].buffer.length), *db = b64_encode(data, n);
        printf("sealed %s %s\n", hb, db);
        free(hb);
        free(db);
        free(data);
        gss_release_iov_buffer(&minor, iov, 3);
      }
      free(iov[1].buffer.value);
    } else if (strcmp(cmd, "unwrap-token") == 0) {
      char *h = strtok(NULL, " "), *d = strtok(NULL, " ");
      if (!h || !d) {
        printf("error unwrap-token needs <header> <data>\n");
        continue;
      }
      size_t hn, dn;
      unsigned char *hb = b64_decode(h, &hn), *db = b64_decode(d, &dn);
      gss_buffer_desc in, out = GSS_C_EMPTY_BUFFER;
      in.length = hn + dn;
      in.value = malloc(in.length + 1);
      memcpy(in.value, hb, hn);
      memcpy((unsigned char *)in.value + hn, db, dn);
      int conf = 0;
      major = gss_unwrap(&minor, ctx, &in, &out, &conf, NULL);
      if (major != GSS_S_COMPLETE) {
        gss_error("gss_unwrap", major, minor);
      } else if (!conf) {
        printf("error gss_unwrap: not sealed\n");
      } else {
        char *b = b64_encode(out.value, out.length);
        printf("plain %s\n", b);
        free(b);
        gss_release_buffer(&minor, &out);
      }
      free(in.value);
      free(hb);
      free(db);
    } else if (strcmp(cmd, "wrap-plain") == 0) {
      char *p = strtok(NULL, " ");
      gss_buffer_desc in = GSS_C_EMPTY_BUFFER, out = GSS_C_EMPTY_BUFFER;
      int conf = 0;
      if (p) in.value = b64_decode(p, &in.length);
      major = gss_wrap(&minor, ctx, 1, GSS_C_QOP_DEFAULT, &in, &conf, &out);
      if (GSS_ERROR(major)) {
        gss_error("gss_wrap", major, minor);
      } else {
        char *b = b64_encode(out.value, out.length);
        printf("token %s\n", b);
        free(b);
        gss_release_buffer(&minor, &out);
      }
      free(in.value);
    } else if (strcmp(cmd, "wrap-trailer") == 0) {
      char *p = strtok(NULL, " ");
      gss_iov_buffer_desc iov[3];
      iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER | GSS_IOV_BUFFER_FLAG_ALLOCATE;
      iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
      iov[1].buffer.value = p ? b64_decode(p, &iov[1].buffer.length) : NULL;
      if (!p) iov[1].buffer.length = 0;
      iov[2].type = GSS_IOV_BUFFER_TYPE_TRAILER | GSS_IOV_BUFFER_FLAG_ALLOCATE;
      int conf = 0;
      major = gss_wrap_iov(&minor, ctx, 1, GSS_C_QOP_DEFAULT, &conf, iov, 3);
      if (GSS_ERROR(major)) {
        gss_error("gss_wrap_iov(trailer)", major, minor);
      } else {
        char *hb = b64_encode(iov[0].buffer.value, iov[0].buffer.length);
        char *db = b64_encode(iov[1].buffer.value, iov[1].buffer.length);
        char *tb = b64_encode(iov[2].buffer.value, iov[2].buffer.length);
        printf("sealed %s %s %s\n", hb, db, tb);
        free(hb);
        free(db);
        free(tb);
        gss_release_iov_buffer(&minor, iov, 3);
      }
      free(iov[1].buffer.value);
    } else if (strcmp(cmd, "mech") == 0) {
      gss_buffer_desc str;
      if (mech != GSS_C_NO_OID && gss_oid_to_str(&minor, mech, &str) == GSS_S_COMPLETE) {
        printf("mech %.*s\n", (int)str.length, (char *)str.value);
        gss_release_buffer(&minor, &str);
      } else {
        printf("mech -\n");
      }
    } else {
      printf("error unknown command %s\n", cmd);
    }
  }
  OM_uint32 minor;
  if (ctx != GSS_C_NO_CONTEXT) gss_delete_sec_context(&minor, &ctx, GSS_C_NO_BUFFER);
  return 0;
}
