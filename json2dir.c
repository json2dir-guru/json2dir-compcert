/* json2dir: create the directory tree a JSON document describes, in the current directory.
 * Implements RFC J2D-1 (https://github.com/kitsunoff/awesome-json2dir/blob/main/spec/rfc-json2dir.md).
 * ISO C99 + POSIX, written for CompCert (ccomp); hand-written UTF-8 check and JSON parser. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

enum kind { K_OBJ, K_STR, K_ARR };

struct node {
  enum kind kind;
  char *str;               /* K_STR: content */
  size_t len;
  char **names;            /* K_OBJ: member names / K_ARR: unused */
  size_t *name_lens;
  struct node **kids;      /* K_OBJ: member values / K_ARR: elements */
  size_t count, cap;
};

static void fail(const char *msg, const char *detail) {
  if (detail != NULL)
    fprintf(stderr, "json2dir: %s: %s\n", msg, detail);
  else
    fprintf(stderr, "json2dir: %s\n", msg);
  exit(1);
}

static void *xrealloc(void *p, size_t n) {
  void *q = realloc(p, n == 0 ? 1 : n);
  if (q == NULL) fail("out of memory", NULL);
  return q;
}

/* ---------- input ---------- */

static unsigned char *in;
static size_t in_len, pos;

static void read_stdin(void) {
  size_t cap = 65536;
  in = xrealloc(NULL, cap);
  in_len = 0;
  for (;;) {
    ssize_t n;
    if (in_len == cap) {
      cap *= 2;
      in = xrealloc(in, cap);
    }
    n = read(0, in + in_len, cap - in_len);
    if (n < 0) {
      if (errno == EINTR) continue;
      fail("cannot read standard input", strerror(errno));
    }
    if (n == 0) break;
    in_len += (size_t)n;
  }
}

/* §3: strict UTF-8 (no overlong forms, no surrogates, nothing above U+10FFFF). */
static void check_utf8(const unsigned char *s, size_t n) {
  size_t i = 0;
  while (i < n) {
    unsigned c = s[i];
    size_t need, k;
    unsigned cp, min;
    if (c < 0x80) { i++; continue; }
    if (c >= 0xC2 && c <= 0xDF) { need = 1; cp = c & 0x1F; min = 0x80; }
    else if (c >= 0xE0 && c <= 0xEF) { need = 2; cp = c & 0x0F; min = 0x800; }
    else if (c >= 0xF0 && c <= 0xF4) { need = 3; cp = c & 0x07; min = 0x10000; }
    else fail("input is not valid UTF-8", NULL);
    if (n - i <= need) fail("input is not valid UTF-8", NULL);
    for (k = 1; k <= need; k++) {
      unsigned d = s[i + k];
      if ((d & 0xC0) != 0x80) fail("input is not valid UTF-8", NULL);
      cp = (cp << 6) | (d & 0x3F);
    }
    if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
      fail("input is not valid UTF-8", NULL);
    i += need + 1;
  }
}

/* ---------- JSON parser ---------- */

static void bad_json(const char *why) {
  char buf[64];
  snprintf(buf, sizeof buf, "%s at byte %lu", why, (unsigned long)pos);
  fail("input is not valid JSON", buf);
}

static void skip_ws(void) {
  while (pos < in_len && (in[pos] == ' ' || in[pos] == '\t' || in[pos] == '\n' || in[pos] == '\r')) pos++;
}

static struct node *new_node(enum kind k) {
  struct node *n = xrealloc(NULL, sizeof *n);
  memset(n, 0, sizeof *n);
  n->kind = k;
  return n;
}

static int hexval(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static unsigned read_hex4(void) {
  unsigned v = 0;
  int i;
  if (in_len - pos < 4) bad_json("truncated \\u escape");
  for (i = 0; i < 4; i++) {
    int h = hexval(in[pos + (size_t)i]);
    if (h < 0) bad_json("bad \\u escape");
    v = v * 16 + (unsigned)h;
  }
  pos += 4;
  return v;
}

/* Parses a JSON string at pos (which is on the opening quote); returns malloc'd bytes. */
static char *parse_string(size_t *out_len) {
  size_t cap = 16, len = 0;
  char *buf = xrealloc(NULL, cap);
  pos++; /* opening quote */
  for (;;) {
    unsigned char c;
    unsigned char enc[4];
    size_t enc_len = 0, i;
    if (pos >= in_len) bad_json("unterminated string");
    c = in[pos];
    if (c == '"') { pos++; break; }
    if (c < 0x20) bad_json("control character in string");
    if (c != '\\') {
      enc[0] = c;
      enc_len = 1;
      pos++;
    } else {
      unsigned cp;
      pos++;
      if (pos >= in_len) bad_json("unterminated string");
      c = in[pos++];
      switch (c) {
        case '"': cp = '"'; break;
        case '\\': cp = '\\'; break;
        case '/': cp = '/'; break;
        case 'b': cp = 8; break;
        case 'f': cp = 12; break;
        case 'n': cp = 10; break;
        case 'r': cp = 13; break;
        case 't': cp = 9; break;
        case 'u':
          cp = read_hex4();
          if (cp >= 0xDC00 && cp <= 0xDFFF) fail("string contains an unpaired surrogate", NULL);
          if (cp >= 0xD800 && cp <= 0xDBFF) {
            unsigned lo;
            if (in_len - pos < 2 || in[pos] != '\\' || in[pos + 1] != 'u')
              fail("string contains an unpaired surrogate", NULL);
            pos += 2;
            lo = read_hex4();
            if (lo < 0xDC00 || lo > 0xDFFF) fail("string contains an unpaired surrogate", NULL);
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
          }
          break;
        default:
          bad_json("bad escape");
          cp = 0;
      }
      if (cp < 0x80) { enc[0] = (unsigned char)cp; enc_len = 1; }
      else if (cp < 0x800) {
        enc[0] = (unsigned char)(0xC0 | (cp >> 6));
        enc[1] = (unsigned char)(0x80 | (cp & 0x3F));
        enc_len = 2;
      } else if (cp < 0x10000) {
        enc[0] = (unsigned char)(0xE0 | (cp >> 12));
        enc[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        enc[2] = (unsigned char)(0x80 | (cp & 0x3F));
        enc_len = 3;
      } else {
        enc[0] = (unsigned char)(0xF0 | (cp >> 18));
        enc[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
        enc[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        enc[3] = (unsigned char)(0x80 | (cp & 0x3F));
        enc_len = 4;
      }
    }
    if (len + enc_len > cap) {
      cap *= 2;
      buf = xrealloc(buf, cap);
    }
    for (i = 0; i < enc_len; i++) buf[len++] = (char)enc[i];
  }
  *out_len = len;
  return buf;
}

static void push_kid(struct node *n, char *name, size_t name_len, struct node *kid) {
  if (n->count == n->cap) {
    n->cap = n->cap ? n->cap * 2 : 4;
    n->names = xrealloc(n->names, n->cap * sizeof *n->names);
    n->name_lens = xrealloc(n->name_lens, n->cap * sizeof *n->name_lens);
    n->kids = xrealloc(n->kids, n->cap * sizeof *n->kids);
  }
  n->names[n->count] = name;
  n->name_lens[n->count] = name_len;
  n->kids[n->count] = kid;
  n->count++;
}

static struct node *parse_value(void);

static struct node *parse_object(void) {
  struct node *n = new_node(K_OBJ);
  pos++; /* { */
  skip_ws();
  if (pos < in_len && in[pos] == '}') { pos++; return n; }
  for (;;) {
    char *name;
    size_t name_len;
    struct node *kid;
    skip_ws();
    if (pos >= in_len || in[pos] != '"') bad_json("expected a member name");
    name = parse_string(&name_len);
    skip_ws();
    if (pos >= in_len || in[pos] != ':') bad_json("expected ':'");
    pos++;
    kid = parse_value();
    push_kid(n, name, name_len, kid);
    skip_ws();
    if (pos < in_len && in[pos] == ',') { pos++; continue; }
    if (pos < in_len && in[pos] == '}') { pos++; return n; }
    bad_json("expected ',' or '}'");
  }
}

static struct node *parse_array(void) {
  struct node *n = new_node(K_ARR);
  pos++; /* [ */
  skip_ws();
  if (pos < in_len && in[pos] == ']') { pos++; return n; }
  for (;;) {
    push_kid(n, NULL, 0, parse_value());
    skip_ws();
    if (pos < in_len && in[pos] == ',') { pos++; continue; }
    if (pos < in_len && in[pos] == ']') { pos++; return n; }
    bad_json("expected ',' or ']'");
  }
}

static struct node *parse_value(void) {
  skip_ws();
  if (pos >= in_len) bad_json("unexpected end of input");
  switch (in[pos]) {
    case '{': return parse_object();
    case '[': return parse_array();
    case '"': {
      struct node *n = new_node(K_STR);
      n->str = parse_string(&n->len);
      return n;
    }
    default:
      /* numbers, true, false, null (valid JSON or not) are never allowed in a document */
      fail("numbers, booleans and null are not allowed (or the input is not valid JSON)", NULL);
      return NULL;
  }
}

/* ---------- validation (§4, §6) ---------- */

static int bytes_eq(const char *a, size_t al, const char *b) {
  size_t bl = strlen(b);
  return al == bl && memcmp(a, b, al) == 0;
}

static struct node *sort_target;

static int cmp_bytes(const char *a, size_t al, const char *b, size_t bl) {
  int c = memcmp(a, b, al < bl ? al : bl);
  if (c != 0) return c;
  return al < bl ? -1 : (al > bl ? 1 : 0);
}

static int cmp_members(const void *x, const void *y) {
  size_t i = *(const size_t *)x, j = *(const size_t *)y;
  return cmp_bytes(sort_target->names[i], sort_target->name_lens[i], sort_target->names[j], sort_target->name_lens[j]);
}

/* Sorts the members of an object by the UTF-8 bytes of their names (like the reference). */
static void sort_object(struct node *n) {
  size_t *idx, i;
  char **names;
  size_t *lens;
  struct node **kids;
  if (n->count < 2) return;
  idx = xrealloc(NULL, n->count * sizeof *idx);
  for (i = 0; i < n->count; i++) idx[i] = i;
  sort_target = n;
  qsort(idx, n->count, sizeof *idx, cmp_members);
  names = xrealloc(NULL, n->count * sizeof *names);
  lens = xrealloc(NULL, n->count * sizeof *lens);
  kids = xrealloc(NULL, n->count * sizeof *kids);
  for (i = 0; i < n->count; i++) {
    names[i] = n->names[idx[i]];
    lens[i] = n->name_lens[idx[i]];
    kids[i] = n->kids[idx[i]];
  }
  free(n->names); free(n->name_lens); free(n->kids); free(idx);
  n->names = names; n->name_lens = lens; n->kids = kids;
}

static void validate(struct node *n) {
  size_t i;
  if (n->kind == K_STR) return;
  if (n->kind == K_ARR) {
    struct node *a, *b;
    if (n->count != 2 || n->kids[0]->kind != K_STR || n->kids[1]->kind != K_STR)
      fail("an array must be [\"link\", target] or [\"script\", content]", NULL);
    a = n->kids[0];
    b = n->kids[1];
    if (!bytes_eq(a->str, a->len, "link") && !bytes_eq(a->str, a->len, "script"))
      fail("unknown array kind", NULL);
    if (bytes_eq(a->str, a->len, "link") && memchr(b->str, 0, b->len) != NULL)
      fail("a link target cannot contain NUL", NULL);
    return;
  }
  sort_object(n);
  for (i = 0; i < n->count; i++) {
    const char *name = n->names[i];
    size_t len = n->name_lens[i];
    if (len == 0 || bytes_eq(name, len, ".") || bytes_eq(name, len, "..") ||
        memchr(name, '/', len) != NULL || memchr(name, 0, len) != NULL)
      fail("invalid name", len ? name : "\"\"");
    /* §4.2: duplicate names are rejected (they are adjacent after sorting) */
    if (i > 0 && cmp_bytes(n->names[i - 1], n->name_lens[i - 1], name, len) == 0)
      fail("duplicate name", name);
    validate(n->kids[i]);
  }
}

/* ---------- writing the tree (§5) ---------- */

static void write_file(int dirfd, const char *name, const struct node *content, int executable) {
  size_t done = 0;
  int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0666);
  if (fd < 0) fail(name, strerror(errno));
  while (done < content->len) {
    ssize_t w = write(fd, content->str + done, content->len - done);
    if (w < 0) {
      if (errno == EINTR) continue;
      fail(name, strerror(errno));
    }
    done += (size_t)w;
  }
  if (executable) {
    struct stat st;
    if (fstat(fd, &st) != 0 || fchmod(fd, (st.st_mode & 07777) | 0111) != 0) fail(name, strerror(errno));
  }
  if (close(fd) != 0) fail(name, strerror(errno));
}

static void apply(int dirfd, struct node *tree) {
  size_t i;
  for (i = 0; i < tree->count; i++) {
    const char *name = tree->names[i];
    struct node *v = tree->kids[i];
    struct stat st;
    int exists = fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0;
    if (!exists && errno != ENOENT) fail(name, strerror(errno));
    if (v->kind == K_OBJ) {
      int sub;
      if (!exists || !S_ISDIR(st.st_mode)) {
        if (exists && unlinkat(dirfd, name, 0) != 0) fail(name, strerror(errno));
        if (mkdirat(dirfd, name, 0777) != 0) fail(name, strerror(errno));
      }
      sub = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
      if (sub < 0) fail(name, strerror(errno));
      apply(sub, v);
      close(sub);
    } else {
      if (exists) {
        if (S_ISDIR(st.st_mode)) fail(name, "a directory is in the way");
        if (unlinkat(dirfd, name, 0) != 0) fail(name, strerror(errno));
      }
      if (v->kind == K_STR) {
        write_file(dirfd, name, v, 0);
      } else if (bytes_eq(v->kids[0]->str, v->kids[0]->len, "link")) {
        if (symlinkat(v->kids[1]->str, dirfd, name) != 0) fail(name, strerror(errno));
      } else {
        write_file(dirfd, name, v->kids[1], 1);
      }
    }
  }
}

/* Strings are stored with a terminating NUL too, so names and link targets work as C strings. */
static void terminate_strings(struct node *n) {
  size_t i;
  if (n->kind == K_STR) {
    n->str = xrealloc(n->str, n->len + 1);
    n->str[n->len] = 0;
    return;
  }
  for (i = 0; i < n->count; i++) {
    if (n->names[i] != NULL) {
      n->names[i] = xrealloc(n->names[i], n->name_lens[i] + 1);
      n->names[i][n->name_lens[i]] = 0;
    }
    terminate_strings(n->kids[i]);
  }
}

int main(int argc, char **argv) {
  struct node *root;
  (void)argv;
  if (argc > 1) {
    fputs("usage: json2dir < document.json\n", stderr);
    return 2;
  }
  read_stdin();
  check_utf8(in, in_len);
  pos = 0;
  if (in_len >= 3 && in[0] == 0xEF && in[1] == 0xBB && in[2] == 0xBF) pos = 3; /* §3: BOM ignored */
  root = parse_value();
  skip_ws();
  if (pos != in_len) bad_json("trailing data");
  if (root->kind != K_OBJ) fail("the root of the document must be an object", NULL);
  terminate_strings(root);
  validate(root);
  apply(AT_FDCWD, root);
  return 0;
}
