// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
//
// trstctl host TLS session observer (X5): which TLS each connection on this
// host negotiated, read from the TLS library itself, with no proxy in the
// path. Attached as uprobes to OpenSSL 3's libssl and libcrypto, it copies
// only:
//
//   - the plaintext TLS handshake records an SSL exchanges with the BIOs it
//     was given (SSL_set0_rbio, SSL_set0_wbio). Each direction stops at its
//     first record that is not a handshake record (ChangeCipherSpec, an alert,
//     application data), so no encrypted byte and no application data is
//     ever copied. For TLS 1.3 that is the ClientHello and the ServerHello (or
//     HelloRetryRequest); for TLS 1.2 everything before ChangeCipherSpec.
//   - the certificates libssl itself parses (d2i_X509 called from libssl)
//     while an SSL handshake call runs on the thread: the peer's chain off the
//     wire, which TLS 1.3 sends encrypted, so this is the only place a host
//     sees it. Certificates an application or libcrypto loads meanwhile (a CA
//     file or bundle) are not copied.
//   - when each handshake call returns, with its result, and when an SSL is
//     freed or cleared.
//
// The kernel requires a GPL-compatible license for bpf_probe_read_user. The
// file is self-contained (no kernel or libbpf headers) and compiles for
// x86-64 (-D__TARGET_ARCH_x86) and arm64 (-D__TARGET_ARCH_arm64); see
// scripts/gen-sessionobserve-bpf.sh. It needs Linux 5.17 or later (bpf_loop).

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef long long __s64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __always_inline inline __attribute__((always_inline))

enum {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};
enum { BPF_ANY = 0, BPF_NOEXIST = 1 };

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)112;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static long (*bpf_loop)(__u32 nr_loops, void *callback_fn, void *callback_ctx, __u64 flags) = (void *)181;

// The registers a uprobe sees, as the kernel lays them out.
#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	unsigned long r15, r14, r13, r12, bp, bx, r11, r10, r9, r8, ax, cx, dx, si, di, orig_ax, ip, cs, flags, sp, ss;
};
#define ARG1(x) ((x)->di)
#define ARG2(x) ((x)->si)
#define ARG3(x) ((x)->dx)
#define ARG4(x) ((x)->cx)
#define RET(x) ((x)->ax)
#define IP(x) ((x)->ip)
#elif defined(__TARGET_ARCH_arm64)
struct pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
#define ARG1(x) ((x)->regs[0])
#define ARG2(x) ((x)->regs[1])
#define ARG3(x) ((x)->regs[2])
#define ARG4(x) ((x)->regs[3])
#define RET(x) ((x)->regs[0])
#define IP(x) ((x)->pc)
#else
#error "build with -D__TARGET_ARCH_x86 or -D__TARGET_ARCH_arm64"
#endif

#define CHUNK_MAX 8191   // bytes in one event; a power of two minus one bounds the copy for the verifier
#define STREAM_MAX 16384 // plaintext handshake bytes kept per direction of one SSL
#define RECORD_MAX 18432 // the largest TLS record: 2^14 plus TLS 1.2's expansion
#define CERTS_MAX 4      // certificates kept per handshake call: the peer's leaf and chain
#define WALK_MAX 16      // record steps per read or write

#define DIR_READ 1
#define DIR_WRITE 2

enum event_type {
	EVENT_HANDSHAKE = 1,   // a handshake call returned: ret is its result
	EVENT_RECORD = 2,      // plaintext handshake bytes: ret is the direction, offset where they start in it
	EVENT_CERTIFICATE = 3, // a certificate parsed during a handshake call: offset is its full DER length
	EVENT_STREAM_END = 4,  // a direction stopped: ret is the direction, offset why (1 sealed, 2 out of step, 3 full)
	EVENT_RELEASE = 5,     // the SSL was freed or cleared
};

struct event {
	__u32 type;
	__u32 pid;
	__u32 tid;
	__u32 len;
	__u64 ssl;
	__s64 ret;
	__u64 offset;
	char comm[16];
	__u8 data[CHUNK_MAX + 1];
};

struct window {
	__u64 ssl;
	__u32 depth;
	__u32 certs;
	__u32 io; // opened by a read or write that runs the handshake itself
	__u32 pad;
};

struct owner_key {
	__u64 ptr;
	__u32 pid;
	__u32 pad;
};

struct bio_owner {
	__u64 ssl;
	__u32 dirs;
	__u32 pad;
};

struct ssl_bios {
	__u64 rbio;
	__u64 wbio;
};

struct stream_key {
	__u64 ssl;
	__u32 pid;
	__u32 dir;
};

struct stream {
	__u32 pending;  // bytes of the current record still to come
	__u32 captured; // bytes copied so far
	__u32 ended;    // why the direction stopped, or 0
	__u32 pad;
};

struct io {
	__u64 ssl;
	__u64 buf;
	__u64 out; // BIO_write_ex's size_t *written
	__u32 depth;
	__u32 ex;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct window);
} windows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct owner_key);
	__type(value, struct bio_owner);
} bios SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct owner_key);
	__type(value, struct ssl_bios);
} ssls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct stream_key);
	__type(value, struct stream);
} streams SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct io);
} reads SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct io);
} writes SEC(".maps");

// libssl_layout is where SSL_set0_rbio and libssl's executable segment sit in
// the library file (link-time addresses), written before the probes attach;
// libssl_text is that segment's address range in each process, learned when
// the process calls SSL_set0_rbio.
struct layout {
	__u64 symbol;
	__u64 start;
	__u64 size;
};

struct text {
	__u64 lo;
	__u64 hi;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct layout);
} libssl_layout SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct text);
} libssl_text SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

// drops counts events the ring buffer had no room for.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

static __always_inline void dropped(void)
{
	__u32 zero = 0;
	__u64 *n = bpf_map_lookup_elem(&drops, &zero);
	if (n)
		__sync_fetch_and_add(n, 1);
}

static __always_inline struct event *start(__u32 type, __u64 ssl, __s64 ret, __u64 offset)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!e) {
		dropped();
		return 0;
	}
	__u64 id = bpf_get_current_pid_tgid();
	e->type = type;
	e->pid = id >> 32;
	e->tid = (__u32)id;
	e->len = 0;
	e->ssl = ssl;
	e->ret = ret;
	e->offset = offset;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

static __always_inline void notice(__u32 type, __u64 ssl, __s64 ret, __u64 offset)
{
	struct event *e = start(type, ssl, ret, offset);
	if (e)
		bpf_ringbuf_submit(e, 0);
}

// copy sends n user bytes at src; a failed read sends none.
static __always_inline void copy(__u32 type, __u64 ssl, __s64 ret, __u64 offset, __u64 src, __u64 n)
{
	struct event *e = start(type, ssl, ret, offset);
	if (!e)
		return;
	if (n > CHUNK_MAX)
		n = CHUNK_MAX;
	n &= CHUNK_MAX;
	if (bpf_probe_read_user(e->data, n, (const void *)src) == 0)
		e->len = n;
	bpf_ringbuf_submit(e, 0);
}

static __always_inline __u32 self_pid(void) { return bpf_get_current_pid_tgid() >> 32; }
static __always_inline __u32 self_tid(void) { return (__u32)bpf_get_current_pid_tgid(); }

static __always_inline void end_stream(struct stream *s, __u64 ssl, __u32 dir, __u32 why)
{
	s->ended = why;
	notice(EVENT_STREAM_END, ssl, dir, why);
}

struct walk_ctx {
	__u64 ssl;
	__u64 buf;
	__u64 n;
	__u64 off;
	__u32 dir;
	__u32 pid;
};

// walk_step takes one step through the bytes: the next piece of the current
// record, or the next record's header. It returns 1 to stop.
static long walk_step(__u32 index, void *data)
{
	struct walk_ctx *c = data;
	if (c->off >= c->n)
		return 1;
	struct stream_key k = {.ssl = c->ssl, .pid = c->pid, .dir = c->dir};
	struct stream *s = bpf_map_lookup_elem(&streams, &k);
	if (!s || s->ended)
		return 1;
	__u64 left = c->n - c->off;
	if (s->pending > 0) {
		__u64 take = left < s->pending ? left : s->pending;
		if (take > CHUNK_MAX)
			take = CHUNK_MAX;
		copy(EVENT_RECORD, c->ssl, c->dir, s->captured, c->buf + c->off, take);
		s->captured += take;
		s->pending -= take;
		c->off += take;
		return 0;
	}
	if (left < 5) {
		end_stream(s, c->ssl, c->dir, 2); // a record header split across reads
		return 1;
	}
	__u8 hdr[5] = {};
	if (bpf_probe_read_user(hdr, sizeof(hdr), (const void *)(c->buf + c->off)) != 0) {
		end_stream(s, c->ssl, c->dir, 2);
		return 1;
	}
	__u32 length = ((__u32)hdr[3] << 8) | hdr[4];
	if (hdr[0] != 0x16 || hdr[1] != 0x03 || length > RECORD_MAX) {
		end_stream(s, c->ssl, c->dir, 1); // the first record that is not a plaintext handshake record
		return 1;
	}
	if (s->captured + 5 + length > STREAM_MAX) {
		end_stream(s, c->ssl, c->dir, 3);
		return 1;
	}
	s->pending = 5 + length; // the header and its body, copied by the steps that follow
	return 0;
}

// walk follows the TLS records in n bytes the SSL read or wrote in one
// direction, copying handshake records and stopping the direction at its
// first record of any other type.
static __always_inline void walk(__u64 ssl, __u32 dir, __u64 buf, __u64 n)
{
	struct walk_ctx c = {.ssl = ssl, .buf = buf, .n = n, .off = 0, .dir = dir, .pid = self_pid()};
	struct stream_key k = {.ssl = ssl, .pid = c.pid, .dir = dir};
	struct stream *s = bpf_map_lookup_elem(&streams, &k);
	if (!s) {
		struct stream fresh = {};
		bpf_map_update_elem(&streams, &k, &fresh, BPF_NOEXIST);
		s = bpf_map_lookup_elem(&streams, &k);
		if (!s)
			return;
	}
	if (s->ended)
		return;
	bpf_loop(WALK_MAX, walk_step, &c, 0);
	if (c.off < n) {
		s = bpf_map_lookup_elem(&streams, &k);
		if (s && !s->ended)
			end_stream(s, ssl, dir, 2); // more records than one call's steps
	}
}

static __always_inline void own(__u64 ssl, __u64 bio, __u32 dir)
{
	__u32 pid = self_pid();
	struct owner_key sk = {.ptr = ssl, .pid = pid};
	struct ssl_bios now = {};
	struct ssl_bios *had = bpf_map_lookup_elem(&ssls, &sk);
	if (had)
		now = *had;
	__u64 old = dir == DIR_READ ? now.rbio : now.wbio;
	if (old && old != bio) {
		struct owner_key ok = {.ptr = old, .pid = pid};
		struct bio_owner *o = bpf_map_lookup_elem(&bios, &ok);
		if (o && o->ssl == ssl) {
			o->dirs &= ~dir;
			if (!o->dirs)
				bpf_map_delete_elem(&bios, &ok);
		}
	}
	if (dir == DIR_READ)
		now.rbio = bio;
	else
		now.wbio = bio;
	bpf_map_update_elem(&ssls, &sk, &now, BPF_ANY);
	if (!bio)
		return;
	struct owner_key bk = {.ptr = bio, .pid = pid};
	struct bio_owner *o = bpf_map_lookup_elem(&bios, &bk);
	if (o && o->ssl == ssl) {
		o->dirs |= dir;
		return;
	}
	struct bio_owner fresh = {.ssl = ssl, .dirs = dir};
	bpf_map_update_elem(&bios, &bk, &fresh, BPF_ANY);
}

// learn_text records where libssl's code is in this process: the probe's
// address is SSL_set0_rbio's.
static __always_inline void learn_text(struct pt_regs *ctx)
{
	__u32 zero = 0;
	struct layout *l = bpf_map_lookup_elem(&libssl_layout, &zero);
	if (!l || !l->symbol || !l->size)
		return;
	__u64 bias = IP(ctx) - l->symbol;
	struct text t = {.lo = bias + l->start, .hi = bias + l->start + l->size};
	__u32 pid = self_pid();
	bpf_map_update_elem(&libssl_text, &pid, &t, BPF_ANY);
}

// caller is the return address at a function's entry.
static __always_inline __u64 caller(struct pt_regs *ctx)
{
#if defined(__TARGET_ARCH_x86)
	__u64 ret = 0;
	if (bpf_probe_read_user(&ret, sizeof(ret), (const void *)ctx->sp) != 0)
		return 0;
	return ret;
#else
	return ctx->regs[30];
#endif
}

SEC("uprobe/SSL_set0_rbio")
int set_rbio(struct pt_regs *ctx)
{
	learn_text(ctx);
	own(ARG1(ctx), ARG2(ctx), DIR_READ);
	return 0;
}

SEC("uprobe/SSL_set0_wbio")
int set_wbio(struct pt_regs *ctx)
{
	own(ARG1(ctx), ARG2(ctx), DIR_WRITE);
	return 0;
}

// release forgets an SSL that is freed or cleared, so a later SSL at the
// same address starts afresh.
static __always_inline void release(__u64 ssl, int freed)
{
	__u32 pid = self_pid();
	struct owner_key sk = {.ptr = ssl, .pid = pid};
	if (freed) {
		struct ssl_bios *b = bpf_map_lookup_elem(&ssls, &sk);
		if (b) {
			struct owner_key bk = {.ptr = b->rbio, .pid = pid};
			bpf_map_delete_elem(&bios, &bk);
			bk.ptr = b->wbio;
			bpf_map_delete_elem(&bios, &bk);
		}
		bpf_map_delete_elem(&ssls, &sk);
	}
	struct stream_key k = {.ssl = ssl, .pid = pid, .dir = DIR_READ};
	bpf_map_delete_elem(&streams, &k);
	k.dir = DIR_WRITE;
	bpf_map_delete_elem(&streams, &k);
	notice(EVENT_RELEASE, ssl, freed, 0);
}

SEC("uprobe/SSL_free")
int ssl_free(struct pt_regs *ctx)
{
	if (ARG1(ctx))
		release(ARG1(ctx), 1);
	return 0;
}

SEC("uprobe/SSL_clear")
int ssl_clear(struct pt_regs *ctx)
{
	if (ARG1(ctx))
		release(ARG1(ctx), 0);
	return 0;
}

static __always_inline void window_enter(__u64 ssl, __u32 io)
{
	__u32 tid = self_tid();
	struct window *w = bpf_map_lookup_elem(&windows, &tid);
	if (w && w->ssl == ssl) {
		w->depth++;
		return;
	}
	struct window fresh = {.ssl = ssl, .depth = 1, .io = io};
	bpf_map_update_elem(&windows, &tid, &fresh, BPF_ANY);
}

// window_exit closes the thread's window of the given kind; a handshake
// call's window reports the call's result.
static __always_inline void window_exit(__u32 io, __s64 ret)
{
	__u32 tid = self_tid();
	struct window *w = bpf_map_lookup_elem(&windows, &tid);
	if (!w || w->io != io)
		return;
	if (w->depth > 1) {
		w->depth--;
		return;
	}
	__u64 ssl = w->ssl;
	bpf_map_delete_elem(&windows, &tid);
	if (!io)
		notice(EVENT_HANDSHAKE, ssl, ret, 0);
}

// A handshake call (SSL_do_handshake, SSL_connect, SSL_accept) opens a window
// on its thread; SSL_connect and SSL_accept call SSL_do_handshake, so windows
// nest.
SEC("uprobe/SSL_do_handshake")
int handshake_enter(struct pt_regs *ctx)
{
	window_enter(ARG1(ctx), 0);
	return 0;
}

SEC("uretprobe/SSL_do_handshake")
int handshake_exit(struct pt_regs *ctx)
{
	window_exit(0, (__s32)RET(ctx));
	return 0;
}

// handshake_over reports whether both directions of an SSL stopped: its
// handshake has finished, as far as anything in the clear goes.
static __always_inline int handshake_over(__u64 ssl, __u32 pid)
{
	struct stream_key k = {.ssl = ssl, .pid = pid, .dir = DIR_READ};
	struct stream *r = bpf_map_lookup_elem(&streams, &k);
	k.dir = DIR_WRITE;
	struct stream *w = bpf_map_lookup_elem(&streams, &k);
	return r && w && r->ended && w->ended;
}

// SSL_read, SSL_write and their _ex forms run the handshake themselves when
// the application never called a handshake function (openssl s_client does
// this). Such a call opens a window too, while an SSL whose BIOs the probes
// know has not finished its handshake.
SEC("uprobe/SSL_read")
int io_call_enter(struct pt_regs *ctx)
{
	__u64 ssl = ARG1(ctx);
	__u32 pid = self_pid();
	struct owner_key sk = {.ptr = ssl, .pid = pid};
	if (!ssl || !bpf_map_lookup_elem(&ssls, &sk) || handshake_over(ssl, pid))
		return 0;
	window_enter(ssl, 1);
	return 0;
}

SEC("uretprobe/SSL_read")
int io_call_exit(struct pt_regs *ctx)
{
	window_exit(1, 0);
	return 0;
}

// d2i_X509(X509 **a, const unsigned char **in, long len): a certificate
// libssl parses while a handshake call runs on this thread.
SEC("uprobe/d2i_X509")
int certificate(struct pt_regs *ctx)
{
	__u32 tid = self_tid();
	struct window *w = bpf_map_lookup_elem(&windows, &tid);
	if (!w || w->certs >= CERTS_MAX)
		return 0;
	__u32 pid = self_pid();
	struct text *t = bpf_map_lookup_elem(&libssl_text, &pid);
	__u64 from = caller(ctx);
	if (!t || from < t->lo || from >= t->hi)
		return 0; // not libssl reading the peer's certificate
	__u64 in = ARG2(ctx);
	__s64 length = (__s64)ARG3(ctx);
	__u64 der = 0;
	if (!in || length <= 0 || bpf_probe_read_user(&der, sizeof(der), (const void *)in) != 0 || !der)
		return 0;
	w->certs++;
	copy(EVENT_CERTIFICATE, w->ssl, 0, (__u64)length, der, (__u64)length);
	return 0;
}

// The BIO calls libssl makes: BIO_read(b, data, dlen) returns the bytes
// read; BIO_write(b, data, dlen) the bytes written; BIO_write_ex(b, data,
// dlen, *written) 1 with the count in *written. Only the outermost call on a
// BIO an SSL owns is followed: a filter BIO's call to the BIO under it is not.
static __always_inline void io_enter(void *calls, __u64 bio, __u64 buf, __u64 out, __u32 dir, __u32 ex)
{
	__u32 tid = self_tid();
	struct io *cur = bpf_map_lookup_elem(calls, &tid);
	if (cur) {
		cur->depth++;
		return;
	}
	struct owner_key bk = {.ptr = bio, .pid = self_pid()};
	struct bio_owner *o = bpf_map_lookup_elem(&bios, &bk);
	if (!o || !(o->dirs & dir))
		return;
	struct stream_key k = {.ssl = o->ssl, .pid = bk.pid, .dir = dir};
	struct stream *s = bpf_map_lookup_elem(&streams, &k);
	if (s && s->ended)
		return;
	struct io fresh = {.ssl = o->ssl, .buf = buf, .out = out, .depth = 1, .ex = ex};
	bpf_map_update_elem(calls, &tid, &fresh, BPF_ANY);
}

static __always_inline void io_exit(void *calls, __s64 rc, __u32 dir)
{
	__u32 tid = self_tid();
	struct io *cur = bpf_map_lookup_elem(calls, &tid);
	if (!cur)
		return;
	if (cur->depth > 1) {
		cur->depth--;
		return;
	}
	struct io done = *cur;
	bpf_map_delete_elem(calls, &tid);
	__u64 n = 0;
	if (done.ex) {
		if (rc != 1 || !done.out || bpf_probe_read_user(&n, sizeof(n), (const void *)done.out) != 0)
			return;
	} else {
		if (rc <= 0)
			return;
		n = (__u64)rc;
	}
	if (n > 0)
		walk(done.ssl, dir, done.buf, n);
}

SEC("uprobe/BIO_read")
int bio_read_enter(struct pt_regs *ctx)
{
	io_enter(&reads, ARG1(ctx), ARG2(ctx), 0, DIR_READ, 0);
	return 0;
}

SEC("uretprobe/BIO_read")
int bio_read_exit(struct pt_regs *ctx)
{
	io_exit(&reads, (__s32)RET(ctx), DIR_READ);
	return 0;
}

SEC("uprobe/BIO_write")
int bio_write_enter(struct pt_regs *ctx)
{
	io_enter(&writes, ARG1(ctx), ARG2(ctx), 0, DIR_WRITE, 0);
	return 0;
}

SEC("uretprobe/BIO_write")
int bio_write_exit(struct pt_regs *ctx)
{
	io_exit(&writes, (__s32)RET(ctx), DIR_WRITE);
	return 0;
}

SEC("uprobe/BIO_write_ex")
int bio_write_ex_enter(struct pt_regs *ctx)
{
	io_enter(&writes, ARG1(ctx), ARG2(ctx), ARG4(ctx), DIR_WRITE, 1);
	return 0;
}

SEC("uretprobe/BIO_write_ex")
int bio_write_ex_exit(struct pt_regs *ctx)
{
	io_exit(&writes, (__s32)RET(ctx), DIR_WRITE);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
