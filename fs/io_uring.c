// SPDX-License-Identifier: GPL-2.0
/*
 * Shared application/kernel submission and completion ring pairs, for
 * supporting fast/efficient IO.
 *
 * A note on the read/write ordering memory barriers that are matched between
 * the application and kernel side.
 *
 * After the application reads the CQ ring tail, it must use an
 * appropriate smp_rmb() to pair with the smp_wmb() the kernel uses
 * before writing the tail (using smp_load_acquire to read the tail will
 * do). It also needs a smp_mb() before updating CQ head (ordering the
 * entry load(s) with the head store), pairing with an implicit barrier
 * through a control-dependency in io_get_cqring (smp_store_release to
 * store head will do). Failure to do so could lead to reading invalid
 * CQ entries.
 *
 * Likewise, the application must use an appropriate smp_wmb() before
 * writing the SQ tail (ordering SQ entry stores with the tail store),
 * which pairs with smp_load_acquire in io_get_sqring (smp_store_release
 * to store the tail will do). And it needs a barrier ordering the SQ
 * head load before writing new SQ entries (smp_load_acquire to read
 * head will do).
 *
 * When using the SQ poll thread (IORING_SETUP_SQPOLL), the application
 * needs to check the SQ flags for IORING_SQ_NEED_WAKEUP *after*
 * updating the SQ tail; a full memory barrier smp_mb() is needed
 * between.
 *
 * Also see the examples in the liburing library:
 *
 *	git://git.kernel.dk/liburing
 *
 * io_uring also uses READ/WRITE_ONCE() for _any_ store or load that happens
 * from data shared between the kernel and application. This is done both
 * for ordering purposes, but also to ensure that once a value is loaded from
 * data that the application could potentially modify, it remains stable.
 *
 * Copyright (C) 2018-2019 Jens Axboe
 * Copyright (c) 2018-2019 Christoph Hellwig
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <net/compat.h>
#include <linux/refcount.h>
#include <linux/uio.h>
#include <linux/bits.h>

#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/blkdev.h>
#include <linux/bvec.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <net/scm.h>
#include <linux/anon_inodes.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>
#include <linux/nospec.h>
#include <linux/sizes.h>
#include <linux/hugetlb.h>
#include <linux/highmem.h>
#include <linux/namei.h>
#include <linux/fsnotify.h>
#include <linux/fadvise.h>
#include <linux/eventpoll.h>
#include <linux/fs_struct.h>
#include <linux/splice.h>
#include <linux/task_work.h>
#include <linux/pagemap.h>
#include <linux/io_uring.h>
#include <linux/blk-cgroup.h>
#include <linux/audit.h>

#define CREATE_TRACE_POINTS
#include <trace/events/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "internal.h"
#include "io-wq.h"

#define IORING_MAX_ENTRIES	32768
#define IORING_MAX_CQ_ENTRIES	(2 * IORING_MAX_ENTRIES)

/*
 * Shift of 9 is 512 entries, or exactly one page on 64-bit archs
 */
#define IORING_FILE_TABLE_SHIFT	9
#define IORING_MAX_FILES_TABLE	(1U << IORING_FILE_TABLE_SHIFT)
#define IORING_FILE_TABLE_MASK	(IORING_MAX_FILES_TABLE - 1)
#define IORING_MAX_FIXED_FILES	(64 * IORING_MAX_FILES_TABLE)
#define IORING_MAX_RESTRICTIONS	(IORING_RESTRICTION_LAST + \
				 IORING_REGISTER_LAST + IORING_OP_LAST)

struct io_uring {
	u32 head ____cacheline_aligned_in_smp;
	u32 tail ____cacheline_aligned_in_smp;
};

/*
 * This data is shared with the application through the mmap at offsets
 * IORING_OFF_SQ_RING and IORING_OFF_CQ_RING.
 *
 * The offsets to the member fields are published through struct
 * io_sqring_offsets when calling io_uring_setup.
 */
struct io_rings {
	/*
	 * Head and tail offsets into the ring; the offsets need to be
	 * masked to get valid indices.
	 *
	 * The kernel controls head of the sq ring and the tail of the cq ring,
	 * and the application controls tail of the sq ring and the head of the
	 * cq ring.
	 */
	struct io_uring		sq, cq;
	/*
	 * Bitmasks to apply to head and tail offsets (constant, equals
	 * ring_entries - 1)
	 */
	u32			sq_ring_mask, cq_ring_mask;
	/* Ring sizes (constant, power of 2) */
	u32			sq_ring_entries, cq_ring_entries;
	/*
	 * Number of invalid entries dropped by the kernel due to
	 * invalid index stored in array
	 *
	 * Written by the kernel, shouldn't be modified by the
	 * application (i.e. get number of "new events" by comparing to
	 * cached value).
	 *
	 * After a new SQ head value was read by the application this
	 * counter includes all submissions that were dropped reaching
	 * the new SQ head (and possibly more).
	 */
	u32			sq_dropped;
	/*
	 * Runtime SQ flags
	 *
	 * Written by the kernel, shouldn't be modified by the
	 * application.
	 *
	 * The application needs a full memory barrier before checking
	 * for IORING_SQ_NEED_WAKEUP after updating the sq tail.
	 */
	u32			sq_flags;
	/*
	 * Runtime CQ flags
	 *
	 * Written by the application, shouldn't be modified by the
	 * kernel.
	 */
	u32                     cq_flags;
	/*
	 * Number of completion events lost because the queue was full;
	 * this should be avoided by the application by making sure
	 * there are not more requests pending than there is space in
	 * the completion queue.
	 *
	 * Written by the kernel, shouldn't be modified by the
	 * application (i.e. get number of "new events" by comparing to
	 * cached value).
	 *
	 * As completion events come in out of order this counter is not
	 * ordered with any other data.
	 */
	u32			cq_overflow;
	/*
	 * Ring buffer of completion events.
	 *
	 * The kernel writes completion events fresh every time they are
	 * produced, so the application is allowed to modify pending
	 * entries.
	 */
	struct io_uring_cqe	cqes[] ____cacheline_aligned_in_smp;
};

enum io_uring_cmd_flags {
	IO_URING_F_NONBLOCK		= 1,
	IO_URING_F_COMPLETE_DEFER	= 2,
};

struct io_mapped_ubuf {
	u64		ubuf;
	size_t		len;
	struct		bio_vec *bvec;
	unsigned int	nr_bvecs;
	unsigned long	acct_pages;
};

struct io_ring_ctx;

struct io_rsrc_put {
	struct list_head list;
	union {
		void *rsrc;
		struct file *file;
	};
};

struct fixed_rsrc_table {
	struct file		**files;
};

struct fixed_rsrc_ref_node {
	struct percpu_ref		refs;
	struct list_head		node;
	struct list_head		rsrc_list;
	struct fixed_rsrc_data		*rsrc_data;
	void				(*rsrc_put)(struct io_ring_ctx *ctx,
						    struct io_rsrc_put *prsrc);
	struct llist_node		llist;
	bool				done;
};

struct fixed_rsrc_data {
	struct fixed_rsrc_table		*table;
	struct io_ring_ctx		*ctx;

	struct fixed_rsrc_ref_node	*node;
	struct percpu_ref		refs;
	struct completion		done;
};

struct io_buffer {
	struct list_head list;
	__u64 addr;
	__s32 len;
	__u16 bid;
};

struct io_restriction {
	DECLARE_BITMAP(register_op, IORING_REGISTER_LAST);
	DECLARE_BITMAP(sqe_op, IORING_OP_LAST);
	u8 sqe_flags_allowed;
	u8 sqe_flags_required;
	bool registered;
};

struct io_sq_data {
	refcount_t		refs;
	struct mutex		lock;

	/* ctx's that are using this sqd */
	struct list_head	ctx_list;
	struct list_head	ctx_new_list;
	struct mutex		ctx_lock;

	struct task_struct	*thread;
	struct wait_queue_head	wait;

	unsigned		sq_thread_idle;
};

#define IO_IOPOLL_BATCH			8
#define IO_COMPL_BATCH			32
#define IO_REQ_CACHE_SIZE		32
#define IO_REQ_ALLOC_BATCH		8

struct io_comp_state {
	struct io_kiocb		*reqs[IO_COMPL_BATCH];
	unsigned int		nr;
	unsigned int		locked_free_nr;
	/* inline/task_work completion list, under ->uring_lock */
	struct list_head	free_list;
	/* IRQ completion list, under ->completion_lock */
	struct list_head	locked_free_list;
};

struct io_submit_state {
	struct blk_plug		plug;

	/*
	 * io_kiocb alloc cache
	 */
	void			*reqs[IO_REQ_CACHE_SIZE];
	unsigned int		free_reqs;

	bool			plug_started;

	/*
	 * Batch completion logic
	 */
	struct io_comp_state	comp;

	/*
	 * File reference cache
	 */
	struct file		*file;
	unsigned int		fd;
	unsigned int		file_refs;
	unsigned int		ios_left;
};

struct io_ring_ctx {
	struct {
		struct percpu_ref	refs;
	} ____cacheline_aligned_in_smp;

	struct {
		unsigned int		flags;
		unsigned int		compat: 1;
		unsigned int		limit_mem: 1;
		unsigned int		cq_overflow_flushed: 1;
		unsigned int		drain_next: 1;
		unsigned int		eventfd_async: 1;
		unsigned int		restricted: 1;
		unsigned int		sqo_dead: 1;

		/*
		 * Ring buffer of indices into array of io_uring_sqe, which is
		 * mmapped by the application using the IORING_OFF_SQES offset.
		 *
		 * This indirection could e.g. be used to assign fixed
		 * io_uring_sqe entries to operations and only submit them to
		 * the queue when needed.
		 *
		 * The kernel modifies neither the indices array nor the entries
		 * array.
		 */
		u32			*sq_array;
		unsigned		cached_sq_head;
		unsigned		sq_entries;
		unsigned		sq_mask;
		unsigned		sq_thread_idle;
		unsigned		cached_sq_dropped;
		unsigned		cached_cq_overflow;
		unsigned long		sq_check_overflow;

		struct list_head	defer_list;
		struct list_head	timeout_list;
		struct list_head	cq_overflow_list;

		struct io_uring_sqe	*sq_sqes;
	} ____cacheline_aligned_in_smp;

	struct {
		struct mutex		uring_lock;
		wait_queue_head_t	wait;
	} ____cacheline_aligned_in_smp;

	struct io_submit_state		submit_state;

	struct io_rings	*rings;

	/* IO offload */
	struct io_wq		*io_wq;

	/*
	 * For SQPOLL usage - we hold a reference to the parent task, so we
	 * have access to the ->files
	 */
	struct task_struct	*sqo_task;

	/* Only used for accounting purposes */
	struct mm_struct	*mm_account;

#ifdef CONFIG_BLK_CGROUP
	struct cgroup_subsys_state	*sqo_blkcg_css;
#endif

	struct io_sq_data	*sq_data;	/* if using sq thread polling */

	struct wait_queue_head	sqo_sq_wait;
	struct list_head	sqd_list;

	/*
	 * If used, fixed file set. Writers must ensure that ->refs is dead,
	 * readers must ensure that ->refs is alive as long as the file* is
	 * used. Only updated through io_uring_register(2).
	 */
	struct fixed_rsrc_data	*file_data;
	unsigned		nr_user_files;

	/* if used, fixed mapped user buffers */
	unsigned		nr_user_bufs;
	struct io_mapped_ubuf	*user_bufs;

	struct user_struct	*user;

	const struct cred	*creds;

#ifdef CONFIG_AUDIT
	kuid_t			loginuid;
	unsigned int		sessionid;
#endif

	struct completion	ref_comp;
	struct completion	sq_thread_comp;

#if defined(CONFIG_UNIX)
	struct socket		*ring_sock;
#endif

	struct idr		io_buffer_idr;

	struct idr		personality_idr;

	struct {
		unsigned		cached_cq_tail;
		unsigned		cq_entries;
		unsigned		cq_mask;
		atomic_t		cq_timeouts;
		unsigned		cq_last_tm_flush;
		unsigned long		cq_check_overflow;
		struct wait_queue_head	cq_wait;
		struct fasync_struct	*cq_fasync;
		struct eventfd_ctx	*cq_ev_fd;
	} ____cacheline_aligned_in_smp;

	struct {
		spinlock_t		completion_lock;

		/*
		 * ->iopoll_list is protected by the ctx->uring_lock for
		 * io_uring instances that don't use IORING_SETUP_SQPOLL.
		 * For SQPOLL, only the single threaded io_sq_thread() will
		 * manipulate the list, hence no extra locking is needed there.
		 */
		struct list_head	iopoll_list;
		struct hlist_head	*cancel_hash;
		unsigned		cancel_hash_bits;
		bool			poll_multi_file;

		spinlock_t		inflight_lock;
		struct list_head	inflight_list;
	} ____cacheline_aligned_in_smp;

	struct delayed_work		rsrc_put_work;
	struct llist_head		rsrc_put_llist;
	struct list_head		rsrc_ref_list;
	spinlock_t			rsrc_ref_lock;

	struct io_restriction		restrictions;

	/* Keep this last, we don't need it for the fast path */
	struct work_struct		exit_work;
};

/*
 * First field must be the file pointer in all the
 * iocb unions! See also 'struct kiocb' in <linux/fs.h>
 */
struct io_poll_iocb {
	struct file			*file;
	struct wait_queue_head		*head;
	__poll_t			events;
	bool				done;
	bool				canceled;
	struct wait_queue_entry		wait;
};

struct io_poll_remove {
	struct file			*file;
	u64				addr;
};

struct io_close {
	struct file			*file;
	int				fd;
};

struct io_timeout_data {
	struct io_kiocb			*req;
	struct hrtimer			timer;
	struct timespec64		ts;
	enum hrtimer_mode		mode;
};

struct io_accept {
	struct file			*file;
	struct sockaddr __user		*addr;
	int __user			*addr_len;
	int				flags;
	unsigned long			nofile;
};

struct io_sync {
	struct file			*file;
	loff_t				len;
	loff_t				off;
	int				flags;
	int				mode;
};

struct io_cancel {
	struct file			*file;
	u64				addr;
};

struct io_timeout {
	struct file			*file;
	u32				off;
	u32				target_seq;
	struct list_head		list;
	/* head of the link, used by linked timeouts only */
	struct io_kiocb			*head;
};

struct io_timeout_rem {
	struct file			*file;
	u64				addr;

	/* timeout update */
	struct timespec64		ts;
	u32				flags;
};

struct io_rw {
	/* NOTE: kiocb has the file as the first member, so don't do it here */
	struct kiocb			kiocb;
	u64				addr;
	u64				len;
};

struct io_connect {
	struct file			*file;
	struct sockaddr __user		*addr;
	int				addr_len;
};

struct io_sr_msg {
	struct file			*file;
	union {
		struct user_msghdr __user *umsg;
		void __user		*buf;
	};
	int				msg_flags;
	int				bgid;
	size_t				len;
	struct io_buffer		*kbuf;
};

struct io_open {
	struct file			*file;
	int				dfd;
	struct filename			*filename;
	struct open_how			how;
	unsigned long			nofile;
};

struct io_rsrc_update {
	struct file			*file;
	u64				arg;
	u32				nr_args;
	u32				offset;
};

struct io_fadvise {
	struct file			*file;
	u64				offset;
	u32				len;
	u32				advice;
};

struct io_madvise {
	struct file			*file;
	u64				addr;
	u32				len;
	u32				advice;
};

struct io_epoll {
	struct file			*file;
	int				epfd;
	int				op;
	int				fd;
	struct epoll_event		event;
};

struct io_splice {
	struct file			*file_out;
	struct file			*file_in;
	loff_t				off_out;
	loff_t				off_in;
	u64				len;
	unsigned int			flags;
};

struct io_provide_buf {
	struct file			*file;
	__u64				addr;
	__s32				len;
	__u32				bgid;
	__u16				nbufs;
	__u16				bid;
};

struct io_statx {
	struct file			*file;
	int				dfd;
	unsigned int			mask;
	unsigned int			flags;
	const char __user		*filename;
	struct statx __user		*buffer;
};

struct io_shutdown {
	struct file			*file;
	int				how;
};

struct io_rename {
	struct file			*file;
	int				old_dfd;
	int				new_dfd;
	struct filename			*oldpath;
	struct filename			*newpath;
	int				flags;
};

struct io_unlink {
	struct file			*file;
	int				dfd;
	int				flags;
	struct filename			*filename;
};

struct io_completion {
	struct file			*file;
	struct list_head		list;
	int				cflags;
};

struct io_async_connect {
	struct sockaddr_storage		address;
};

struct io_async_msghdr {
	struct iovec			fast_iov[UIO_FASTIOV];
	/* points to an allocated iov, if NULL we use fast_iov instead */
	struct iovec			*free_iov;
	struct sockaddr __user		*uaddr;
	struct msghdr			msg;
	struct sockaddr_storage		addr;
};

struct io_async_rw {
	struct iovec			fast_iov[UIO_FASTIOV];
	const struct iovec		*free_iovec;
	struct iov_iter			iter;
	size_t				bytes_done;
	struct wait_page_queue		wpq;
};

enum {
	REQ_F_FIXED_FILE_BIT	= IOSQE_FIXED_FILE_BIT,
	REQ_F_IO_DRAIN_BIT	= IOSQE_IO_DRAIN_BIT,
	REQ_F_LINK_BIT		= IOSQE_IO_LINK_BIT,
	REQ_F_HARDLINK_BIT	= IOSQE_IO_HARDLINK_BIT,
	REQ_F_FORCE_ASYNC_BIT	= IOSQE_ASYNC_BIT,
	REQ_F_BUFFER_SELECT_BIT	= IOSQE_BUFFER_SELECT_BIT,

	REQ_F_FAIL_LINK_BIT,
	REQ_F_INFLIGHT_BIT,
	REQ_F_CUR_POS_BIT,
	REQ_F_NOWAIT_BIT,
	REQ_F_LINK_TIMEOUT_BIT,
	REQ_F_ISREG_BIT,
	REQ_F_NEED_CLEANUP_BIT,
	REQ_F_POLLED_BIT,
	REQ_F_BUFFER_SELECTED_BIT,
	REQ_F_NO_FILE_TABLE_BIT,
	REQ_F_WORK_INITIALIZED_BIT,
	REQ_F_LTIMEOUT_ACTIVE_BIT,
	REQ_F_COMPLETE_INLINE_BIT,

	/* not a real bit, just to check we're not overflowing the space */
	__REQ_F_LAST_BIT,
};

enum {
	/* ctx owns file */
	REQ_F_FIXED_FILE	= BIT(REQ_F_FIXED_FILE_BIT),
	/* drain existing IO first */
	REQ_F_IO_DRAIN		= BIT(REQ_F_IO_DRAIN_BIT),
	/* linked sqes */
	REQ_F_LINK		= BIT(REQ_F_LINK_BIT),
	/* doesn't sever on completion < 0 */
	REQ_F_HARDLINK		= BIT(REQ_F_HARDLINK_BIT),
	/* IOSQE_ASYNC */
	REQ_F_FORCE_ASYNC	= BIT(REQ_F_FORCE_ASYNC_BIT),
	/* IOSQE_BUFFER_SELECT */
	REQ_F_BUFFER_SELECT	= BIT(REQ_F_BUFFER_SELECT_BIT),

	/* fail rest of links */
	REQ_F_FAIL_LINK		= BIT(REQ_F_FAIL_LINK_BIT),
	/* on inflight list */
	REQ_F_INFLIGHT		= BIT(REQ_F_INFLIGHT_BIT),
	/* read/write uses file position */
	REQ_F_CUR_POS		= BIT(REQ_F_CUR_POS_BIT),
	/* must not punt to workers */
	REQ_F_NOWAIT		= BIT(REQ_F_NOWAIT_BIT),
	/* has or had linked timeout */
	REQ_F_LINK_TIMEOUT	= BIT(REQ_F_LINK_TIMEOUT_BIT),
	/* regular file */
	REQ_F_ISREG		= BIT(REQ_F_ISREG_BIT),
	/* needs cleanup */
	REQ_F_NEED_CLEANUP	= BIT(REQ_F_NEED_CLEANUP_BIT),
	/* already went through poll handler */
	REQ_F_POLLED		= BIT(REQ_F_POLLED_BIT),
	/* buffer already selected */
	REQ_F_BUFFER_SELECTED	= BIT(REQ_F_BUFFER_SELECTED_BIT),
	/* doesn't need file table for this request */
	REQ_F_NO_FILE_TABLE	= BIT(REQ_F_NO_FILE_TABLE_BIT),
	/* io_wq_work is initialized */
	REQ_F_WORK_INITIALIZED	= BIT(REQ_F_WORK_INITIALIZED_BIT),
	/* linked timeout is active, i.e. prepared by link's head */
	REQ_F_LTIMEOUT_ACTIVE	= BIT(REQ_F_LTIMEOUT_ACTIVE_BIT),
	/* completion is deferred through io_comp_state */
	REQ_F_COMPLETE_INLINE	= BIT(REQ_F_COMPLETE_INLINE_BIT),
};

struct async_poll {
	struct io_poll_iocb	poll;
	struct io_poll_iocb	*double_poll;
};

struct io_task_work {
	struct io_wq_work_node	node;
	task_work_func_t	func;
};

/*
 * NOTE! Each of the iocb union members has the file pointer
 * as the first entry in their struct definition. So you can
 * access the file pointer through any of the sub-structs,
 * or directly as just 'ki_filp' in this struct.
 */
struct io_kiocb {
	union {
		struct file		*file;
		struct io_rw		rw;
		struct io_poll_iocb	poll;
		struct io_poll_remove	poll_remove;
		struct io_accept	accept;
		struct io_sync		sync;
		struct io_cancel	cancel;
		struct io_timeout	timeout;
		struct io_timeout_rem	timeout_rem;
		struct io_connect	connect;
		struct io_sr_msg	sr_msg;
		struct io_open		open;
		struct io_close		close;
		struct io_rsrc_update	rsrc_update;
		struct io_fadvise	fadvise;
		struct io_madvise	madvise;
		struct io_epoll		epoll;
		struct io_splice	splice;
		struct io_provide_buf	pbuf;
		struct io_statx		statx;
		struct io_shutdown	shutdown;
		struct io_rename	rename;
		struct io_unlink	unlink;
		/* use only after cleaning per-op data, see io_clean_op() */
		struct io_completion	compl;
	};

	/* opcode allocated if it needs to store data for async defer */
	void				*async_data;
	u8				opcode;
	/* polled IO has completed */
	u8				iopoll_completed;

	u16				buf_index;
	u32				result;

	struct io_ring_ctx		*ctx;
	unsigned int			flags;
	refcount_t			refs;
	struct task_struct		*task;
	u64				user_data;

	struct io_kiocb			*link;
	struct percpu_ref		*fixed_rsrc_refs;

	/*
	 * 1. used with ctx->iopoll_list with reads/writes
	 * 2. to track reqs with ->files (see io_op_def::file_table)
	 */
	struct list_head		inflight_entry;
	union {
		struct io_task_work	io_task_work;
		struct callback_head	task_work;
	};
	/* for polled requests, i.e. IORING_OP_POLL_ADD and async armed poll */
	struct hlist_node		hash_node;
	struct async_poll		*apoll;
	struct io_wq_work		work;
};

struct io_defer_entry {
	struct list_head	list;
	struct io_kiocb		*req;
	u32			seq;
};

struct io_op_def {
	/* needs req->file assigned */
	unsigned		needs_file : 1;
	/* hash wq insertion if file is a regular file */
	unsigned		hash_reg_file : 1;
	/* unbound wq insertion if file is a non-regular file */
	unsigned		unbound_nonreg_file : 1;
	/* opcode is not supported by this kernel */
	unsigned		not_supported : 1;
	/* set if opcode supports polled "wait" */
	unsigned		pollin : 1;
	unsigned		pollout : 1;
	/* op supports buffer selection */
	unsigned		buffer_select : 1;
	/* must always have async data allocated */
	unsigned		needs_async_data : 1;
	/* should block plug */
	unsigned		plug : 1;
	/* size of async data needed, if any */
	unsigned short		async_size;
	unsigned		work_flags;
};

static const struct io_op_def io_op_defs[] = {
	[IORING_OP_NOP] = {},
	[IORING_OP_READV] = {
		.needs_file		= 1,
		.unbound_nonreg_file	= 1,
		.pollin			= 1,
		.buffer_select		= 1,
		.needs_async_data	= 1,
		.plug			= 1,
		.async_size		= sizeof(struct io_async_rw),
		.work_flags		= IO_WQ_WORK_MM | IO_WQ_WORK_BLKCG,
	},
	[IORING_OP_WRITEV] = {
		.needs_file		= 1,
		.hash_reg_file		= 1,
		.unbound_nonreg_file	= 1,
		.pollout		= 1,
		.needs_async_data	= 1,
		.plug			= 1,
		.async_size		= sizeof(struct io_async_rw),
		.work_flags		= IO_WQ_WORK_MM | IO_WQ_WORK_BLKCG |
						IO_WQ_WORK_FSIZE,
	},
	[IORING_OP_FSYNC] = {
		.needs_file		= 1,
		.work_flags		= IO_WQ_WORK_BLKCG,
	},
	[IORING_OP_READ_FIXED] = {
		.needs_file		= 1,
		.unbound_nonreg_file	= 1,
		.pollin			= 1,
		.plug			= 1,
		.async_size		= sizeof(struct io_async_rw),
		.work_flags		= IO_WQ_WORK_BLKCG | IO_WQ_WORK_MM,
	},
	[IORING_OP_WRITE_FIXED] = {
		.needs_file		= 1,
		.hash_reg_file		= 1,
		.unbound_nonreg_file	= 1,
		.pollout		= 1,
		.plug			= 1,
		.async_size		= sizeof(struct io_async_rw),
		.work_flags		= IO_WQ_WORK_BLKCG | IO_WQ_WORK_FSIZE |
						IO_WQ_WORK_MM,
	},
	[IORING_OP_POLL_ADD] = {
		.needs_file		= 1,
		.unbound_nonreg_file	= 1,
	},
	[IORING_OP_POLL_REMOVE] = {},
	[IORING_OP_SYNC_FILE_RANGE] = {
		.needs_file		= 1,
		.work_flags		= IO_WQ_WORK_BLKCG,
	},
	[IORING_OP_SENDMSG] = {
		.needs_file		= 1,
		.unbound_nonreg_file	= 1,
		.pollout		= 1,
		.needs_async_data	= 1,
		.async_size		= sizeof(struct io_async_msghdr),
		.work_flags		= IO_WQ_WORK_MM | IO_WQ_WORK_BLKCG |
						IO_WQ_WORK_FS,
	},
	[IORING_OP_RECVMSG] = {
		.needs_file		= 1,
		.unbound_nonreg_file	= 1,
		.pollin			= 1,
		.buffer_select		= 1,
		.needs_async_data	= 1,
		.async_size		= sizeof(struct io_async_msghdr),
		.work_flags		= IO_WQ_WORK_MM | IO_WQ_WORK_BLKCG |
						IO_WQ_WORK_FS,
	},
	[IORING_OP_TIMEOUT] = {
		.needs_async_data	= 1,
		.async_size		= sizeof(struct io_timeout_data),
		.work_flags		= IO_WQ_WORK_MM,
	},
	[IORING_OP_TIMEOUT_REMOVE] = {
		/* used by timeout updates' prep() */
		.work_flags		= IO_WQ_WORK_MM,
	},
	[IORING_OP_ACCEPT] = {
		.needs_file		= 1,
		.unbound_nonreg_file	= 1,
		.pollin			= 1,
		.work_flags		= IO_WQ_WORK_MM | IO_WQ_WORK_FILES,
	},
	[IORING_OP_ASYNC_CANCEL] = {},
	[IORING_OP_LINK_TIMEOUT] = {
		.needs_async_data	= 1,
		.async_size		= sizeof(struct io_timeout_data),
		.work_flags		= IO_WQ_WORK_MM,
	},
	[IORING_OP_CONNECT] = {
		.needs_file		= 1,
		.unbound_nonreg_file	= 1,
		.pollout		= 1,
		.needs_async_data	= 1,
		.async_size		= sizeof(struct io_async_connect),
		.work_flags		= IO_WQ_WORK_MM,
	},
	[IORING_OP_FALLOCATE] = {
		.needs_file		= 1,
		.work_flags		= IO_WQ_WORK_BLKCG | IO_WQ_WORK_FSIZE,
	},
	[IORING_OP_OPENAT] = {
		.work_flags		= IO_WQ_WORK_FILES | IO_WQ_WORK_BLKCG |
						IO_WQ_WORK_FS | IO_WQ_WORK_MM,
	},
	[IORING_OP_CLOSE] = {
		.work_flags		= IO_WQ_WORK_FILES | IO_WQ_WORK_BLKCG,
	},
	[IORING_OP_FILES_UPDATE] = {
		.work_flags		= IO_WQ_WORK_FILES | IO_WQ_WORK_MM,
	},
	[IORING_OP_STATX] = {
		.work_flags		= IO_WQ_WORK_FILES | IO_WQ_WORK_MM |
						IO_WQ_WORK_FS | IO_WQ_WORK_BLKCG,
	},
	[IORING_OP_READ] = {
		.needs_file		= 1,
		.unbound_nonreg_file	= 1,
		.pollin			= 1,
		.buffer_select		= 1,
		.plug			= 1,
		.async_size		= sizeof(struct io_async_rw),
		.work_flags		= IO_WQ_WORK_MM | IO_WQ_WORK_BLKCG,
	},
	[IORING_OP_WRITE] = {
		.needs_file		= 1,
		.unbound_nonreg_file	= 1,
		.pollout		= 1,
		.plug			= 1,
		.async_size		= sizeof(struct io_async_rw),
		.work_flags		= IO_WQ_WORK_MM | IO_WQ_WORK_BLKCG |
						IO_WQ_WORK_FSIZE,
	},
	[IORING_OP_FADVISE] = {
		.needs_file		= 1,
		.work_flags		= IO_WQ_WORK_BLKCG,
	},
	[IORING_OP_MADVISE] = {
		.work_flags		= IO_WQ_WORK_MM | IO_WQ_WORK_BLKCG,
	},
	[IORING_OP_SEND] = {
		.needs_file		= 1,
		.unbound_nonreg_file	= 1,
		.pollout		= 1,
		.work_flags		= IO_WQ_WORK_MM | IO_WQ_WORK_BLKCG,
	},
	[IORING_OP_RECV] = {
		.needs_file		= 1,
		.unbound_nonreg_file	= 1,
		.pollin			= 1,
		.buffer_select		= 1,
		.work_flags		= IO_WQ_WORK_MM | IO_WQ_WORK_BLKCG,
	},
	[IORING_OP_OPENAT2] = {
		.work_flags		= IO_WQ_WORK_FILES | IO_WQ_WORK_FS |
						IO_WQ_WORK_BLKCG | IO_WQ_WORK_MM,
	},
	[IORING_OP_EPOLL_CTL] = {
		.unbound_nonreg_file	= 1,
		.work_flags		= IO_WQ_WORK_FILES,
	},
	[IORING_OP_SPLICE] = {
		.needs_file		= 1,
		.hash_reg_file		= 1,
		.unbound_nonreg_file	= 1,
		.work_flags		= IO_WQ_WORK_BLKCG,
	},
	[IORING_OP_PROVIDE_BUFFERS] = {},
	[IORING_OP_REMOVE_BUFFERS] = {},
	[IORING_OP_TEE] = {
		.needs_file		= 1,
		.hash_reg_file		= 1,
		.unbound_nonreg_file	= 1,
	},
	[IORING_OP_SHUTDOWN] = {
		.needs_file		= 1,
	},
	[IORING_OP_RENAMEAT] = {
		.work_flags		= IO_WQ_WORK_MM | IO_WQ_WORK_FILES |
						IO_WQ_WORK_FS | IO_WQ_WORK_BLKCG,
	},
	[IORING_OP_UNLINKAT] = {
		.work_flags		= IO_WQ_WORK_MM | IO_WQ_WORK_FILES |
						IO_WQ_WORK_FS | IO_WQ_WORK_BLKCG,
	},
};

static void io_uring_try_cancel_requests(struct io_ring_ctx *ctx,
					 struct task_struct *task,
					 struct files_struct *files);
static void destroy_fixed_rsrc_ref_node(struct fixed_rsrc_ref_node *ref_node);
static struct fixed_rsrc_ref_node *alloc_fixed_rsrc_ref_node(
			struct io_ring_ctx *ctx);
static void init_fixed_file_ref_node(struct io_ring_ctx *ctx,
				     struct fixed_rsrc_ref_node *ref_node);

static bool io_rw_reissue(struct io_kiocb *req);
static void io_cqring_fill_event(struct io_kiocb *req, long res);
static void io_put_req(struct io_kiocb *req);
static void io_put_req_deferred(struct io_kiocb *req, int nr);
static void io_double_put_req(struct io_kiocb *req);
static void io_dismantle_req(struct io_kiocb *req);
static void io_put_task(struct task_struct *task, int nr);
static void io_queue_next(struct io_kiocb *req);
static struct io_kiocb *io_prep_linked_timeout(struct io_kiocb *req);
static void __io_queue_linked_timeout(struct io_kiocb *req);
static void io_queue_linked_timeout(struct io_kiocb *req);
static int __io_sqe_files_update(struct io_ring_ctx *ctx,
				 struct io_uring_rsrc_update *ip,
				 unsigned nr_args);
static void __io_clean_op(struct io_kiocb *req);
static struct file *io_file_get(struct io_submit_state *state,
				struct io_kiocb *req, int fd, bool fixed);
static void __io_queue_sqe(struct io_kiocb *req);
static void io_rsrc_put_work(struct work_struct *work);

static int io_import_iovec(int rw, struct io_kiocb *req, struct iovec **iovec,
			   struct iov_iter *iter, bool needs_lock);
static int io_setup_async_rw(struct io_kiocb *req, const struct iovec *iovec,
			     const struct iovec *fast_iov,
			     struct iov_iter *iter, bool force);
static void io_req_task_queue(struct io_kiocb *req);
static void io_submit_flush_completions(struct io_comp_state *cs,
					struct io_ring_ctx *ctx);

static struct kmem_cache *req_cachep;

static const struct file_operations io_uring_fops;

struct sock *io_uring_get_socket(struct file *file)
{
#if defined(CONFIG_UNIX)
	if (file->f_op == &io_uring_fops) {
		struct io_ring_ctx *ctx = file->private_data;

		return ctx->ring_sock->sk;
	}
#endif
	return NULL;
}
EXPORT_SYMBOL(io_uring_get_socket);

#define io_for_each_link(pos, head) \
	for (pos = (head); pos; pos = pos->link)

static inline void io_clean_op(struct io_kiocb *req)
{
	if (req->flags & (REQ_F_NEED_CLEANUP | REQ_F_BUFFER_SELECTED))
		__io_clean_op(req);
}

static inline void io_set_resource_node(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;

	if (!req->fixed_rsrc_refs) {
		req->fixed_rsrc_refs = &ctx->file_data->node->refs;
		percpu_ref_get(req->fixed_rsrc_refs);
	}
}

static bool io_match_task(struct io_kiocb *head,
			  struct task_struct *task,
			  struct files_struct *files)
{
	struct io_kiocb *req;

	if (task && head->task != task) {
		/* in terms of cancelation, always match if req task is dead */
		if (head->task->flags & PF_EXITING)
			return true;
		return false;
	}
	if (!files)
		return true;

	io_for_each_link(req, head) {
		if (!(req->flags & REQ_F_WORK_INITIALIZED))
			continue;
		if (req->file && req->file->f_op == &io_uring_fops)
			return true;
		if ((req->work.flags & IO_WQ_WORK_FILES) &&
		    req->work.identity->files == files)
			return true;
	}
	return false;
}

static void io_sq_thread_drop_mm_files(void)
{
	struct files_struct *files = current->files;
	struct mm_struct *mm = current->mm;

	if (mm) {
		kthread_unuse_mm(mm);
		mmput(mm);
		current->mm = NULL;
	}
	if (files) {
		struct nsproxy *nsproxy = current->nsproxy;

		task_lock(current);
		current->files = NULL;
		current->nsproxy = NULL;
		task_unlock(current);
		put_files_struct(files);
		put_nsproxy(nsproxy);
	}
}

static int __io_sq_thread_acquire_files(struct io_ring_ctx *ctx)
{
	if (!current->files) {
		struct files_struct *files;
		struct nsproxy *nsproxy;

		task_lock(ctx->sqo_task);
		files = ctx->sqo_task->files;
		if (!files) {
			task_unlock(ctx->sqo_task);
			return -EOWNERDEAD;
		}
		atomic_inc(&files->count);
		get_nsproxy(ctx->sqo_task->nsproxy);
		nsproxy = ctx->sqo_task->nsproxy;
		task_unlock(ctx->sqo_task);

		task_lock(current);
		current->files = files;
		current->nsproxy = nsproxy;
		task_unlock(current);
	}
	return 0;
}

static int __io_sq_thread_acquire_mm(struct io_ring_ctx *ctx)
{
	struct mm_struct *mm;

	if (current->mm)
		return 0;

	task_lock(ctx->sqo_task);
	mm = ctx->sqo_task->mm;
	if (unlikely(!mm || !mmget_not_zero(mm)))
		mm = NULL;
	task_unlock(ctx->sqo_task);

	if (mm) {
		kthread_use_mm(mm);
		return 0;
	}

	return -EFAULT;
}

static int __io_sq_thread_acquire_mm_files(struct io_ring_ctx *ctx,
					   struct io_kiocb *req)
{
	const struct io_op_def *def = &io_op_defs[req->opcode];
	int ret;

	if (def->work_flags & IO_WQ_WORK_MM) {
		ret = __io_sq_thread_acquire_mm(ctx);
		if (unlikely(ret))
			return ret;
	}

	if (def->needs_file || (def->work_flags & IO_WQ_WORK_FILES)) {
		ret = __io_sq_thread_acquire_files(ctx);
		if (unlikely(ret))
			return ret;
	}

	return 0;
}

static inline int io_sq_thread_acquire_mm_files(struct io_ring_ctx *ctx,
						struct io_kiocb *req)
{
	if (!(ctx->flags & IORING_SETUP_SQPOLL))
		return 0;
	return __io_sq_thread_acquire_mm_files(ctx, req);
}

static void io_sq_thread_associate_blkcg(struct io_ring_ctx *ctx,
					 struct cgroup_subsys_state **cur_css)

{
#ifdef CONFIG_BLK_CGROUP
	/* puts the old one when swapping */
	if (*cur_css != ctx->sqo_blkcg_css) {
		kthread_associate_blkcg(ctx->sqo_blkcg_css);
		*cur_css = ctx->sqo_blkcg_css;
	}
#endif
}

static void io_sq_thread_unassociate_blkcg(void)
{
#ifdef CONFIG_BLK_CGROUP
	kthread_associate_blkcg(NULL);
#endif
}

static inline void req_set_fail_links(struct io_kiocb *req)
{
	if ((req->flags & (REQ_F_LINK | REQ_F_HARDLINK)) == REQ_F_LINK)
		req->flags |= REQ_F_FAIL_LINK;
}

/*
 * None of these are dereferenced, they are simply used to check if any of
 * them have changed. If we're under current and check they are still the
 * same, we're fine to grab references to them for actual out-of-line use.
 */
static void io_init_identity(struct io_identity *id)
{
	id->files = current->files;
	id->mm = current->mm;
#ifdef CONFIG_BLK_CGROUP
	rcu_read_lock();
	id->blkcg_css = blkcg_css();
	rcu_read_unlock();
#endif
	id->creds = current_cred();
	id->nsproxy = current->nsproxy;
	id->fs = current->fs;
	id->fsize = rlimit(RLIMIT_FSIZE);
#ifdef CONFIG_AUDIT
	id->loginuid = current->loginuid;
	id->sessionid = current->sessionid;
#endif
	refcount_set(&id->count, 1);
}

static inline void __io_req_init_async(struct io_kiocb *req)
{
	memset(&req->work, 0, sizeof(req->work));
	req->flags |= REQ_F_WORK_INITIALIZED;
}

/*
 * Note: must call io_req_init_async() for the first time you
 * touch any members of io_wq_work.
 */
static inline void io_req_init_async(struct io_kiocb *req)
{
	struct io_uring_task *tctx = current->io_uring;

	if (req->flags & REQ_F_WORK_INITIALIZED)
		return;

	__io_req_init_async(req);

	/* Grab a ref if this isn't our static identity */
	req->work.identity = tctx->identity;
	if (tctx->identity != &tctx->__identity)
		refcount_inc(&req->work.identity->count);
}

static void io_ring_ctx_ref_free(struct percpu_ref *ref)
{
	struct io_ring_ctx *ctx = container_of(ref, struct io_ring_ctx, refs);

	complete(&ctx->ref_comp);
}

static inline bool io_is_timeout_noseq(struct io_kiocb *req)
{
	return !req->timeout.off;
}

static struct io_ring_ctx *io_ring_ctx_alloc(struct io_uring_params *p)
{
	struct io_ring_ctx *ctx;
	int hash_bits;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	/*
	 * Use 5 bits less than the max cq entries, that should give us around
	 * 32 entries per hash list if totally full and uniformly spread.
	 */
	hash_bits = ilog2(p->cq_entries);
	hash_bits -= 5;
	if (hash_bits <= 0)
		hash_bits = 1;
	ctx->cancel_hash_bits = hash_bits;
	ctx->cancel_hash = kmalloc((1U << hash_bits) * sizeof(struct hlist_head),
					GFP_KERNEL);
	if (!ctx->cancel_hash)
		goto err;
	__hash_init(ctx->cancel_hash, 1U << hash_bits);

	if (percpu_ref_init(&ctx->refs, io_ring_ctx_ref_free,
			    PERCPU_REF_ALLOW_REINIT, GFP_KERNEL))
		goto err;

	ctx->flags = p->flags;
	init_waitqueue_head(&ctx->sqo_sq_wait);
	INIT_LIST_HEAD(&ctx->sqd_list);
	init_waitqueue_head(&ctx->cq_wait);
	INIT_LIST_HEAD(&ctx->cq_overflow_list);
	init_completion(&ctx->ref_comp);
	init_completion(&ctx->sq_thread_comp);
	idr_init(&ctx->io_buffer_idr);
	idr_init(&ctx->personality_idr);
	mutex_init(&ctx->uring_lock);
	init_waitqueue_head(&ctx->wait);
	spin_lock_init(&ctx->completion_lock);
	INIT_LIST_HEAD(&ctx->iopoll_list);
	INIT_LIST_HEAD(&ctx->defer_list);
	INIT_LIST_HEAD(&ctx->timeout_list);
	spin_lock_init(&ctx->inflight_lock);
	INIT_LIST_HEAD(&ctx->inflight_list);
	spin_lock_init(&ctx->rsrc_ref_lock);
	INIT_LIST_HEAD(&ctx->rsrc_ref_list);
	INIT_DELAYED_WORK(&ctx->rsrc_put_work, io_rsrc_put_work);
	init_llist_head(&ctx->rsrc_put_llist);
	INIT_LIST_HEAD(&ctx->submit_state.comp.free_list);
	INIT_LIST_HEAD(&ctx->submit_state.comp.locked_free_list);
	return ctx;
err:
	kfree(ctx->cancel_hash);
	kfree(ctx);
	return NULL;
}

static bool req_need_defer(struct io_kiocb *req, u32 seq)
{
	if (unlikely(req->flags & REQ_F_IO_DRAIN)) {
		struct io_ring_ctx *ctx = req->ctx;

		return seq != ctx->cached_cq_tail
				+ READ_ONCE(ctx->cached_cq_overflow);
	}

	return false;
}

static void io_put_identity(struct io_uring_task *tctx, struct io_kiocb *req)
{
	if (req->work.identity == &tctx->__identity)
		return;
	if (refcount_dec_and_test(&req->work.identity->count))
		kfree(req->work.identity);
}

static void io_req_clean_work(struct io_kiocb *req)
{
	if (!(req->flags & REQ_F_WORK_INITIALIZED))
		return;

	if (req->work.flags & IO_WQ_WORK_MM)
		mmdrop(req->work.identity->mm);
#ifdef CONFIG_BLK_CGROUP
	if (req->work.flags & IO_WQ_WORK_BLKCG)
		css_put(req->work.identity->blkcg_css);
#endif
	if (req->work.flags & IO_WQ_WORK_CREDS)
		put_cred(req->work.identity->creds);
	if (req->work.flags & IO_WQ_WORK_FS) {
		struct fs_struct *fs = req->work.identity->fs;

		spin_lock(&req->work.identity->fs->lock);
		if (--fs->users)
			fs = NULL;
		spin_unlock(&req->work.identity->fs->lock);
		if (fs)
			free_fs_struct(fs);
	}
	if (req->work.flags & IO_WQ_WORK_FILES) {
		put_files_struct(req->work.identity->files);
		put_nsproxy(req->work.identity->nsproxy);
	}
	if (req->flags & REQ_F_INFLIGHT) {
		struct io_ring_ctx *ctx = req->ctx;
		struct io_uring_task *tctx = req->task->io_uring;
		unsigned long flags;

		spin_lock_irqsave(&ctx->inflight_lock, flags);
		list_del(&req->inflight_entry);
		spin_unlock_irqrestore(&ctx->inflight_lock, flags);
		req->flags &= ~REQ_F_INFLIGHT;
		if (atomic_read(&tctx->in_idle))
			wake_up(&tctx->wait);
	}

	req->flags &= ~REQ_F_WORK_INITIALIZED;
	req->work.flags &= ~(IO_WQ_WORK_MM | IO_WQ_WORK_BLKCG | IO_WQ_WORK_FS |
			     IO_WQ_WORK_CREDS | IO_WQ_WORK_FILES);
	io_put_identity(req->task->io_uring, req);
}

/*
 * Create a private copy of io_identity, since some fields don't match
 * the current context.
 */
static bool io_identity_cow(struct io_kiocb *req)
{
	struct io_uring_task *tctx = current->io_uring;
	const struct cred *creds = NULL;
	struct io_identity *id;

	if (req->work.flags & IO_WQ_WORK_CREDS)
		creds = req->work.identity->creds;

	id = kmemdup(req->work.identity, sizeof(*id), GFP_KERNEL);
	if (unlikely(!id)) {
		req->work.flags |= IO_WQ_WORK_CANCEL;
		return false;
	}

	/*
	 * We can safely just re-init the creds we copied  Either the field
	 * matches the current one, or we haven't grabbed it yet. The only
	 * exception is ->creds, through registered personalities, so handle
	 * that one separately.
	 */
	io_init_identity(id);
	if (creds)
		id->creds = creds;

	/* add one for this request */
	refcount_inc(&id->count);

	/* drop tctx and req identity references, if needed */
	if (tctx->identity != &tctx->__identity &&
	    refcount_dec_and_test(&tctx->identity->count))
		kfree(tctx->identity);
	if (req->work.identity != &tctx->__identity &&
	    refcount_dec_and_test(&req->work.identity->count))
		kfree(req->work.identity);

	req->work.identity = id;
	tctx->identity = id;
	return true;
}

static void io_req_track_inflight(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;

	if (!(req->flags & REQ_F_INFLIGHT)) {
		io_req_init_async(req);
		req->flags |= REQ_F_INFLIGHT;

		spin_lock_irq(&ctx->inflight_lock);
		list_add(&req->inflight_entry, &ctx->inflight_list);
		spin_unlock_irq(&ctx->inflight_lock);
	}
}

static bool io_grab_identity(struct io_kiocb *req)
{
	const struct io_op_def *def = &io_op_defs[req->opcode];
	struct io_identity *id = req->work.identity;

	if (def->work_flags & IO_WQ_WORK_FSIZE) {
		if (id->fsize != rlimit(RLIMIT_FSIZE))
			return false;
		req->work.flags |= IO_WQ_WORK_FSIZE;
	}
#ifdef CONFIG_BLK_CGROUP
	if (!(req->work.flags & IO_WQ_WORK_BLKCG) &&
	    (def->work_flags & IO_WQ_WORK_BLKCG)) {
		rcu_read_lock();
		if (id->blkcg_css != blkcg_css()) {
			rcu_read_unlock();
			return false;
		}
		/*
		 * This should be rare, either the cgroup is dying or the task
		 * is moving cgroups. Just punt to root for the handful of ios.
		 */
		if (css_tryget_online(id->blkcg_css))
			req->work.flags |= IO_WQ_WORK_BLKCG;
		rcu_read_unlock();
	}
#endif
	if (!(req->work.flags & IO_WQ_WORK_CREDS)) {
		if (id->creds != current_cred())
			return false;
		get_cred(id->creds);
		req->work.flags |= IO_WQ_WORK_CREDS;
	}
#ifdef CONFIG_AUDIT
	if (!uid_eq(current->loginuid, id->loginuid) ||
	    current->sessionid != id->sessionid)
		return false;
#endif
	if (!(req->work.flags & IO_WQ_WORK_FS) &&
	    (def->work_flags & IO_WQ_WORK_FS)) {
		if (current->fs != id->fs)
			return false;
		spin_lock(&id->fs->lock);
		if (!id->fs->in_exec) {
			id->fs->users++;
			req->work.flags |= IO_WQ_WORK_FS;
		} else {
			req->work.flags |= IO_WQ_WORK_CANCEL;
		}
		spin_unlock(&current->fs->lock);
	}
	if (!(req->work.flags & IO_WQ_WORK_FILES) &&
	    (def->work_flags & IO_WQ_WORK_FILES) &&
	    !(req->flags & REQ_F_NO_FILE_TABLE)) {
		if (id->files != current->files ||
		    id->nsproxy != current->nsproxy)
			return false;
		atomic_inc(&id->files->count);
		get_nsproxy(id->nsproxy);
		req->work.flags |= IO_WQ_WORK_FILES;
		io_req_track_inflight(req);
	}
	if (!(req->work.flags & IO_WQ_WORK_MM) &&
	    (def->work_flags & IO_WQ_WORK_MM)) {
		if (id->mm != current->mm)
			return false;
		mmgrab(id->mm);
		req->work.flags |= IO_WQ_WORK_MM;
	}

	return true;
}

static void io_prep_async_work(struct io_kiocb *req)
{
	const struct io_op_def *def = &io_op_defs[req->opcode];
	struct io_ring_ctx *ctx = req->ctx;

	io_req_init_async(req);

	if (req->flags & REQ_F_FORCE_ASYNC)
		req->work.flags |= IO_WQ_WORK_CONCURRENT;

	if (req->flags & REQ_F_ISREG) {
		if (def->hash_reg_file || (ctx->flags & IORING_SETUP_IOPOLL))
			io_wq_hash_work(&req->work, file_inode(req->file));
	} else {
		if (def->unbound_nonreg_file)
			req->work.flags |= IO_WQ_WORK_UNBOUND;
	}

	/* if we fail grabbing identity, we must COW, regrab, and retry */
	if (io_grab_identity(req))
		return;

	if (!io_identity_cow(req))
		return;

	/* can't fail at this point */
	if (!io_grab_identity(req))
		WARN_ON(1);
}

static void io_prep_async_link(struct io_kiocb *req)
{
	struct io_kiocb *cur;

	io_for_each_link(cur, req)
		io_prep_async_work(cur);
}

static struct io_kiocb *__io_queue_async_work(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_kiocb *link = io_prep_linked_timeout(req);

	trace_io_uring_queue_async_work(ctx, io_wq_is_hashed(&req->work), req,
					&req->work, req->flags);
	io_wq_enqueue(ctx->io_wq, &req->work);
	return link;
}

static void io_queue_async_work(struct io_kiocb *req)
{
	struct io_kiocb *link;

	/* init ->work of the whole link before punting */
	io_prep_async_link(req);
	link = __io_queue_async_work(req);

	if (link)
		io_queue_linked_timeout(link);
}

static void io_kill_timeout(struct io_kiocb *req)
{
	struct io_timeout_data *io = req->async_data;
	int ret;

	ret = hrtimer_try_to_cancel(&io->timer);
	if (ret != -1) {
		atomic_set(&req->ctx->cq_timeouts,
			atomic_read(&req->ctx->cq_timeouts) + 1);
		list_del_init(&req->timeout.list);
		io_cqring_fill_event(req, 0);
		io_put_req_deferred(req, 1);
	}
}

/*
 * Returns true if we found and killed one or more timeouts
 */
static bool io_kill_timeouts(struct io_ring_ctx *ctx, struct task_struct *tsk,
			     struct files_struct *files)
{
	struct io_kiocb *req, *tmp;
	int canceled = 0;

	spin_lock_irq(&ctx->completion_lock);
	list_for_each_entry_safe(req, tmp, &ctx->timeout_list, timeout.list) {
		if (io_match_task(req, tsk, files)) {
			io_kill_timeout(req);
			canceled++;
		}
	}
	spin_unlock_irq(&ctx->completion_lock);
	return canceled != 0;
}

static void __io_queue_deferred(struct io_ring_ctx *ctx)
{
	do {
		struct io_defer_entry *de = list_first_entry(&ctx->defer_list,
						struct io_defer_entry, list);

		if (req_need_defer(de->req, de->seq))
			break;
		list_del_init(&de->list);
		io_req_task_queue(de->req);
		kfree(de);
	} while (!list_empty(&ctx->defer_list));
}

static void io_flush_timeouts(struct io_ring_ctx *ctx)
{
	u32 seq;

	if (list_empty(&ctx->timeout_list))
		return;

	seq = ctx->cached_cq_tail - atomic_read(&ctx->cq_timeouts);

	do {
		u32 events_needed, events_got;
		struct io_kiocb *req = list_first_entry(&ctx->timeout_list,
						struct io_kiocb, timeout.list);

		if (io_is_timeout_noseq(req))
			break;

		/*
		 * Since seq can easily wrap around over time, subtract
		 * the last seq at which timeouts were flushed before comparing.
		 * Assuming not more than 2^31-1 events have happened since,
		 * these subtractions won't have wrapped, so we can check if
		 * target is in [last_seq, current_seq] by comparing the two.
		 */
		events_needed = req->timeout.target_seq - ctx->cq_last_tm_flush;
		events_got = seq - ctx->cq_last_tm_flush;
		if (events_got < events_needed)
			break;

		list_del_init(&req->timeout.list);
		io_kill_timeout(req);
	} while (!list_empty(&ctx->timeout_list));

	ctx->cq_last_tm_flush = seq;
}

static void io_commit_cqring(struct io_ring_ctx *ctx)
{
	io_flush_timeouts(ctx);

	/* order cqe stores with ring update */
	smp_store_release(&ctx->rings->cq.tail, ctx->cached_cq_tail);

	if (unlikely(!list_empty(&ctx->defer_list)))
		__io_queue_deferred(ctx);
}

static inline bool io_sqring_full(struct io_ring_ctx *ctx)
{
	struct io_rings *r = ctx->rings;

	return READ_ONCE(r->sq.tail) - ctx->cached_sq_head == r->sq_ring_entries;
}

static inline unsigned int __io_cqring_events(struct io_ring_ctx *ctx)
{
	return ctx->cached_cq_tail - READ_ONCE(ctx->rings->cq.head);
}

static struct io_uring_cqe *io_get_cqring(struct io_ring_ctx *ctx)
{
	struct io_rings *rings = ctx->rings;
	unsigned tail;

	/*
	 * writes to the cq entry need to come after reading head; the
	 * control dependency is enough as we're using WRITE_ONCE to
	 * fill the cq entry
	 */
	if (__io_cqring_events(ctx) == rings->cq_ring_entries)
		return NULL;

	tail = ctx->cached_cq_tail++;
	return &rings->cqes[tail & ctx->cq_mask];
}

static inline bool io_should_trigger_evfd(struct io_ring_ctx *ctx)
{
	if (!ctx->cq_ev_fd)
		return false;
	if (READ_ONCE(ctx->rings->cq_flags) & IORING_CQ_EVENTFD_DISABLED)
		return false;
	if (!ctx->eventfd_async)
		return true;
	return io_wq_current_is_worker();
}

static void io_cqring_ev_posted(struct io_ring_ctx *ctx)
{
	/* see waitqueue_active() comment */
	smp_mb();

	if (waitqueue_active(&ctx->wait))
		wake_up(&ctx->wait);
	if (ctx->sq_data && waitqueue_active(&ctx->sq_data->wait))
		wake_up(&ctx->sq_data->wait);
	if (io_should_trigger_evfd(ctx))
		eventfd_signal(ctx->cq_ev_fd, 1);
	if (waitqueue_active(&ctx->cq_wait)) {
		wake_up_interruptible(&ctx->cq_wait);
		kill_fasync(&ctx->cq_fasync, SIGIO, POLL_IN);
	}
}

static void io_cqring_ev_posted_iopoll(struct io_ring_ctx *ctx)
{
	/* see waitqueue_active() comment */
	smp_mb();

	if (ctx->flags & IORING_SETUP_SQPOLL) {
		if (waitqueue_active(&ctx->wait))
			wake_up(&ctx->wait);
	}
	if (io_should_trigger_evfd(ctx))
		eventfd_signal(ctx->cq_ev_fd, 1);
	if (waitqueue_active(&ctx->cq_wait)) {
		wake_up_interruptible(&ctx->cq_wait);
		kill_fasync(&ctx->cq_fasync, SIGIO, POLL_IN);
	}
}

/* Returns true if there are no backlogged entries after the flush */
static bool __io_cqring_overflow_flush(struct io_ring_ctx *ctx, bool force,
				       struct task_struct *tsk,
				       struct files_struct *files)
{
	struct io_rings *rings = ctx->rings;
	struct io_kiocb *req, *tmp;
	struct io_uring_cqe *cqe;
	unsigned long flags;
	bool all_flushed, posted;
	LIST_HEAD(list);

	if (!force && __io_cqring_events(ctx) == rings->cq_ring_entries)
		return false;

	posted = false;
	spin_lock_irqsave(&ctx->completion_lock, flags);
	list_for_each_entry_safe(req, tmp, &ctx->cq_overflow_list, compl.list) {
		if (!io_match_task(req, tsk, files))
			continue;

		cqe = io_get_cqring(ctx);
		if (!cqe && !force)
			break;

		list_move(&req->compl.list, &list);
		if (cqe) {
			WRITE_ONCE(cqe->user_data, req->user_data);
			WRITE_ONCE(cqe->res, req->result);
			WRITE_ONCE(cqe->flags, req->compl.cflags);
		} else {
			ctx->cached_cq_overflow++;
			WRITE_ONCE(ctx->rings->cq_overflow,
				   ctx->cached_cq_overflow);
		}
		posted = true;
	}

	all_flushed = list_empty(&ctx->cq_overflow_list);
	if (all_flushed) {
		clear_bit(0, &ctx->sq_check_overflow);
		clear_bit(0, &ctx->cq_check_overflow);
		ctx->rings->sq_flags &= ~IORING_SQ_CQ_OVERFLOW;
	}

	if (posted)
		io_commit_cqring(ctx);
	spin_unlock_irqrestore(&ctx->completion_lock, flags);
	if (posted)
		io_cqring_ev_posted(ctx);

	while (!list_empty(&list)) {
		req = list_first_entry(&list, struct io_kiocb, compl.list);
		list_del(&req->compl.list);
		io_put_req(req);
	}

	return all_flushed;
}

static void io_cqring_overflow_flush(struct io_ring_ctx *ctx, bool force,
				     struct task_struct *tsk,
				     struct files_struct *files)
{
	if (test_bit(0, &ctx->cq_check_overflow)) {
		/* iopoll syncs against uring_lock, not completion_lock */
		if (ctx->flags & IORING_SETUP_IOPOLL)
			mutex_lock(&ctx->uring_lock);
		__io_cqring_overflow_flush(ctx, force, tsk, files);
		if (ctx->flags & IORING_SETUP_IOPOLL)
			mutex_unlock(&ctx->uring_lock);
	}
}

static void __io_cqring_fill_event(struct io_kiocb *req, long res, long cflags)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_uring_cqe *cqe;

	trace_io_uring_complete(ctx, req->user_data, res);

	/*
	 * If we can't get a cq entry, userspace overflowed the
	 * submission (by quite a lot). Increment the overflow count in
	 * the ring.
	 */
	cqe = io_get_cqring(ctx);
	if (likely(cqe)) {
		WRITE_ONCE(cqe->user_data, req->user_data);
		WRITE_ONCE(cqe->res, res);
		WRITE_ONCE(cqe->flags, cflags);
	} else if (ctx->cq_overflow_flushed ||
		   atomic_read(&req->task->io_uring->in_idle)) {
		/*
		 * If we're in ring overflow flush mode, or in task cancel mode,
		 * then we cannot store the request for later flushing, we need
		 * to drop it on the floor.
		 */
		ctx->cached_cq_overflow++;
		WRITE_ONCE(ctx->rings->cq_overflow, ctx->cached_cq_overflow);
	} else {
		if (list_empty(&ctx->cq_overflow_list)) {
			set_bit(0, &ctx->sq_check_overflow);
			set_bit(0, &ctx->cq_check_overflow);
			ctx->rings->sq_flags |= IORING_SQ_CQ_OVERFLOW;
		}
		io_clean_op(req);
		req->result = res;
		req->compl.cflags = cflags;
		refcount_inc(&req->refs);
		list_add_tail(&req->compl.list, &ctx->cq_overflow_list);
	}
}

static void io_cqring_fill_event(struct io_kiocb *req, long res)
{
	__io_cqring_fill_event(req, res, 0);
}

static inline void io_req_complete_post(struct io_kiocb *req, long res,
					unsigned int cflags)
{
	struct io_ring_ctx *ctx = req->ctx;
	unsigned long flags;

	spin_lock_irqsave(&ctx->completion_lock, flags);
	__io_cqring_fill_event(req, res, cflags);
	io_commit_cqring(ctx);
	/*
	 * If we're the last reference to this request, add to our locked
	 * free_list cache.
	 */
	if (refcount_dec_and_test(&req->refs)) {
		struct io_comp_state *cs = &ctx->submit_state.comp;

		io_dismantle_req(req);
		io_put_task(req->task, 1);
		list_add(&req->compl.list, &cs->locked_free_list);
		cs->locked_free_nr++;
	} else
		req = NULL;
	spin_unlock_irqrestore(&ctx->completion_lock, flags);

	io_cqring_ev_posted(ctx);
	if (req) {
		io_queue_next(req);
		percpu_ref_put(&ctx->refs);
	}
}

static void io_req_complete_state(struct io_kiocb *req, long res,
				  unsigned int cflags)
{
	io_clean_op(req);
	req->result = res;
	req->compl.cflags = cflags;
	req->flags |= REQ_F_COMPLETE_INLINE;
}

static inline void __io_req_complete(struct io_kiocb *req, unsigned issue_flags,
				     long res, unsigned cflags)
{
	if (issue_flags & IO_URING_F_COMPLETE_DEFER)
		io_req_complete_state(req, res, cflags);
	else
		io_req_complete_post(req, res, cflags);
}

static inline void io_req_complete(struct io_kiocb *req, long res)
{
	__io_req_complete(req, 0, res, 0);
}

static bool io_flush_cached_reqs(struct io_ring_ctx *ctx)
{
	struct io_submit_state *state = &ctx->submit_state;
	struct io_comp_state *cs = &state->comp;
	struct io_kiocb *req = NULL;

	/*
	 * If we have more than a batch's worth of requests in our IRQ side
	 * locked cache, grab the lock and move them over to our submission
	 * side cache.
	 */
	if (READ_ONCE(cs->locked_free_nr) > IO_COMPL_BATCH) {
		spin_lock_irq(&ctx->completion_lock);
		list_splice_init(&cs->locked_free_list, &cs->free_list);
		cs->locked_free_nr = 0;
		spin_unlock_irq(&ctx->completion_lock);
	}

	while (!list_empty(&cs->free_list)) {
		req = list_first_entry(&cs->free_list, struct io_kiocb,
					compl.list);
		list_del(&req->compl.list);
		state->reqs[state->free_reqs++] = req;
		if (state->free_reqs == ARRAY_SIZE(state->reqs))
			break;
	}

	return req != NULL;
}

static struct io_kiocb *io_alloc_req(struct io_ring_ctx *ctx)
{
	struct io_submit_state *state = &ctx->submit_state;

	BUILD_BUG_ON(IO_REQ_ALLOC_BATCH > ARRAY_SIZE(state->reqs));

	if (!state->free_reqs) {
		gfp_t gfp = GFP_KERNEL | __GFP_NOWARN;
		int ret;

		if (io_flush_cached_reqs(ctx))
			goto got_req;

		ret = kmem_cache_alloc_bulk(req_cachep, gfp, IO_REQ_ALLOC_BATCH,
					    state->reqs);

		/*
		 * Bulk alloc is all-or-nothing. If we fail to get a batch,
		 * retry single alloc to be on the safe side.
		 */
		if (unlikely(ret <= 0)) {
			state->reqs[0] = kmem_cache_alloc(req_cachep, gfp);
			if (!state->reqs[0])
				return NULL;
			ret = 1;
		}
		state->free_reqs = ret;
	}
got_req:
	state->free_reqs--;
	return state->reqs[state->free_reqs];
}

static inline void io_put_file(struct io_kiocb *req, struct file *file,
			  bool fixed)
{
	if (!fixed)
		fput(file);
}

static void io_dismantle_req(struct io_kiocb *req)
{
	io_clean_op(req);

	if (req->async_data)
		kfree(req->async_data);
	if (req->file)
		io_put_file(req, req->file, (req->flags & REQ_F_FIXED_FILE));
	if (req->fixed_rsrc_refs)
		percpu_ref_put(req->fixed_rsrc_refs);
	io_req_clean_work(req);
}

static inline void io_put_task(struct task_struct *task, int nr)
{
	struct io_uring_task *tctx = task->io_uring;

	percpu_counter_sub(&tctx->inflight, nr);
	if (unlikely(atomic_read(&tctx->in_idle)))
		wake_up(&tctx->wait);
	put_task_struct_many(task, nr);
}

static void __io_free_req(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;

	io_dismantle_req(req);
	io_put_task(req->task, 1);

	kmem_cache_free(req_cachep, req);
	percpu_ref_put(&ctx->refs);
}

static inline void io_remove_next_linked(struct io_kiocb *req)
{
	struct io_kiocb *nxt = req->link;

	req->link = nxt->link;
	nxt->link = NULL;
}

static void io_kill_linked_timeout(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_kiocb *link;
	bool cancelled = false;
	unsigned long flags;

	spin_lock_irqsave(&ctx->completion_lock, flags);
	link = req->link;

	/*
	 * Can happen if a linked timeout fired and link had been like
	 * req -> link t-out -> link t-out [-> ...]
	 */
	if (link && (link->flags & REQ_F_LTIMEOUT_ACTIVE)) {
		struct io_timeout_data *io = link->async_data;
		int ret;

		io_remove_next_linked(req);
		link->timeout.head = NULL;
		ret = hrtimer_try_to_cancel(&io->timer);
		if (ret != -1) {
			io_cqring_fill_event(link, -ECANCELED);
			io_commit_cqring(ctx);
			cancelled = true;
		}
	}
	req->flags &= ~REQ_F_LINK_TIMEOUT;
	spin_unlock_irqrestore(&ctx->completion_lock, flags);

	if (cancelled) {
		io_cqring_ev_posted(ctx);
		io_put_req(link);
	}
}


static void io_fail_links(struct io_kiocb *req)
{
	struct io_kiocb *link, *nxt;
	struct io_ring_ctx *ctx = req->ctx;
	unsigned long flags;

	spin_lock_irqsave(&ctx->completion_lock, flags);
	link = req->link;
	req->link = NULL;

	while (link) {
		nxt = link->link;
		link->link = NULL;

		trace_io_uring_fail_link(req, link);
		io_cqring_fill_event(link, -ECANCELED);

		/*
		 * It's ok to free under spinlock as they're not linked anymore,
		 * but avoid REQ_F_WORK_INITIALIZED because it may deadlock on
		 * work.fs->lock.
		 */
		if (link->flags & REQ_F_WORK_INITIALIZED)
			io_put_req_deferred(link, 2);
		else
			io_double_put_req(link);
		link = nxt;
	}
	io_commit_cqring(ctx);
	spin_unlock_irqrestore(&ctx->completion_lock, flags);

	io_cqring_ev_posted(ctx);
}

static struct io_kiocb *__io_req_find_next(struct io_kiocb *req)
{
	if (req->flags & REQ_F_LINK_TIMEOUT)
		io_kill_linked_timeout(req);

	/*
	 * If LINK is set, we have dependent requests in this chain. If we
	 * didn't fail this request, queue the first one up, moving any other
	 * dependencies to the next request. In case of failure, fail the rest
	 * of the chain.
	 */
	if (likely(!(req->flags & REQ_F_FAIL_LINK))) {
		struct io_kiocb *nxt = req->link;

		req->link = NULL;
		return nxt;
	}
	io_fail_links(req);
	return NULL;
}

static inline struct io_kiocb *io_req_find_next(struct io_kiocb *req)
{
	if (likely(!(req->flags & (REQ_F_LINK|REQ_F_HARDLINK))))
		return NULL;
	return __io_req_find_next(req);
}

static bool __tctx_task_work(struct io_uring_task *tctx)
{
	struct io_ring_ctx *ctx = NULL;
	struct io_wq_work_list list;
	struct io_wq_work_node *node;

	if (wq_list_empty(&tctx->task_list))
		return false;

	spin_lock_irq(&tctx->task_lock);
	list = tctx->task_list;
	INIT_WQ_LIST(&tctx->task_list);
	spin_unlock_irq(&tctx->task_lock);

	node = list.first;
	while (node) {
		struct io_wq_work_node *next = node->next;
		struct io_ring_ctx *this_ctx;
		struct io_kiocb *req;

		req = container_of(node, struct io_kiocb, io_task_work.node);
		this_ctx = req->ctx;
		req->task_work.func(&req->task_work);
		node = next;

		if (!ctx) {
			ctx = this_ctx;
		} else if (ctx != this_ctx) {
			mutex_lock(&ctx->uring_lock);
			io_submit_flush_completions(&ctx->submit_state.comp, ctx);
			mutex_unlock(&ctx->uring_lock);
			ctx = this_ctx;
		}
	}

	if (ctx && ctx->submit_state.comp.nr) {
		mutex_lock(&ctx->uring_lock);
		io_submit_flush_completions(&ctx->submit_state.comp, ctx);
		mutex_unlock(&ctx->uring_lock);
	}

	return list.first != NULL;
}

static void tctx_task_work(struct callback_head *cb)
{
	struct io_uring_task *tctx = container_of(cb, struct io_uring_task, task_work);

	while (__tctx_task_work(tctx))
		cond_resched();

	clear_bit(0, &tctx->task_state);
}

static int io_task_work_add(struct task_struct *tsk, struct io_kiocb *req,
			    enum task_work_notify_mode notify)
{
	struct io_uring_task *tctx = tsk->io_uring;
	struct io_wq_work_node *node, *prev;
	unsigned long flags;
	int ret;

	WARN_ON_ONCE(!tctx);

	spin_lock_irqsave(&tctx->task_lock, flags);
	wq_list_add_tail(&req->io_task_work.node, &tctx->task_list);
	spin_unlock_irqrestore(&tctx->task_lock, flags);

	/* task_work already pending, we're done */
	if (test_bit(0, &tctx->task_state) ||
	    test_and_set_bit(0, &tctx->task_state))
		return 0;

	if (!task_work_add(tsk, &tctx->task_work, notify))
		return 0;

	/*
	 * Slow path - we failed, find and delete work. if the work is not
	 * in the list, it got run and we're fine.
	 */
	ret = 0;
	spin_lock_irqsave(&tctx->task_lock, flags);
	wq_list_for_each(node, prev, &tctx->task_list) {
		if (&req->io_task_work.node == node) {
			wq_list_del(&tctx->task_list, node, prev);
			ret = 1;
			break;
		}
	}
	spin_unlock_irqrestore(&tctx->task_lock, flags);
	clear_bit(0, &tctx->task_state);
	return ret;
}

static int io_req_task_work_add(struct io_kiocb *req)
{
	struct task_struct *tsk = req->task;
	struct io_ring_ctx *ctx = req->ctx;
	enum task_work_notify_mode notify;
	int ret;

	if (tsk->flags & PF_EXITING)
		return -ESRCH;

	/*
	 * SQPOLL kernel thread doesn't need notification, just a wakeup. For
	 * all other cases, use TWA_SIGNAL unconditionally to ensure we're
	 * processing task_work. There's no reliable way to tell if TWA_RESUME
	 * will do the job.
	 */
	notify = TWA_NONE;
	if (!(ctx->flags & IORING_SETUP_SQPOLL))
		notify = TWA_SIGNAL;

	ret = io_task_work_add(tsk, req, notify);
	if (!ret)
		wake_up_process(tsk);

	return ret;
}

static void io_req_task_work_add_fallback(struct io_kiocb *req,
					  task_work_func_t cb)
{
	struct task_struct *tsk = io_wq_get_task(req->ctx->io_wq);

	init_task_work(&req->task_work, cb);
	task_work_add(tsk, &req->task_work, TWA_NONE);
	wake_up_process(tsk);
}

static void __io_req_task_cancel(struct io_kiocb *req, int error)
{
	struct io_ring_ctx *ctx = req->ctx;

	spin_lock_irq(&ctx->completion_lock);
	io_cqring_fill_event(req, error);
	io_commit_cqring(ctx);
	spin_unlock_irq(&ctx->completion_lock);

	io_cqring_ev_posted(ctx);
	req_set_fail_links(req);
	io_double_put_req(req);
}

static void io_req_task_cancel(struct callback_head *cb)
{
	struct io_kiocb *req = container_of(cb, struct io_kiocb, task_work);
	struct io_ring_ctx *ctx = req->ctx;

	__io_req_task_cancel(req, -ECANCELED);
	percpu_ref_put(&ctx->refs);
}

static void __io_req_task_submit(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;

	/* ctx stays valid until unlock, even if we drop all ours ctx->refs */
	mutex_lock(&ctx->uring_lock);
	if (!ctx->sqo_dead && !(current->flags & PF_EXITING) &&
	    !io_sq_thread_acquire_mm_files(ctx, req))
		__io_queue_sqe(req);
	else
		__io_req_task_cancel(req, -EFAULT);
	mutex_unlock(&ctx->uring_lock);

	if (ctx->flags & IORING_SETUP_SQPOLL)
		io_sq_thread_drop_mm_files();
}

static void io_req_task_submit(struct callback_head *cb)
{
	struct io_kiocb *req = container_of(cb, struct io_kiocb, task_work);

	__io_req_task_submit(req);
}

static void io_req_task_queue(struct io_kiocb *req)
{
	int ret;

	req->task_work.func = io_req_task_submit;
	ret = io_req_task_work_add(req);
	if (unlikely(ret)) {
		percpu_ref_get(&req->ctx->refs);
		io_req_task_work_add_fallback(req, io_req_task_cancel);
	}
}

static inline void io_queue_next(struct io_kiocb *req)
{
	struct io_kiocb *nxt = io_req_find_next(req);

	if (nxt)
		io_req_task_queue(nxt);
}

static void io_free_req(struct io_kiocb *req)
{
	io_queue_next(req);
	__io_free_req(req);
}

struct req_batch {
	struct task_struct	*task;
	int			task_refs;
	int			ctx_refs;
};

static inline void io_init_req_batch(struct req_batch *rb)
{
	rb->task_refs = 0;
	rb->ctx_refs = 0;
	rb->task = NULL;
}

static void io_req_free_batch_finish(struct io_ring_ctx *ctx,
				     struct req_batch *rb)
{
	if (rb->task)
		io_put_task(rb->task, rb->task_refs);
	if (rb->ctx_refs)
		percpu_ref_put_many(&ctx->refs, rb->ctx_refs);
}

static void io_req_free_batch(struct req_batch *rb, struct io_kiocb *req,
			      struct io_submit_state *state)
{
	io_queue_next(req);

	if (req->task != rb->task) {
		if (rb->task)
			io_put_task(rb->task, rb->task_refs);
		rb->task = req->task;
		rb->task_refs = 0;
	}
	rb->task_refs++;
	rb->ctx_refs++;

	io_dismantle_req(req);
	if (state->free_reqs != ARRAY_SIZE(state->reqs))
		state->reqs[state->free_reqs++] = req;
	else
		list_add(&req->compl.list, &state->comp.free_list);
}

static void io_submit_flush_completions(struct io_comp_state *cs,
					struct io_ring_ctx *ctx)
{
	int i, nr = cs->nr;
	struct io_kiocb *req;
	struct req_batch rb;

	io_init_req_batch(&rb);
	spin_lock_irq(&ctx->completion_lock);
	for (i = 0; i < nr; i++) {
		req = cs->reqs[i];
		__io_cqring_fill_event(req, req->result, req->compl.cflags);
	}
	io_commit_cqring(ctx);
	spin_unlock_irq(&ctx->completion_lock);

	io_cqring_ev_posted(ctx);
	for (i = 0; i < nr; i++) {
		req = cs->reqs[i];

		/* submission and completion refs */
		if (refcount_sub_and_test(2, &req->refs))
			io_req_free_batch(&rb, req, &ctx->submit_state);
	}

	io_req_free_batch_finish(ctx, &rb);
	cs->nr = 0;
}

/*
 * Drop reference to request, return next in chain (if there is one) if this
 * was the last reference to this request.
 */
static struct io_kiocb *io_put_req_find_next(struct io_kiocb *req)
{
	struct io_kiocb *nxt = NULL;

	if (refcount_dec_and_test(&req->refs)) {
		nxt = io_req_find_next(req);
		__io_free_req(req);
	}
	return nxt;
}

static void io_put_req(struct io_kiocb *req)
{
	if (refcount_dec_and_test(&req->refs))
		io_free_req(req);
}

static void io_put_req_deferred_cb(struct callback_head *cb)
{
	struct io_kiocb *req = container_of(cb, struct io_kiocb, task_work);

	io_free_req(req);
}

static void io_free_req_deferred(struct io_kiocb *req)
{
	int ret;

	req->task_work.func = io_put_req_deferred_cb;
	ret = io_req_task_work_add(req);
	if (unlikely(ret))
		io_req_task_work_add_fallback(req, io_put_req_deferred_cb);
}

static inline void io_put_req_deferred(struct io_kiocb *req, int refs)
{
	if (refcount_sub_and_test(refs, &req->refs))
		io_free_req_deferred(req);
}

static void io_double_put_req(struct io_kiocb *req)
{
	/* drop both submit and complete references */
	if (refcount_sub_and_test(2, &req->refs))
		io_free_req(req);
}

static unsigned io_cqring_events(struct io_ring_ctx *ctx)
{
	/* See comment at the top of this file */
	smp_rmb();
	return __io_cqring_events(ctx);
}

static inline unsigned int io_sqring_entries(struct io_ring_ctx *ctx)
{
	struct io_rings *rings = ctx->rings;

	/* make sure SQ entry isn't read before tail */
	return smp_load_acquire(&rings->sq.tail) - ctx->cached_sq_head;
}

static unsigned int io_put_kbuf(struct io_kiocb *req, struct io_buffer *kbuf)
{
	unsigned int cflags;

	cflags = kbuf->bid << IORING_CQE_BUFFER_SHIFT;
	cflags |= IORING_CQE_F_BUFFER;
	req->flags &= ~REQ_F_BUFFER_SELECTED;
	kfree(kbuf);
	return cflags;
}

static inline unsigned int io_put_rw_kbuf(struct io_kiocb *req)
{
	struct io_buffer *kbuf;

	kbuf = (struct io_buffer *) (unsigned long) req->rw.addr;
	return io_put_kbuf(req, kbuf);
}

static inline bool io_run_task_work(void)
{
	/*
	 * Not safe to run on exiting task, and the task_work handling will
	 * not add work to such a task.
	 */
	if (unlikely(current->flags & PF_EXITING))
		return false;
	if (current->task_works) {
		__set_current_state(TASK_RUNNING);
		task_work_run();
		return true;
	}

	return false;
}

/*
 * Find and free completed poll iocbs
 */
static void io_iopoll_complete(struct io_ring_ctx *ctx, unsigned int *nr_events,
			       struct list_head *done)
{
	struct req_batch rb;
	struct io_kiocb *req;

	/* order with ->result store in io_complete_rw_iopoll() */
	smp_rmb();

	io_init_req_batch(&rb);
	while (!list_empty(done)) {
		int cflags = 0;

		req = list_first_entry(done, struct io_kiocb, inflight_entry);
		list_del(&req->inflight_entry);

		if (READ_ONCE(req->result) == -EAGAIN) {
			req->iopoll_completed = 0;
			if (io_rw_reissue(req))
				continue;
		}

		if (req->flags & REQ_F_BUFFER_SELECTED)
			cflags = io_put_rw_kbuf(req);

		__io_cqring_fill_event(req, req->result, cflags);
		(*nr_events)++;

		if (refcount_dec_and_test(&req->refs))
			io_req_free_batch(&rb, req, &ctx->submit_state);
	}

	io_commit_cqring(ctx);
	io_cqring_ev_posted_iopoll(ctx);
	io_req_free_batch_finish(ctx, &rb);
}

static int io_do_iopoll(struct io_ring_ctx *ctx, unsigned int *nr_events,
			long min)
{
	struct io_kiocb *req, *tmp;
	LIST_HEAD(done);
	bool spin;
	int ret;

	/*
	 * Only spin for completions if we don't have multiple devices hanging
	 * off our complete list, and we're under the requested amount.
	 */
	spin = !ctx->poll_multi_file && *nr_events < min;

	ret = 0;
	list_for_each_entry_safe(req, tmp, &ctx->iopoll_list, inflight_entry) {
		struct kiocb *kiocb = &req->rw.kiocb;

		/*
		 * Move completed and retryable entries to our local lists.
		 * If we find a request that requires polling, break out
		 * and complete those lists first, if we have entries there.
		 */
		if (READ_ONCE(req->iopoll_completed)) {
			list_move_tail(&req->inflight_entry, &done);
			continue;
		}
		if (!list_empty(&done))
			break;

		ret = kiocb->ki_filp->f_op->iopoll(kiocb, spin);
		if (ret < 0)
			break;

		/* iopoll may have completed current req */
		if (READ_ONCE(req->iopoll_completed))
			list_move_tail(&req->inflight_entry, &done);

		if (ret && spin)
			spin = false;
		ret = 0;
	}

	if (!list_empty(&done))
		io_iopoll_complete(ctx, nr_events, &done);

	return ret;
}

/*
 * Poll for a minimum of 'min' events. Note that if min == 0 we consider that a
 * non-spinning poll check - we'll still enter the driver poll loop, but only
 * as a non-spinning completion check.
 */
static int io_iopoll_getevents(struct io_ring_ctx *ctx, unsigned int *nr_events,
				long min)
{
	while (!list_empty(&ctx->iopoll_list) && !need_resched()) {
		int ret;

		ret = io_do_iopoll(ctx, nr_events, min);
		if (ret < 0)
			return ret;
		if (*nr_events >= min)
			return 0;
	}

	return 1;
}

/*
 * We can't just wait for polled events to come to us, we have to actively
 * find and complete them.
 */
static void io_iopoll_try_reap_events(struct io_ring_ctx *ctx)
{
	if (!(ctx->flags & IORING_SETUP_IOPOLL))
		return;

	mutex_lock(&ctx->uring_lock);
	while (!list_empty(&ctx->iopoll_list)) {
		unsigned int nr_events = 0;

		io_do_iopoll(ctx, &nr_events, 0);

		/* let it sleep and repeat later if can't complete a request */
		if (nr_events == 0)
			break;
		/*
		 * Ensure we allow local-to-the-cpu processing to take place,
		 * in this case we need to ensure that we reap all events.
		 * Also let task_work, etc. to progress by releasing the mutex
		 */
		if (need_resched()) {
			mutex_unlock(&ctx->uring_lock);
			cond_resched();
			mutex_lock(&ctx->uring_lock);
		}
	}
	mutex_unlock(&ctx->uring_lock);
}

static int io_iopoll_check(struct io_ring_ctx *ctx, long min)
{
	unsigned int nr_events = 0;
	int iters = 0, ret = 0;

	/*
	 * We disallow the app entering submit/complete with polling, but we
	 * still need to lock the ring to prevent racing with polled issue
	 * that got punted to a workqueue.
	 */
	mutex_lock(&ctx->uring_lock);
	do {
		/*
		 * Don't enter poll loop if we already have events pending.
		 * If we do, we can potentially be spinning for commands that
		 * already triggered a CQE (eg in error).
		 */
		if (test_bit(0, &ctx->cq_check_overflow))
			__io_cqring_overflow_flush(ctx, false, NULL, NULL);
		if (io_cqring_events(ctx))
			break;

		/*
		 * If a submit got punted to a workqueue, we can have the
		 * application entering polling for a command before it gets
		 * issued. That app will hold the uring_lock for the duration
		 * of the poll right here, so we need to take a breather every
		 * now and then to ensure that the issue has a chance to add
		 * the poll to the issued list. Otherwise we can spin here
		 * forever, while the workqueue is stuck trying to acquire the
		 * very same mutex.
		 */
		if (!(++iters & 7)) {
			mutex_unlock(&ctx->uring_lock);
			io_run_task_work();
			mutex_lock(&ctx->uring_lock);
		}

		ret = io_iopoll_getevents(ctx, &nr_events, min);
		if (ret <= 0)
			break;
		ret = 0;
	} while (min && !nr_events && !need_resched());

	mutex_unlock(&ctx->uring_lock);
	return ret;
}

static void kiocb_end_write(struct io_kiocb *req)
{
	/*
	 * Tell lockdep we inherited freeze protection from submission
	 * thread.
	 */
	if (req->flags & REQ_F_ISREG) {
		struct inode *inode = file_inode(req->file);

		__sb_writers_acquired(inode->i_sb, SB_FREEZE_WRITE);
	}
	file_end_write(req->file);
}

#ifdef CONFIG_BLOCK
static bool io_resubmit_prep(struct io_kiocb *req)
{
	struct iovec inline_vecs[UIO_FASTIOV], *iovec = inline_vecs;
	int rw, ret;
	struct iov_iter iter;

	/* already prepared */
	if (req->async_data)
		return true;

	switch (req->opcode) {
	case IORING_OP_READV:
	case IORING_OP_READ_FIXED:
	case IORING_OP_READ:
		rw = READ;
		break;
	case IORING_OP_WRITEV:
	case IORING_OP_WRITE_FIXED:
	case IORING_OP_WRITE:
		rw = WRITE;
		break;
	default:
		printk_once(KERN_WARNING "io_uring: bad opcode in resubmit %d\n",
				req->opcode);
		return false;
	}

	ret = io_import_iovec(rw, req, &iovec, &iter, false);
	if (ret < 0)
		return false;
	return !io_setup_async_rw(req, iovec, inline_vecs, &iter, false);
}
#endif

static bool io_rw_reissue(struct io_kiocb *req)
{
#ifdef CONFIG_BLOCK
	umode_t mode = file_inode(req->file)->i_mode;
	int ret;

	if (!S_ISBLK(mode) && !S_ISREG(mode))
		return false;
	if ((req->flags & REQ_F_NOWAIT) || io_wq_current_is_worker())
		return false;

	lockdep_assert_held(&req->ctx->uring_lock);

	ret = io_sq_thread_acquire_mm_files(req->ctx, req);

	if (!ret && io_resubmit_prep(req)) {
		refcount_inc(&req->refs);
		io_queue_async_work(req);
		return true;
	}
	req_set_fail_links(req);
#endif
	return false;
}

static void __io_complete_rw(struct io_kiocb *req, long res, long res2,
			     unsigned int issue_flags)
{
	int cflags = 0;

	if ((res == -EAGAIN || res == -EOPNOTSUPP) && io_rw_reissue(req))
		return;
	if (res != req->result)
		req_set_fail_links(req);

	if (req->rw.kiocb.ki_flags & IOCB_WRITE)
		kiocb_end_write(req);
	if (req->flags & REQ_F_BUFFER_SELECTED)
		cflags = io_put_rw_kbuf(req);
	__io_req_complete(req, issue_flags, res, cflags);
}

static void io_complete_rw(struct kiocb *kiocb, long res, long res2)
{
	struct io_kiocb *req = container_of(kiocb, struct io_kiocb, rw.kiocb);

	__io_complete_rw(req, res, res2, 0);
}

static void io_complete_rw_iopoll(struct kiocb *kiocb, long res, long res2)
{
	struct io_kiocb *req = container_of(kiocb, struct io_kiocb, rw.kiocb);

	if (kiocb->ki_flags & IOCB_WRITE)
		kiocb_end_write(req);

	if (res != -EAGAIN && res != req->result)
		req_set_fail_links(req);

	WRITE_ONCE(req->result, res);
	/* order with io_poll_complete() checking ->result */
	smp_wmb();
	WRITE_ONCE(req->iopoll_completed, 1);
}

/*
 * After the iocb has been issued, it's safe to be found on the poll list.
 * Adding the kiocb to the list AFTER submission ensures that we don't
 * find it from a io_iopoll_getevents() thread before the issuer is done
 * accessing the kiocb cookie.
 */
static void io_iopoll_req_issued(struct io_kiocb *req, bool in_async)
{
	struct io_ring_ctx *ctx = req->ctx;

	/*
	 * Track whether we have multiple files in our lists. This will impact
	 * how we do polling eventually, not spinning if we're on potentially
	 * different devices.
	 */
	if (list_empty(&ctx->iopoll_list)) {
		ctx->poll_multi_file = false;
	} else if (!ctx->poll_multi_file) {
		struct io_kiocb *list_req;

		list_req = list_first_entry(&ctx->iopoll_list, struct io_kiocb,
						inflight_entry);
		if (list_req->file != req->file)
			ctx->poll_multi_file = true;
	}

	/*
	 * For fast devices, IO may have already completed. If it has, add
	 * it to the front so we find it first.
	 */
	if (READ_ONCE(req->iopoll_completed))
		list_add(&req->inflight_entry, &ctx->iopoll_list);
	else
		list_add_tail(&req->inflight_entry, &ctx->iopoll_list);

	/*
	 * If IORING_SETUP_SQPOLL is enabled, sqes are either handled in sq thread
	 * task context or in io worker task context. If current task context is
	 * sq thread, we don't need to check whether should wake up sq thread.
	 */
	if (in_async && (ctx->flags & IORING_SETUP_SQPOLL) &&
	    wq_has_sleeper(&ctx->sq_data->wait))
		wake_up(&ctx->sq_data->wait);
}

static inline void io_state_file_put(struct io_submit_state *state)
{
	if (state->file_refs) {
		fput_many(state->file, state->file_refs);
		state->file_refs = 0;
	}
}

/*
 * Get as many references to a file as we have IOs left in this submission,
 * assuming most submissions are for one file, or at least that each file
 * has more than one submission.
 */
static struct file *__io_file_get(struct io_submit_state *state, int fd)
{
	if (!state)
		return fget(fd);

	if (state->file_refs) {
		if (state->fd == fd) {
			state->file_refs--;
			return state->file;
		}
		io_state_file_put(state);
	}
	state->file = fget_many(fd, state->ios_left);
	if (unlikely(!state->file))
		return NULL;

	state->fd = fd;
	state->file_refs = state->ios_left - 1;
	return state->file;
}

static bool io_bdev_nowait(struct block_device *bdev)
{
	return !bdev || blk_queue_nowait(bdev_get_queue(bdev));
}

/*
 * If we tracked the file through the SCM inflight mechanism, we could support
 * any file. For now, just ensure that anything potentially problematic is done
 * inline.
 */
static bool io_file_supports_async(struct file *file, int rw)
{
	umode_t mode = file_inode(file)->i_mode;

	if (S_ISBLK(mode)) {
		if (IS_ENABLED(CONFIG_BLOCK) &&
		    io_bdev_nowait(I_BDEV(file->f_mapping->host)))
			return true;
		return false;
	}
	if (S_ISCHR(mode) || S_ISSOCK(mode))
		return true;
	if (S_ISREG(mode)) {
		if (IS_ENABLED(CONFIG_BLOCK) &&
		    io_bdev_nowait(file->f_inode->i_sb->s_bdev) &&
		    file->f_op != &io_uring_fops)
			return true;
		return false;
	}

	/* any ->read/write should understand O_NONBLOCK */
	if (file->f_flags & O_NONBLOCK)
		return true;

	if (!(file->f_mode & FMODE_NOWAIT))
		return false;

	if (rw == READ)
		return file->f_op->read_iter != NULL;

	return file->f_op->write_iter != NULL;
}

static int io_prep_rw(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct kiocb *kiocb = &req->rw.kiocb;
	struct file *file = req->file;
	unsigned ioprio;
	int ret;

	if (S_ISREG(file_inode(file)->i_mode))
		req->flags |= REQ_F_ISREG;

	kiocb->ki_pos = READ_ONCE(sqe->off);
	if (kiocb->ki_pos == -1 && !(file->f_mode & FMODE_STREAM)) {
		req->flags |= REQ_F_CUR_POS;
		kiocb->ki_pos = file->f_pos;
	}
	kiocb->ki_hint = ki_hint_validate(file_write_hint(kiocb->ki_filp));
	kiocb->ki_flags = iocb_flags(kiocb->ki_filp);
	ret = kiocb_set_rw_flags(kiocb, READ_ONCE(sqe->rw_flags));
	if (unlikely(ret))
		return ret;

	/* don't allow async punt for O_NONBLOCK or RWF_NOWAIT */
	if ((kiocb->ki_flags & IOCB_NOWAIT) || (file->f_flags & O_NONBLOCK))
		req->flags |= REQ_F_NOWAIT;

	ioprio = READ_ONCE(sqe->ioprio);
	if (ioprio) {
		ret = ioprio_check_cap(ioprio);
		if (ret)
			return ret;

		kiocb->ki_ioprio = ioprio;
	} else
		kiocb->ki_ioprio = get_current_ioprio();

	if (ctx->flags & IORING_SETUP_IOPOLL) {
		if (!(kiocb->ki_flags & IOCB_DIRECT) ||
		    !kiocb->ki_filp->f_op->iopoll)
			return -EOPNOTSUPP;

		kiocb->ki_flags |= IOCB_HIPRI;
		kiocb->ki_complete = io_complete_rw_iopoll;
		req->iopoll_completed = 0;
	} else {
		if (kiocb->ki_flags & IOCB_HIPRI)
			return -EINVAL;
		kiocb->ki_complete = io_complete_rw;
	}

	req->rw.addr = READ_ONCE(sqe->addr);
	req->rw.len = READ_ONCE(sqe->len);
	req->buf_index = READ_ONCE(sqe->buf_index);
	return 0;
}

static inline void io_rw_done(struct kiocb *kiocb, ssize_t ret)
{
	switch (ret) {
	case -EIOCBQUEUED:
		break;
	case -ERESTARTSYS:
	case -ERESTARTNOINTR:
	case -ERESTARTNOHAND:
	case -ERESTART_RESTARTBLOCK:
		/*
		 * We can't just restart the syscall, since previously
		 * submitted sqes may already be in progress. Just fail this
		 * IO with EINTR.
		 */
		ret = -EINTR;
		fallthrough;
	default:
		kiocb->ki_complete(kiocb, ret, 0);
	}
}

static void kiocb_done(struct kiocb *kiocb, ssize_t ret,
		       unsigned int issue_flags)
{
	struct io_kiocb *req = container_of(kiocb, struct io_kiocb, rw.kiocb);
	struct io_async_rw *io = req->async_data;

	/* add previously done IO, if any */
	if (io && io->bytes_done > 0) {
		if (ret < 0)
			ret = io->bytes_done;
		else
			ret += io->bytes_done;
	}

	if (req->flags & REQ_F_CUR_POS)
		req->file->f_pos = kiocb->ki_pos;
	if (ret >= 0 && kiocb->ki_complete == io_complete_rw)
		__io_complete_rw(req, ret, 0, issue_flags);
	else
		io_rw_done(kiocb, ret);
}

static int io_import_fixed(struct io_kiocb *req, int rw, struct iov_iter *iter)
{
	struct io_ring_ctx *ctx = req->ctx;
	size_t len = req->rw.len;
	struct io_mapped_ubuf *imu;
	u16 index, buf_index = req->buf_index;
	size_t offset;
	u64 buf_addr;

	if (unlikely(buf_index >= ctx->nr_user_bufs))
		return -EFAULT;
	index = array_index_nospec(buf_index, ctx->nr_user_bufs);
	imu = &ctx->user_bufs[index];
	buf_addr = req->rw.addr;

	/* overflow */
	if (buf_addr + len < buf_addr)
		return -EFAULT;
	/* not inside the mapped region */
	if (buf_addr < imu->ubuf || buf_addr + len > imu->ubuf + imu->len)
		return -EFAULT;

	/*
	 * May not be a start of buffer, set size appropriately
	 * and advance us to the beginning.
	 */
	offset = buf_addr - imu->ubuf;
	iov_iter_bvec(iter, rw, imu->bvec, imu->nr_bvecs, offset + len);

	if (offset) {
		/*
		 * Don't use iov_iter_advance() here, as it's really slow for
		 * using the latter parts of a big fixed buffer - it iterates
		 * over each segment manually. We can cheat a bit here, because
		 * we know that:
		 *
		 * 1) it's a BVEC iter, we set it up
		 * 2) all bvecs are PAGE_SIZE in size, except potentially the
		 *    first and last bvec
		 *
		 * So just find our index, and adjust the iterator afterwards.
		 * If the offset is within the first bvec (or the whole first
		 * bvec, just use iov_iter_advance(). This makes it easier
		 * since we can just skip the first segment, which may not
		 * be PAGE_SIZE aligned.
		 */
		const struct bio_vec *bvec = imu->bvec;

		if (offset <= bvec->bv_len) {
			iov_iter_advance(iter, offset);
		} else {
			unsigned long seg_skip;

			/* skip first vec */
			offset -= bvec->bv_len;
			seg_skip = 1 + (offset >> PAGE_SHIFT);

			iter->bvec = bvec + seg_skip;
			iter->nr_segs -= seg_skip;
			iter->count -= bvec->bv_len + offset;
			iter->iov_offset = offset & ~PAGE_MASK;
		}
	}

	return 0;
}

static void io_ring_submit_unlock(struct io_ring_ctx *ctx, bool needs_lock)
{
	if (needs_lock)
		mutex_unlock(&ctx->uring_lock);
}

static void io_ring_submit_lock(struct io_ring_ctx *ctx, bool needs_lock)
{
	/*
	 * "Normal" inline submissions always hold the uring_lock, since we
	 * grab it from the system call. Same is true for the SQPOLL offload.
	 * The only exception is when we've detached the request and issue it
	 * from an async worker thread, grab the lock for that case.
	 */
	if (needs_lock)
		mutex_lock(&ctx->uring_lock);
}

static struct io_buffer *io_buffer_select(struct io_kiocb *req, size_t *len,
					  int bgid, struct io_buffer *kbuf,
					  bool needs_lock)
{
	struct io_buffer *head;

	if (req->flags & REQ_F_BUFFER_SELECTED)
		return kbuf;

	io_ring_submit_lock(req->ctx, needs_lock);

	lockdep_assert_held(&req->ctx->uring_lock);

	head = idr_find(&req->ctx->io_buffer_idr, bgid);
	if (head) {
		if (!list_empty(&head->list)) {
			kbuf = list_last_entry(&head->list, struct io_buffer,
							list);
			list_del(&kbuf->list);
		} else {
			kbuf = head;
			idr_remove(&req->ctx->io_buffer_idr, bgid);
		}
		if (*len > kbuf->len)
			*len = kbuf->len;
	} else {
		kbuf = ERR_PTR(-ENOBUFS);
	}

	io_ring_submit_unlock(req->ctx, needs_lock);

	return kbuf;
}

static void __user *io_rw_buffer_select(struct io_kiocb *req, size_t *len,
					bool needs_lock)
{
	struct io_buffer *kbuf;
	u16 bgid;

	kbuf = (struct io_buffer *) (unsigned long) req->rw.addr;
	bgid = req->buf_index;
	kbuf = io_buffer_select(req, len, bgid, kbuf, needs_lock);
	if (IS_ERR(kbuf))
		return kbuf;
	req->rw.addr = (u64) (unsigned long) kbuf;
	req->flags |= REQ_F_BUFFER_SELECTED;
	return u64_to_user_ptr(kbuf->addr);
}

#ifdef CONFIG_COMPAT
static ssize_t io_compat_import(struct io_kiocb *req, struct iovec *iov,
				bool needs_lock)
{
	struct compat_iovec __user *uiov;
	compat_ssize_t clen;
	void __user *buf;
	ssize_t len;

	uiov = u64_to_user_ptr(req->rw.addr);
	if (!access_ok(uiov, sizeof(*uiov)))
		return -EFAULT;
	if (__get_user(clen, &uiov->iov_len))
		return -EFAULT;
	if (clen < 0)
		return -EINVAL;

	len = clen;
	buf = io_rw_buffer_select(req, &len, needs_lock);
	if (IS_ERR(buf))
		return PTR_ERR(buf);
	iov[0].iov_base = buf;
	iov[0].iov_len = (compat_size_t) len;
	return 0;
}
#endif

static ssize_t __io_iov_buffer_select(struct io_kiocb *req, struct iovec *iov,
				      bool needs_lock)
{
	struct iovec __user *uiov = u64_to_user_ptr(req->rw.addr);
	void __user *buf;
	ssize_t len;

	if (copy_from_user(iov, uiov, sizeof(*uiov)))
		return -EFAULT;

	len = iov[0].iov_len;
	if (len < 0)
		return -EINVAL;
	buf = io_rw_buffer_select(req, &len, needs_lock);
	if (IS_ERR(buf))
		return PTR_ERR(buf);
	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	return 0;
}

static ssize_t io_iov_buffer_select(struct io_kiocb *req, struct iovec *iov,
				    bool needs_lock)
{
	if (req->flags & REQ_F_BUFFER_SELECTED) {
		struct io_buffer *kbuf;

		kbuf = (struct io_buffer *) (unsigned long) req->rw.addr;
		iov[0].iov_base = u64_to_user_ptr(kbuf->addr);
		iov[0].iov_len = kbuf->len;
		return 0;
	}
	if (req->rw.len != 1)
		return -EINVAL;

#ifdef CONFIG_COMPAT
	if (req->ctx->compat)
		return io_compat_import(req, iov, needs_lock);
#endif

	return __io_iov_buffer_select(req, iov, needs_lock);
}

static int io_import_iovec(int rw, struct io_kiocb *req, struct iovec **iovec,
			   struct iov_iter *iter, bool needs_lock)
{
	void __user *buf = u64_to_user_ptr(req->rw.addr);
	size_t sqe_len = req->rw.len;
	u8 opcode = req->opcode;
	ssize_t ret;

	if (opcode == IORING_OP_READ_FIXED || opcode == IORING_OP_WRITE_FIXED) {
		*iovec = NULL;
		return io_import_fixed(req, rw, iter);
	}

	/* buffer index only valid with fixed read/write, or buffer select  */
	if (req->buf_index && !(req->flags & REQ_F_BUFFER_SELECT))
		return -EINVAL;

	if (opcode == IORING_OP_READ || opcode == IORING_OP_WRITE) {
		if (req->flags & REQ_F_BUFFER_SELECT) {
			buf = io_rw_buffer_select(req, &sqe_len, needs_lock);
			if (IS_ERR(buf))
				return PTR_ERR(buf);
			req->rw.len = sqe_len;
		}

		ret = import_single_range(rw, buf, sqe_len, *iovec, iter);
		*iovec = NULL;
		return ret;
	}

	if (req->flags & REQ_F_BUFFER_SELECT) {
		ret = io_iov_buffer_select(req, *iovec, needs_lock);
		if (!ret)
			iov_iter_init(iter, rw, *iovec, 1, (*iovec)->iov_len);
		*iovec = NULL;
		return ret;
	}

	return __import_iovec(rw, buf, sqe_len, UIO_FASTIOV, iovec, iter,
			      req->ctx->compat);
}

static inline loff_t *io_kiocb_ppos(struct kiocb *kiocb)
{
	return (kiocb->ki_filp->f_mode & FMODE_STREAM) ? NULL : &kiocb->ki_pos;
}

/*
 * For files that don't have ->read_iter() and ->write_iter(), handle them
 * by looping over ->read() or ->write() manually.
 */
static ssize_t loop_rw_iter(int rw, struct io_kiocb *req, struct iov_iter *iter)
{
	struct kiocb *kiocb = &req->rw.kiocb;
	struct file *file = req->file;
	ssize_t ret = 0;

	/*
	 * Don't support polled IO through this interface, and we can't
	 * support non-blocking either. For the latter, this just causes
	 * the kiocb to be handled from an async context.
	 */
	if (kiocb->ki_flags & IOCB_HIPRI)
		return -EOPNOTSUPP;
	if (kiocb->ki_flags & IOCB_NOWAIT)
		return -EAGAIN;

	while (iov_iter_count(iter)) {
		struct iovec iovec;
		ssize_t nr;

		if (!iov_iter_is_bvec(iter)) {
			iovec = iov_iter_iovec(iter);
		} else {
			iovec.iov_base = u64_to_user_ptr(req->rw.addr);
			iovec.iov_len = req->rw.len;
		}

		if (rw == READ) {
			nr = file->f_op->read(file, iovec.iov_base,
					      iovec.iov_len, io_kiocb_ppos(kiocb));
		} else {
			nr = file->f_op->write(file, iovec.iov_base,
					       iovec.iov_len, io_kiocb_ppos(kiocb));
		}

		if (nr < 0) {
			if (!ret)
				ret = nr;
			break;
		}
		ret += nr;
		if (nr != iovec.iov_len)
			break;
		req->rw.len -= nr;
		req->rw.addr += nr;
		iov_iter_advance(iter, nr);
	}

	return ret;
}

static void io_req_map_rw(struct io_kiocb *req, const struct iovec *iovec,
			  const struct iovec *fast_iov, struct iov_iter *iter)
{
	struct io_async_rw *rw = req->async_data;

	memcpy(&rw->iter, iter, sizeof(*iter));
	rw->free_iovec = iovec;
	rw->bytes_done = 0;
	/* can only be fixed buffers, no need to do anything */
	if (iov_iter_is_bvec(iter))
		return;
	if (!iovec) {
		unsigned iov_off = 0;

		rw->iter.iov = rw->fast_iov;
		if (iter->iov != fast_iov) {
			iov_off = iter->iov - fast_iov;
			rw->iter.iov += iov_off;
		}
		if (rw->fast_iov != fast_iov)
			memcpy(rw->fast_iov + iov_off, fast_iov + iov_off,
			       sizeof(struct iovec) * iter->nr_segs);
	} else {
		req->flags |= REQ_F_NEED_CLEANUP;
	}
}

static inline int __io_alloc_async_data(struct io_kiocb *req)
{
	WARN_ON_ONCE(!io_op_defs[req->opcode].async_size);
	req->async_data = kmalloc(io_op_defs[req->opcode].async_size, GFP_KERNEL);
	return req->async_data == NULL;
}

static int io_alloc_async_data(struct io_kiocb *req)
{
	if (!io_op_defs[req->opcode].needs_async_data)
		return 0;

	return  __io_alloc_async_data(req);
}

static int io_setup_async_rw(struct io_kiocb *req, const struct iovec *iovec,
			     const struct iovec *fast_iov,
			     struct iov_iter *iter, bool force)
{
	if (!force && !io_op_defs[req->opcode].needs_async_data)
		return 0;
	if (!req->async_data) {
		if (__io_alloc_async_data(req)) {
			kfree(iovec);
			return -ENOMEM;
		}

		io_req_map_rw(req, iovec, fast_iov, iter);
	}
	return 0;
}

static inline int io_rw_prep_async(struct io_kiocb *req, int rw)
{
	struct io_async_rw *iorw = req->async_data;
	struct iovec *iov = iorw->fast_iov;
	int ret;

	ret = io_import_iovec(rw, req, &iov, &iorw->iter, false);
	if (unlikely(ret < 0))
		return ret;

	iorw->bytes_done = 0;
	iorw->free_iovec = iov;
	if (iov)
		req->flags |= REQ_F_NEED_CLEANUP;
	return 0;
}

static int io_read_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	ssize_t ret;

	ret = io_prep_rw(req, sqe);
	if (ret)
		return ret;

	if (unlikely(!(req->file->f_mode & FMODE_READ)))
		return -EBADF;

	/* either don't need iovec imported or already have it */
	if (!req->async_data)
		return 0;
	return io_rw_prep_async(req, READ);
}

/*
 * This is our waitqueue callback handler, registered through lock_page_async()
 * when we initially tried to do the IO with the iocb armed our waitqueue.
 * This gets called when the page is unlocked, and we generally expect that to
 * happen when the page IO is completed and the page is now uptodate. This will
 * queue a task_work based retry of the operation, attempting to copy the data
 * again. If the latter fails because the page was NOT uptodate, then we will
 * do a thread based blocking retry of the operation. That's the unexpected
 * slow path.
 */
static int io_async_buf_func(struct wait_queue_entry *wait, unsigned mode,
			     int sync, void *arg)
{
	struct wait_page_queue *wpq;
	struct io_kiocb *req = wait->private;
	struct wait_page_key *key = arg;

	wpq = container_of(wait, struct wait_page_queue, wait);

	if (!wake_page_match(wpq, key))
		return 0;

	req->rw.kiocb.ki_flags &= ~IOCB_WAITQ;
	list_del_init(&wait->entry);

	/* submit ref gets dropped, acquire a new one */
	refcount_inc(&req->refs);
	io_req_task_queue(req);
	return 1;
}

/*
 * This controls whether a given IO request should be armed for async page
 * based retry. If we return false here, the request is handed to the async
 * worker threads for retry. If we're doing buffered reads on a regular file,
 * we prepare a private wait_page_queue entry and retry the operation. This
 * will either succeed because the page is now uptodate and unlocked, or it
 * will register a callback when the page is unlocked at IO completion. Through
 * that callback, io_uring uses task_work to setup a retry of the operation.
 * That retry will attempt the buffered read again. The retry will generally
 * succeed, or in rare cases where it fails, we then fall back to using the
 * async worker threads for a blocking retry.
 */
static bool io_rw_should_retry(struct io_kiocb *req)
{
	struct io_async_rw *rw = req->async_data;
	struct wait_page_queue *wait = &rw->wpq;
	struct kiocb *kiocb = &req->rw.kiocb;

	/* never retry for NOWAIT, we just complete with -EAGAIN */
	if (req->flags & REQ_F_NOWAIT)
		return false;

	/* Only for buffered IO */
	if (kiocb->ki_flags & (IOCB_DIRECT | IOCB_HIPRI))
		return false;

	/*
	 * just use poll if we can, and don't attempt if the fs doesn't
	 * support callback based unlocks
	 */
	if (file_can_poll(req->file) || !(req->file->f_mode & FMODE_BUF_RASYNC))
		return false;

	wait->wait.func = io_async_buf_func;
	wait->wait.private = req;
	wait->wait.flags = 0;
	INIT_LIST_HEAD(&wait->wait.entry);
	kiocb->ki_flags |= IOCB_WAITQ;
	kiocb->ki_flags &= ~IOCB_NOWAIT;
	kiocb->ki_waitq = wait;
	return true;
}

static int io_iter_do_read(struct io_kiocb *req, struct iov_iter *iter)
{
	if (req->file->f_op->read_iter)
		return call_read_iter(req->file, &req->rw.kiocb, iter);
	else if (req->file->f_op->read)
		return loop_rw_iter(READ, req, iter);
	else
		return -EINVAL;
}

static int io_read(struct io_kiocb *req, unsigned int issue_flags)
{
	struct iovec inline_vecs[UIO_FASTIOV], *iovec = inline_vecs;
	struct kiocb *kiocb = &req->rw.kiocb;
	struct iov_iter __iter, *iter = &__iter;
	struct io_async_rw *rw = req->async_data;
	ssize_t io_size, ret, ret2;
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;

	if (rw) {
		iter = &rw->iter;
		iovec = NULL;
	} else {
		ret = io_import_iovec(READ, req, &iovec, iter, !force_nonblock);
		if (ret < 0)
			return ret;
	}
	io_size = iov_iter_count(iter);
	req->result = io_size;

	/* Ensure we clear previously set non-block flag */
	if (!force_nonblock)
		kiocb->ki_flags &= ~IOCB_NOWAIT;
	else
		kiocb->ki_flags |= IOCB_NOWAIT;

	/* If the file doesn't support async, just async punt */
	if (force_nonblock && !io_file_supports_async(req->file, READ)) {
		ret = io_setup_async_rw(req, iovec, inline_vecs, iter, true);
		return ret ?: -EAGAIN;
	}

	ret = rw_verify_area(READ, req->file, io_kiocb_ppos(kiocb), io_size);
	if (unlikely(ret)) {
		kfree(iovec);
		return ret;
	}

	ret = io_iter_do_read(req, iter);

	if (ret == -EIOCBQUEUED) {
		/* it's faster to check here then delegate to kfree */
		if (iovec)
			kfree(iovec);
		return 0;
	} else if (ret == -EAGAIN) {
		/* IOPOLL retry should happen for io-wq threads */
		if (!force_nonblock && !(req->ctx->flags & IORING_SETUP_IOPOLL))
			goto done;
		/* no retry on NONBLOCK nor RWF_NOWAIT */
		if (req->flags & REQ_F_NOWAIT)
			goto done;
		/* some cases will consume bytes even on error returns */
		iov_iter_revert(iter, io_size - iov_iter_count(iter));
		ret = 0;
	} else if (ret <= 0 || ret == io_size || !force_nonblock ||
		   (req->flags & REQ_F_NOWAIT) || !(req->flags & REQ_F_ISREG)) {
		/* read all, failed, already did sync or don't want to retry */
		goto done;
	}

	ret2 = io_setup_async_rw(req, iovec, inline_vecs, iter, true);
	if (ret2)
		return ret2;

	rw = req->async_data;
	/* now use our persistent iterator, if we aren't already */
	iter = &rw->iter;

	do {
		io_size -= ret;
		rw->bytes_done += ret;
		/* if we can retry, do so with the callbacks armed */
		if (!io_rw_should_retry(req)) {
			kiocb->ki_flags &= ~IOCB_WAITQ;
			return -EAGAIN;
		}

		/*
		 * Now retry read with the IOCB_WAITQ parts set in the iocb. If
		 * we get -EIOCBQUEUED, then we'll get a notification when the
		 * desired page gets unlocked. We can also get a partial read
		 * here, and if we do, then just retry at the new offset.
		 */
		ret = io_iter_do_read(req, iter);
		if (ret == -EIOCBQUEUED)
			return 0;
		/* we got some bytes, but not all. retry. */
	} while (ret > 0 && ret < io_size);
done:
	kiocb_done(kiocb, ret, issue_flags);
	return 0;
}

static int io_write_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	ssize_t ret;

	ret = io_prep_rw(req, sqe);
	if (ret)
		return ret;

	if (unlikely(!(req->file->f_mode & FMODE_WRITE)))
		return -EBADF;

	/* either don't need iovec imported or already have it */
	if (!req->async_data)
		return 0;
	return io_rw_prep_async(req, WRITE);
}

static int io_write(struct io_kiocb *req, unsigned int issue_flags)
{
	struct iovec inline_vecs[UIO_FASTIOV], *iovec = inline_vecs;
	struct kiocb *kiocb = &req->rw.kiocb;
	struct iov_iter __iter, *iter = &__iter;
	struct io_async_rw *rw = req->async_data;
	ssize_t ret, ret2, io_size;
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;

	if (rw) {
		iter = &rw->iter;
		iovec = NULL;
	} else {
		ret = io_import_iovec(WRITE, req, &iovec, iter, !force_nonblock);
		if (ret < 0)
			return ret;
	}
	io_size = iov_iter_count(iter);
	req->result = io_size;

	/* Ensure we clear previously set non-block flag */
	if (!force_nonblock)
		kiocb->ki_flags &= ~IOCB_NOWAIT;
	else
		kiocb->ki_flags |= IOCB_NOWAIT;

	/* If the file doesn't support async, just async punt */
	if (force_nonblock && !io_file_supports_async(req->file, WRITE))
		goto copy_iov;

	/* file path doesn't support NOWAIT for non-direct_IO */
	if (force_nonblock && !(kiocb->ki_flags & IOCB_DIRECT) &&
	    (req->flags & REQ_F_ISREG))
		goto copy_iov;

	ret = rw_verify_area(WRITE, req->file, io_kiocb_ppos(kiocb), io_size);
	if (unlikely(ret))
		goto out_free;

	/*
	 * Open-code file_start_write here to grab freeze protection,
	 * which will be released by another thread in
	 * io_complete_rw().  Fool lockdep by telling it the lock got
	 * released so that it doesn't complain about the held lock when
	 * we return to userspace.
	 */
	if (req->flags & REQ_F_ISREG) {
		sb_start_write(file_inode(req->file)->i_sb);
		__sb_writers_release(file_inode(req->file)->i_sb,
					SB_FREEZE_WRITE);
	}
	kiocb->ki_flags |= IOCB_WRITE;

	if (req->file->f_op->write_iter)
		ret2 = call_write_iter(req->file, kiocb, iter);
	else if (req->file->f_op->write)
		ret2 = loop_rw_iter(WRITE, req, iter);
	else
		ret2 = -EINVAL;

	/*
	 * Raw bdev writes will return -EOPNOTSUPP for IOCB_NOWAIT. Just
	 * retry them without IOCB_NOWAIT.
	 */
	if (ret2 == -EOPNOTSUPP && (kiocb->ki_flags & IOCB_NOWAIT))
		ret2 = -EAGAIN;
	/* no retry on NONBLOCK nor RWF_NOWAIT */
	if (ret2 == -EAGAIN && (req->flags & REQ_F_NOWAIT))
		goto done;
	if (!force_nonblock || ret2 != -EAGAIN) {
		/* IOPOLL retry should happen for io-wq threads */
		if ((req->ctx->flags & IORING_SETUP_IOPOLL) && ret2 == -EAGAIN)
			goto copy_iov;
done:
		kiocb_done(kiocb, ret2, issue_flags);
	} else {
copy_iov:
		/* some cases will consume bytes even on error returns */
		iov_iter_revert(iter, io_size - iov_iter_count(iter));
		ret = io_setup_async_rw(req, iovec, inline_vecs, iter, false);
		return ret ?: -EAGAIN;
	}
out_free:
	/* it's reportedly faster than delegating the null check to kfree() */
	if (iovec)
		kfree(iovec);
	return ret;
}

static int io_renameat_prep(struct io_kiocb *req,
			    const struct io_uring_sqe *sqe)
{
	struct io_rename *ren = &req->rename;
	const char __user *oldf, *newf;

	if (unlikely(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	ren->old_dfd = READ_ONCE(sqe->fd);
	oldf = u64_to_user_ptr(READ_ONCE(sqe->addr));
	newf = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	ren->new_dfd = READ_ONCE(sqe->len);
	ren->flags = READ_ONCE(sqe->rename_flags);

	ren->oldpath = getname(oldf);
	if (IS_ERR(ren->oldpath))
		return PTR_ERR(ren->oldpath);

	ren->newpath = getname(newf);
	if (IS_ERR(ren->newpath)) {
		putname(ren->oldpath);
		return PTR_ERR(ren->newpath);
	}

	req->flags |= REQ_F_NEED_CLEANUP;
	return 0;
}

static int io_renameat(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_rename *ren = &req->rename;
	int ret;

	if (issue_flags & IO_URING_F_NONBLOCK)
		return -EAGAIN;

	ret = do_renameat2(ren->old_dfd, ren->oldpath, ren->new_dfd,
				ren->newpath, ren->flags);

	req->flags &= ~REQ_F_NEED_CLEANUP;
	if (ret < 0)
		req_set_fail_links(req);
	io_req_complete(req, ret);
	return 0;
}

static int io_unlinkat_prep(struct io_kiocb *req,
			    const struct io_uring_sqe *sqe)
{
	struct io_unlink *un = &req->unlink;
	const char __user *fname;

	if (unlikely(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	un->dfd = READ_ONCE(sqe->fd);

	un->flags = READ_ONCE(sqe->unlink_flags);
	if (un->flags & ~AT_REMOVEDIR)
		return -EINVAL;

	fname = u64_to_user_ptr(READ_ONCE(sqe->addr));
	un->filename = getname(fname);
	if (IS_ERR(un->filename))
		return PTR_ERR(un->filename);

	req->flags |= REQ_F_NEED_CLEANUP;
	return 0;
}

static int io_unlinkat(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_unlink *un = &req->unlink;
	int ret;

	if (issue_flags & IO_URING_F_NONBLOCK)
		return -EAGAIN;

	if (un->flags & AT_REMOVEDIR)
		ret = do_rmdir(un->dfd, un->filename);
	else
		ret = do_unlinkat(un->dfd, un->filename);

	req->flags &= ~REQ_F_NEED_CLEANUP;
	if (ret < 0)
		req_set_fail_links(req);
	io_req_complete(req, ret);
	return 0;
}

static int io_shutdown_prep(struct io_kiocb *req,
			    const struct io_uring_sqe *sqe)
{
#if defined(CONFIG_NET)
	if (unlikely(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;
	if (sqe->ioprio || sqe->off || sqe->addr || sqe->rw_flags ||
	    sqe->buf_index)
		return -EINVAL;

	req->shutdown.how = READ_ONCE(sqe->len);
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

static int io_shutdown(struct io_kiocb *req, unsigned int issue_flags)
{
#if defined(CONFIG_NET)
	struct socket *sock;
	int ret;

	if (issue_flags & IO_URING_F_NONBLOCK)
		return -EAGAIN;

	sock = sock_from_file(req->file);
	if (unlikely(!sock))
		return -ENOTSOCK;

	ret = __sys_shutdown_sock(sock, req->shutdown.how);
	if (ret < 0)
		req_set_fail_links(req);
	io_req_complete(req, ret);
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

static int __io_splice_prep(struct io_kiocb *req,
			    const struct io_uring_sqe *sqe)
{
	struct io_splice* sp = &req->splice;
	unsigned int valid_flags = SPLICE_F_FD_IN_FIXED | SPLICE_F_ALL;

	if (unlikely(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;

	sp->file_in = NULL;
	sp->len = READ_ONCE(sqe->len);
	sp->flags = READ_ONCE(sqe->splice_flags);

	if (unlikely(sp->flags & ~valid_flags))
		return -EINVAL;

	sp->file_in = io_file_get(NULL, req, READ_ONCE(sqe->splice_fd_in),
				  (sp->flags & SPLICE_F_FD_IN_FIXED));
	if (!sp->file_in)
		return -EBADF;
	req->flags |= REQ_F_NEED_CLEANUP;

	if (!S_ISREG(file_inode(sp->file_in)->i_mode)) {
		/*
		 * Splice operation will be punted aync, and here need to
		 * modify io_wq_work.flags, so initialize io_wq_work firstly.
		 */
		io_req_init_async(req);
		req->work.flags |= IO_WQ_WORK_UNBOUND;
	}

	return 0;
}

static int io_tee_prep(struct io_kiocb *req,
		       const struct io_uring_sqe *sqe)
{
	if (READ_ONCE(sqe->splice_off_in) || READ_ONCE(sqe->off))
		return -EINVAL;
	return __io_splice_prep(req, sqe);
}

static int io_tee(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_splice *sp = &req->splice;
	struct file *in = sp->file_in;
	struct file *out = sp->file_out;
	unsigned int flags = sp->flags & ~SPLICE_F_FD_IN_FIXED;
	long ret = 0;

	if (issue_flags & IO_URING_F_NONBLOCK)
		return -EAGAIN;
	if (sp->len)
		ret = do_tee(in, out, sp->len, flags);

	io_put_file(req, in, (sp->flags & SPLICE_F_FD_IN_FIXED));
	req->flags &= ~REQ_F_NEED_CLEANUP;

	if (ret != sp->len)
		req_set_fail_links(req);
	io_req_complete(req, ret);
	return 0;
}

static int io_splice_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_splice* sp = &req->splice;

	sp->off_in = READ_ONCE(sqe->splice_off_in);
	sp->off_out = READ_ONCE(sqe->off);
	return __io_splice_prep(req, sqe);
}

static int io_splice(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_splice *sp = &req->splice;
	struct file *in = sp->file_in;
	struct file *out = sp->file_out;
	unsigned int flags = sp->flags & ~SPLICE_F_FD_IN_FIXED;
	loff_t *poff_in, *poff_out;
	long ret = 0;

	if (issue_flags & IO_URING_F_NONBLOCK)
		return -EAGAIN;

	poff_in = (sp->off_in == -1) ? NULL : &sp->off_in;
	poff_out = (sp->off_out == -1) ? NULL : &sp->off_out;

	if (sp->len)
		ret = do_splice(in, poff_in, out, poff_out, sp->len, flags);

	io_put_file(req, in, (sp->flags & SPLICE_F_FD_IN_FIXED));
	req->flags &= ~REQ_F_NEED_CLEANUP;

	if (ret != sp->len)
		req_set_fail_links(req);
	io_req_complete(req, ret);
	return 0;
}

/*
 * IORING_OP_NOP just posts a completion event, nothing else.
 */
static int io_nop(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ring_ctx *ctx = req->ctx;

	if (unlikely(ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;

	__io_req_complete(req, issue_flags, 0, 0);
	return 0;
}

static int io_prep_fsync(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_ring_ctx *ctx = req->ctx;

	if (!req->file)
		return -EBADF;

	if (unlikely(ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;
	if (unlikely(sqe->addr || sqe->ioprio || sqe->buf_index))
		return -EINVAL;

	req->sync.flags = READ_ONCE(sqe->fsync_flags);
	if (unlikely(req->sync.flags & ~IORING_FSYNC_DATASYNC))
		return -EINVAL;

	req->sync.off = READ_ONCE(sqe->off);
	req->sync.len = READ_ONCE(sqe->len);
	return 0;
}

static int io_fsync(struct io_kiocb *req, unsigned int issue_flags)
{
	loff_t end = req->sync.off + req->sync.len;
	int ret;

	/* fsync always requires a blocking context */
	if (issue_flags & IO_URING_F_NONBLOCK)
		return -EAGAIN;

	ret = vfs_fsync_range(req->file, req->sync.off,
				end > 0 ? end : LLONG_MAX,
				req->sync.flags & IORING_FSYNC_DATASYNC);
	if (ret < 0)
		req_set_fail_links(req);
	io_req_complete(req, ret);
	return 0;
}

static int io_fallocate_prep(struct io_kiocb *req,
			     const struct io_uring_sqe *sqe)
{
	if (sqe->ioprio || sqe->buf_index || sqe->rw_flags)
		return -EINVAL;
	if (unlikely(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;

	req->sync.off = READ_ONCE(sqe->off);
	req->sync.len = READ_ONCE(sqe->addr);
	req->sync.mode = READ_ONCE(sqe->len);
	return 0;
}

static int io_fallocate(struct io_kiocb *req, unsigned int issue_flags)
{
	int ret;

	/* fallocate always requiring blocking context */
	if (issue_flags & IO_URING_F_NONBLOCK)
		return -EAGAIN;
	ret = vfs_fallocate(req->file, req->sync.mode, req->sync.off,
				req->sync.len);
	if (ret < 0)
		req_set_fail_links(req);
	io_req_complete(req, ret);
	return 0;
}

static int __io_openat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	const char __user *fname;
	int ret;

	if (unlikely(sqe->ioprio || sqe->buf_index))
		return -EINVAL;
	if (unlikely(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	/* open.how should be already initialised */
	if (!(req->open.how.flags & O_PATH) && force_o_largefile())
		req->open.how.flags |= O_LARGEFILE;

	req->open.dfd = READ_ONCE(sqe->fd);
	fname = u64_to_user_ptr(READ_ONCE(sqe->addr));
	req->open.filename = getname(fname);
	if (IS_ERR(req->open.filename)) {
		ret = PTR_ERR(req->open.filename);
		req->open.filename = NULL;
		return ret;
	}
	req->open.nofile = rlimit(RLIMIT_NOFILE);
	req->flags |= REQ_F_NEED_CLEANUP;
	return 0;
}

static int io_openat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	u64 flags, mode;

	if (unlikely(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;
	mode = READ_ONCE(sqe->len);
	flags = READ_ONCE(sqe->open_flags);
	req->open.how = build_open_how(flags, mode);
	return __io_openat_prep(req, sqe);
}

static int io_openat2_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct open_how __user *how;
	size_t len;
	int ret;

	if (unlikely(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;
	how = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	len = READ_ONCE(sqe->len);
	if (len < OPEN_HOW_SIZE_VER0)
		return -EINVAL;

	ret = copy_struct_from_user(&req->open.how, sizeof(req->open.how), how,
					len);
	if (ret)
		return ret;

	return __io_openat_prep(req, sqe);
}

static int io_openat2(struct io_kiocb *req, unsigned int issue_flags)
{
	struct open_flags op;
	struct file *file;
	bool nonblock_set;
	bool resolve_nonblock;
	int ret;

	ret = build_open_flags(&req->open.how, &op);
	if (ret)
		goto err;
	nonblock_set = op.open_flag & O_NONBLOCK;
	resolve_nonblock = req->open.how.resolve & RESOLVE_CACHED;
	if (issue_flags & IO_URING_F_NONBLOCK) {
		/*
		 * Don't bother trying for O_TRUNC, O_CREAT, or O_TMPFILE open,
		 * it'll always -EAGAIN
		 */
		if (req->open.how.flags & (O_TRUNC | O_CREAT | O_TMPFILE))
			return -EAGAIN;
		op.lookup_flags |= LOOKUP_CACHED;
		op.open_flag |= O_NONBLOCK;
	}

	ret = __get_unused_fd_flags(req->open.how.flags, req->open.nofile);
	if (ret < 0)
		goto err;

	file = do_filp_open(req->open.dfd, req->open.filename, &op);
	/* only retry if RESOLVE_CACHED wasn't already set by application */
	if ((!resolve_nonblock && (issue_flags & IO_URING_F_NONBLOCK)) &&
	    file == ERR_PTR(-EAGAIN)) {
		/*
		 * We could hang on to this 'fd', but seems like marginal
		 * gain for something that is now known to be a slower path.
		 * So just put it, and we'll get a new one when we retry.
		 */
		put_unused_fd(ret);
		return -EAGAIN;
	}

	if (IS_ERR(file)) {
		put_unused_fd(ret);
		ret = PTR_ERR(file);
	} else {
		if ((issue_flags & IO_URING_F_NONBLOCK) && !nonblock_set)
			file->f_flags &= ~O_NONBLOCK;
		fsnotify_open(file);
		fd_install(ret, file);
	}
err:
	putname(req->open.filename);
	req->flags &= ~REQ_F_NEED_CLEANUP;
	if (ret < 0)
		req_set_fail_links(req);
	io_req_complete(req, ret);
	return 0;
}

static int io_openat(struct io_kiocb *req, unsigned int issue_flags)
{
	return io_openat2(req, issue_flags & IO_URING_F_NONBLOCK);
}

static int io_remove_buffers_prep(struct io_kiocb *req,
				  const struct io_uring_sqe *sqe)
{
	struct io_provide_buf *p = &req->pbuf;
	u64 tmp;

	if (sqe->ioprio || sqe->rw_flags || sqe->addr || sqe->len || sqe->off)
		return -EINVAL;

	tmp = READ_ONCE(sqe->fd);
	if (!tmp || tmp > USHRT_MAX)
		return -EINVAL;

	memset(p, 0, sizeof(*p));
	p->nbufs = tmp;
	p->bgid = READ_ONCE(sqe->buf_group);
	return 0;
}

static int __io_remove_buffers(struct io_ring_ctx *ctx, struct io_buffer *buf,
			       int bgid, unsigned nbufs)
{
	unsigned i = 0;

	/* shouldn't happen */
	if (!nbufs)
		return 0;

	/* the head kbuf is the list itself */
	while (!list_empty(&buf->list)) {
		struct io_buffer *nxt;

		nxt = list_first_entry(&buf->list, struct io_buffer, list);
		list_del(&nxt->list);
		kfree(nxt);
		if (++i == nbufs)
			return i;
	}
	i++;
	kfree(buf);
	idr_remove(&ctx->io_buffer_idr, bgid);

	return i;
}

static int io_remove_buffers(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_provide_buf *p = &req->pbuf;
	struct io_ring_ctx *ctx = req->ctx;
	struct io_buffer *head;
	int ret = 0;
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;

	io_ring_submit_lock(ctx, !force_nonblock);

	lockdep_assert_held(&ctx->uring_lock);

	ret = -ENOENT;
	head = idr_find(&ctx->io_buffer_idr, p->bgid);
	if (head)
		ret = __io_remove_buffers(ctx, head, p->bgid, p->nbufs);
	if (ret < 0)
		req_set_fail_links(req);

	/* need to hold the lock to complete IOPOLL requests */
	if (ctx->flags & IORING_SETUP_IOPOLL) {
		__io_req_complete(req, issue_flags, ret, 0);
		io_ring_submit_unlock(ctx, !force_nonblock);
	} else {
		io_ring_submit_unlock(ctx, !force_nonblock);
		__io_req_complete(req, issue_flags, ret, 0);
	}
	return 0;
}

static int io_provide_buffers_prep(struct io_kiocb *req,
				   const struct io_uring_sqe *sqe)
{
	struct io_provide_buf *p = &req->pbuf;
	u64 tmp;

	if (sqe->ioprio || sqe->rw_flags)
		return -EINVAL;

	tmp = READ_ONCE(sqe->fd);
	if (!tmp || tmp > USHRT_MAX)
		return -E2BIG;
	p->nbufs = tmp;
	p->addr = READ_ONCE(sqe->addr);
	p->len = READ_ONCE(sqe->len);

	if (!access_ok(u64_to_user_ptr(p->addr), (p->len * p->nbufs)))
		return -EFAULT;

	p->bgid = READ_ONCE(sqe->buf_group);
	tmp = READ_ONCE(sqe->off);
	if (tmp > USHRT_MAX)
		return -E2BIG;
	p->bid = tmp;
	return 0;
}

static int io_add_buffers(struct io_provide_buf *pbuf, struct io_buffer **head)
{
	struct io_buffer *buf;
	u64 addr = pbuf->addr;
	int i, bid = pbuf->bid;

	for (i = 0; i < pbuf->nbufs; i++) {
		buf = kmalloc(sizeof(*buf), GFP_KERNEL);
		if (!buf)
			break;

		buf->addr = addr;
		buf->len = pbuf->len;
		buf->bid = bid;
		addr += pbuf->len;
		bid++;
		if (!*head) {
			INIT_LIST_HEAD(&buf->list);
			*head = buf;
		} else {
			list_add_tail(&buf->list, &(*head)->list);
		}
	}

	return i ? i : -ENOMEM;
}

static int io_provide_buffers(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_provide_buf *p = &req->pbuf;
	struct io_ring_ctx *ctx = req->ctx;
	struct io_buffer *head, *list;
	int ret = 0;
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;

	io_ring_submit_lock(ctx, !force_nonblock);

	lockdep_assert_held(&ctx->uring_lock);

	list = head = idr_find(&ctx->io_buffer_idr, p->bgid);

	ret = io_add_buffers(p, &head);
	if (ret < 0)
		goto out;

	if (!list) {
		ret = idr_alloc(&ctx->io_buffer_idr, head, p->bgid, p->bgid + 1,
					GFP_KERNEL);
		if (ret < 0) {
			__io_remove_buffers(ctx, head, p->bgid, -1U);
			goto out;
		}
	}
out:
	if (ret < 0)
		req_set_fail_links(req);

	/* need to hold the lock to complete IOPOLL requests */
	if (ctx->flags & IORING_SETUP_IOPOLL) {
		__io_req_complete(req, issue_flags, ret, 0);
		io_ring_submit_unlock(ctx, !force_nonblock);
	} else {
		io_ring_submit_unlock(ctx, !force_nonblock);
		__io_req_complete(req, issue_flags, ret, 0);
	}
	return 0;
}

static int io_epoll_ctl_prep(struct io_kiocb *req,
			     const struct io_uring_sqe *sqe)
{
#if defined(CONFIG_EPOLL)
	if (sqe->ioprio || sqe->buf_index)
		return -EINVAL;
	if (unlikely(req->ctx->flags & (IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL)))
		return -EINVAL;

	req->epoll.epfd = READ_ONCE(sqe->fd);
	req->epoll.op = READ_ONCE(sqe->len);
	req->epoll.fd = READ_ONCE(sqe->off);

	if (ep_op_has_event(req->epoll.op)) {
		struct epoll_event __user *ev;

		ev = u64_to_user_ptr(READ_ONCE(sqe->addr));
		if (copy_from_user(&req->epoll.event, ev, sizeof(*ev)))
			return -EFAULT;
	}

	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

static int io_epoll_ctl(struct io_kiocb *req, unsigned int issue_flags)
{
#if defined(CONFIG_EPOLL)
	struct io_epoll *ie = &req->epoll;
	int ret;
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;

	ret = do_epoll_ctl(ie->epfd, ie->op, ie->fd, &ie->event, force_nonblock);
	if (force_nonblock && ret == -EAGAIN)
		return -EAGAIN;

	if (ret < 0)
		req_set_fail_links(req);
	__io_req_complete(req, issue_flags, ret, 0);
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

static int io_madvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
#if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)
	if (sqe->ioprio || sqe->buf_index || sqe->off)
		return -EINVAL;
	if (unlikely(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;

	req->madvise.addr = READ_ONCE(sqe->addr);
	req->madvise.len = READ_ONCE(sqe->len);
	req->madvise.advice = READ_ONCE(sqe->fadvise_advice);
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

static int io_madvise(struct io_kiocb *req, unsigned int issue_flags)
{
#if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)
	struct io_madvise *ma = &req->madvise;
	int ret;

	if (issue_flags & IO_URING_F_NONBLOCK)
		return -EAGAIN;

	ret = do_madvise(current->mm, ma->addr, ma->len, ma->advice);
	if (ret < 0)
		req_set_fail_links(req);
	io_req_complete(req, ret);
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

static int io_fadvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	if (sqe->ioprio || sqe->buf_index || sqe->addr)
		return -EINVAL;
	if (unlikely(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;

	req->fadvise.offset = READ_ONCE(sqe->off);
	req->fadvise.len = READ_ONCE(sqe->len);
	req->fadvise.advice = READ_ONCE(sqe->fadvise_advice);
	return 0;
}

static int io_fadvise(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_fadvise *fa = &req->fadvise;
	int ret;

	if (issue_flags & IO_URING_F_NONBLOCK) {
		switch (fa->advice) {
		case POSIX_FADV_NORMAL:
		case POSIX_FADV_RANDOM:
		case POSIX_FADV_SEQUENTIAL:
			break;
		default:
			return -EAGAIN;
		}
	}

	ret = vfs_fadvise(req->file, fa->offset, fa->len, fa->advice);
	if (ret < 0)
		req_set_fail_links(req);
	io_req_complete(req, ret);
	return 0;
}

static int io_statx_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	if (unlikely(req->ctx->flags & (IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL)))
		return -EINVAL;
	if (sqe->ioprio || sqe->buf_index)
		return -EINVAL;
	if (req->flags & REQ_F_FIXED_FILE)
		return -EBADF;

	req->statx.dfd = READ_ONCE(sqe->fd);
	req->statx.mask = READ_ONCE(sqe->len);
	req->statx.filename = u64_to_user_ptr(READ_ONCE(sqe->addr));
	req->statx.buffer = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	req->statx.flags = READ_ONCE(sqe->statx_flags);

	return 0;
}

static int io_statx(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_statx *ctx = &req->statx;
	int ret;

	if (issue_flags & IO_URING_F_NONBLOCK) {
		/* only need file table for an actual valid fd */
		if (ctx->dfd == -1 || ctx->dfd == AT_FDCWD)
			req->flags |= REQ_F_NO_FILE_TABLE;
		return -EAGAIN;
	}

	ret = do_statx(ctx->dfd, ctx->filename, ctx->flags, ctx->mask,
		       ctx->buffer);

	if (ret < 0)
		req_set_fail_links(req);
	io_req_complete(req, ret);
	return 0;
}

static int io_close_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	if (unlikely(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;
	if (sqe->ioprio || sqe->off || sqe->addr || sqe->len ||
	    sqe->rw_flags || sqe->buf_index)
		return -EINVAL;
	if (req->flags & REQ_F_FIXED_FILE)
		return -EBADF;

	req->close.fd = READ_ONCE(sqe->fd);
	return 0;
}

static int io_close(struct io_kiocb *req, unsigned int issue_flags)
{
	struct files_struct *files = current->files;
	struct io_close *close = &req->close;
	struct fdtable *fdt;
	struct file *file;
	int ret;

	file = NULL;
	ret = -EBADF;
	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if (close->fd >= fdt->max_fds) {
		spin_unlock(&files->file_lock);
		goto err;
	}
	file = fdt->fd[close->fd];
	if (!file) {
		spin_unlock(&files->file_lock);
		goto err;
	}

	if (file->f_op == &io_uring_fops) {
		spin_unlock(&files->file_lock);
		file = NULL;
		goto err;
	}

	/* if the file has a flush method, be safe and punt to async */
	if (file->f_op->flush && (issue_flags & IO_URING_F_NONBLOCK)) {
		spin_unlock(&files->file_lock);
		return -EAGAIN;
	}

	ret = __close_fd_get_file(close->fd, &file);
	spin_unlock(&files->file_lock);
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = -EBADF;
		goto err;
	}

	/* No ->flush() or already async, safely close from here */
	ret = filp_close(file, current->files);
err:
	if (ret < 0)
		req_set_fail_links(req);
	if (file)
		fput(file);
	__io_req_complete(req, issue_flags, ret, 0);
	return 0;
}

static int io_prep_sfr(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_ring_ctx *ctx = req->ctx;

	if (!req->file)
		return -EBADF;

	if (unlikely(ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;
	if (unlikely(sqe->addr || sqe->ioprio || sqe->buf_index))
		return -EINVAL;

	req->sync.off = READ_ONCE(sqe->off);
	req->sync.len = READ_ONCE(sqe->len);
	req->sync.flags = READ_ONCE(sqe->sync_range_flags);
	return 0;
}

static int io_sync_file_range(struct io_kiocb *req, unsigned int issue_flags)
{
	int ret;

	/* sync_file_range always requires a blocking context */
	if (issue_flags & IO_URING_F_NONBLOCK)
		return -EAGAIN;

	ret = sync_file_range(req->file, req->sync.off, req->sync.len,
				req->sync.flags);
	if (ret < 0)
		req_set_fail_links(req);
	io_req_complete(req, ret);
	return 0;
}

#if defined(CONFIG_NET)
static int io_setup_async_msg(struct io_kiocb *req,
			      struct io_async_msghdr *kmsg)
{
	struct io_async_msghdr *async_msg = req->async_data;

	if (async_msg)
		return -EAGAIN;
	if (io_alloc_async_data(req)) {
		kfree(kmsg->free_iov);
		return -ENOMEM;
	}
	async_msg = req->async_data;
	req->flags |= REQ_F_NEED_CLEANUP;
	memcpy(async_msg, kmsg, sizeof(*kmsg));
	async_msg->msg.msg_name = &async_msg->addr;
	/* if were using fast_iov, set it to the new one */
	if (!async_msg->free_iov)
		async_msg->msg.msg_iter.iov = async_msg->fast_iov;

	return -EAGAIN;
}

static int io_sendmsg_copy_hdr(struct io_kiocb *req,
			       struct io_async_msghdr *iomsg)
{
	iomsg->msg.msg_name = &iomsg->addr;
	iomsg->free_iov = iomsg->fast_iov;
	return sendmsg_copy_msghdr(&iomsg->msg, req->sr_msg.umsg,
				   req->sr_msg.msg_flags, &iomsg->free_iov);
}

static int io_sendmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_async_msghdr *async_msg = req->async_data;
	struct io_sr_msg *sr = &req->sr_msg;
	int ret;

	if (unlikely(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;

	sr->msg_flags = READ_ONCE(sqe->msg_flags);
	sr->umsg = u64_to_user_ptr(READ_ONCE(sqe->addr));
	sr->len = READ_ONCE(sqe->len);

#ifdef CONFIG_COMPAT
	if (req->ctx->compat)
		sr->msg_flags |= MSG_CMSG_COMPAT;
#endif

	if (!async_msg || !io_op_defs[req->opcode].needs_async_data)
		return 0;
	ret = io_sendmsg_copy_hdr(req, async_msg);
	if (!ret)
		req->flags |= REQ_F_NEED_CLEANUP;
	return ret;
}

static int io_sendmsg(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_async_msghdr iomsg, *kmsg;
	struct socket *sock;
	unsigned flags;
	int ret;

	sock = sock_from_file(req->file);
	if (unlikely(!sock))
		return -ENOTSOCK;

	kmsg = req->async_data;
	if (!kmsg) {
		ret = io_sendmsg_copy_hdr(req, &iomsg);
		if (ret)
			return ret;
		kmsg = &iomsg;
	}

	flags = req->sr_msg.msg_flags;
	if (flags & MSG_DONTWAIT)
		req->flags |= REQ_F_NOWAIT;
	else if (issue_flags & IO_URING_F_NONBLOCK)
		flags |= MSG_DONTWAIT;

	ret = __sys_sendmsg_sock(sock, &kmsg->msg, flags);
	if ((issue_flags & IO_URING_F_NONBLOCK) && ret == -EAGAIN)
		return io_setup_async_msg(req, kmsg);
	if (ret == -ERESTARTSYS)
		ret = -EINTR;

	/* fast path, check for non-NULL to avoid function call */
	if (kmsg->free_iov)
		kfree(kmsg->free_iov);
	req->flags &= ~REQ_F_NEED_CLEANUP;
	if (ret < 0)
		req_set_fail_links(req);
	__io_req_complete(req, issue_flags, ret, 0);
	return 0;
}

static int io_send(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_sr_msg *sr = &req->sr_msg;
	struct msghdr msg;
	struct iovec iov;
	struct socket *sock;
	unsigned flags;
	int ret;

	sock = sock_from_file(req->file);
	if (unlikely(!sock))
		return -ENOTSOCK;

	ret = import_single_range(WRITE, sr->buf, sr->len, &iov, &msg.msg_iter);
	if (unlikely(ret))
		return ret;

	msg.msg_name = NULL;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_namelen = 0;

	flags = req->sr_msg.msg_flags;
	if (flags & MSG_DONTWAIT)
		req->flags |= REQ_F_NOWAIT;
	else if (issue_flags & IO_URING_F_NONBLOCK)
		flags |= MSG_DONTWAIT;

	msg.msg_flags = flags;
	ret = sock_sendmsg(sock, &msg);
	if ((issue_flags & IO_URING_F_NONBLOCK) && ret == -EAGAIN)
		return -EAGAIN;
	if (ret == -ERESTARTSYS)
		ret = -EINTR;

	if (ret < 0)
		req_set_fail_links(req);
	__io_req_complete(req, issue_flags, ret, 0);
	return 0;
}

static int __io_recvmsg_copy_hdr(struct io_kiocb *req,
				 struct io_async_msghdr *iomsg)
{
	struct io_sr_msg *sr = &req->sr_msg;
	struct iovec __user *uiov;
	size_t iov_len;
	int ret;

	ret = __copy_msghdr_from_user(&iomsg->msg, sr->umsg,
					&iomsg->uaddr, &uiov, &iov_len);
	if (ret)
		return ret;

	if (req->flags & REQ_F_BUFFER_SELECT) {
		if (iov_len > 1)
			return -EINVAL;
		if (copy_from_user(iomsg->fast_iov, uiov, sizeof(*uiov)))
			return -EFAULT;
		sr->len = iomsg->fast_iov[0].iov_len;
		iomsg->free_iov = NULL;
	} else {
		iomsg->free_iov = iomsg->fast_iov;
		ret = __import_iovec(READ, uiov, iov_len, UIO_FASTIOV,
				     &iomsg->free_iov, &iomsg->msg.msg_iter,
				     false);
		if (ret > 0)
			ret = 0;
	}

	return ret;
}

#ifdef CONFIG_COMPAT
static int __io_compat_recvmsg_copy_hdr(struct io_kiocb *req,
					struct io_async_msghdr *iomsg)
{
	struct compat_msghdr __user *msg_compat;
	struct io_sr_msg *sr = &req->sr_msg;
	struct compat_iovec __user *uiov;
	compat_uptr_t ptr;
	compat_size_t len;
	int ret;

	msg_compat = (struct compat_msghdr __user *) sr->umsg;
	ret = __get_compat_msghdr(&iomsg->msg, msg_compat, &iomsg->uaddr,
					&ptr, &len);
	if (ret)
		return ret;

	uiov = compat_ptr(ptr);
	if (req->flags & REQ_F_BUFFER_SELECT) {
		compat_ssize_t clen;

		if (len > 1)
			return -EINVAL;
		if (!access_ok(uiov, sizeof(*uiov)))
			return -EFAULT;
		if (__get_user(clen, &uiov->iov_len))
			return -EFAULT;
		if (clen < 0)
			return -EINVAL;
		sr->len = clen;
		iomsg->free_iov = NULL;
	} else {
		iomsg->free_iov = iomsg->fast_iov;
		ret = __import_iovec(READ, (struct iovec __user *)uiov, len,
				   UIO_FASTIOV, &iomsg->free_iov,
				   &iomsg->msg.msg_iter, true);
		if (ret < 0)
			return ret;
	}

	return 0;
}
#endif

static int io_recvmsg_copy_hdr(struct io_kiocb *req,
			       struct io_async_msghdr *iomsg)
{
	iomsg->msg.msg_name = &iomsg->addr;

#ifdef CONFIG_COMPAT
	if (req->ctx->compat)
		return __io_compat_recvmsg_copy_hdr(req, iomsg);
#endif

	return __io_recvmsg_copy_hdr(req, iomsg);
}

static struct io_buffer *io_recv_buffer_select(struct io_kiocb *req,
					       bool needs_lock)
{
	struct io_sr_msg *sr = &req->sr_msg;
	struct io_buffer *kbuf;

	kbuf = io_buffer_select(req, &sr->len, sr->bgid, sr->kbuf, needs_lock);
	if (IS_ERR(kbuf))
		return kbuf;

	sr->kbuf = kbuf;
	req->flags |= REQ_F_BUFFER_SELECTED;
	return kbuf;
}

static inline unsigned int io_put_recv_kbuf(struct io_kiocb *req)
{
	return io_put_kbuf(req, req->sr_msg.kbuf);
}

static int io_recvmsg_prep(struct io_kiocb *req,
			   const struct io_uring_sqe *sqe)
{
	struct io_async_msghdr *async_msg = req->async_data;
	struct io_sr_msg *sr = &req->sr_msg;
	int ret;

	if (unlikely(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;

	sr->msg_flags = READ_ONCE(sqe->msg_flags);
	sr->umsg = u64_to_user_ptr(READ_ONCE(sqe->addr));
	sr->len = READ_ONCE(sqe->len);
	sr->bgid = READ_ONCE(sqe->buf_group);

#ifdef CONFIG_COMPAT
	if (req->ctx->compat)
		sr->msg_flags |= MSG_CMSG_COMPAT;
#endif

	if (!async_msg || !io_op_defs[req->opcode].needs_async_data)
		return 0;
	ret = io_recvmsg_copy_hdr(req, async_msg);
	if (!ret)
		req->flags |= REQ_F_NEED_CLEANUP;
	return ret;
}

static int io_recvmsg(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_async_msghdr iomsg, *kmsg;
	struct socket *sock;
	struct io_buffer *kbuf;
	unsigned flags;
	int ret, cflags = 0;
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;

	sock = sock_from_file(req->file);
	if (unlikely(!sock))
		return -ENOTSOCK;

	kmsg = req->async_data;
	if (!kmsg) {
		ret = io_recvmsg_copy_hdr(req, &iomsg);
		if (ret)
			return ret;
		kmsg = &iomsg;
	}

	if (req->flags & REQ_F_BUFFER_SELECT) {
		kbuf = io_recv_buffer_select(req, !force_nonblock);
		if (IS_ERR(kbuf))
			return PTR_ERR(kbuf);
		kmsg->fast_iov[0].iov_base = u64_to_user_ptr(kbuf->addr);
		kmsg->fast_iov[0].iov_len = req->sr_msg.len;
		iov_iter_init(&kmsg->msg.msg_iter, READ, kmsg->fast_iov,
				1, req->sr_msg.len);
	}

	flags = req->sr_msg.msg_flags;
	if (flags & MSG_DONTWAIT)
		req->flags |= REQ_F_NOWAIT;
	else if (force_nonblock)
		flags |= MSG_DONTWAIT;

	ret = __sys_recvmsg_sock(sock, &kmsg->msg, req->sr_msg.umsg,
					kmsg->uaddr, flags);
	if (force_nonblock && ret == -EAGAIN)
		return io_setup_async_msg(req, kmsg);
	if (ret == -ERESTARTSYS)
		ret = -EINTR;

	if (req->flags & REQ_F_BUFFER_SELECTED)
		cflags = io_put_recv_kbuf(req);
	/* fast path, check for non-NULL to avoid function call */
	if (kmsg->free_iov)
		kfree(kmsg->free_iov);
	req->flags &= ~REQ_F_NEED_CLEANUP;
	if (ret < 0)
		req_set_fail_links(req);
	__io_req_complete(req, issue_flags, ret, cflags);
	return 0;
}

static int io_recv(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_buffer *kbuf;
	struct io_sr_msg *sr = &req->sr_msg;
	struct msghdr msg;
	void __user *buf = sr->buf;
	struct socket *sock;
	struct iovec iov;
	unsigned flags;
	int ret, cflags = 0;
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;

	sock = sock_from_file(req->file);
	if (unlikely(!sock))
		return -ENOTSOCK;

	if (req->flags & REQ_F_BUFFER_SELECT) {
		kbuf = io_recv_buffer_select(req, !force_nonblock);
		if (IS_ERR(kbuf))
			return PTR_ERR(kbuf);
		buf = u64_to_user_ptr(kbuf->addr);
	}

	ret = import_single_range(READ, buf, sr->len, &iov, &msg.msg_iter);
	if (unlikely(ret))
		goto out_free;

	msg.msg_name = NULL;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_namelen = 0;
	msg.msg_iocb = NULL;
	msg.msg_flags = 0;

	flags = req->sr_msg.msg_flags;
	if (flags & MSG_DONTWAIT)
		req->flags |= REQ_F_NOWAIT;
	else if (force_nonblock)
		flags |= MSG_DONTWAIT;

	ret = sock_recvmsg(sock, &msg, flags);
	if (force_nonblock && ret == -EAGAIN)
		return -EAGAIN;
	if (ret == -ERESTARTSYS)
		ret = -EINTR;
out_free:
	if (req->flags & REQ_F_BUFFER_SELECTED)
		cflags = io_put_recv_kbuf(req);
	if (ret < 0)
		req_set_fail_links(req);
	__io_req_complete(req, issue_flags, ret, cflags);
	return 0;
}

static int io_accept_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_accept *accept = &req->accept;

	if (unlikely(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;
	if (sqe->ioprio || sqe->len || sqe->buf_index)
		return -EINVAL;

	accept->addr = u64_to_user_ptr(READ_ONCE(sqe->addr));
	accept->addr_len = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	accept->flags = READ_ONCE(sqe->accept_flags);
	accept->nofile = rlimit(RLIMIT_NOFILE);
	return 0;
}

static int io_accept(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_accept *accept = &req->accept;
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;
	unsigned int file_flags = force_nonblock ? O_NONBLOCK : 0;
	int ret;

	if (req->file->f_flags & O_NONBLOCK)
		req->flags |= REQ_F_NOWAIT;

	ret = __sys_accept4_file(req->file, file_flags, accept->addr,
					accept->addr_len, accept->flags,
					accept->nofile);
	if (ret == -EAGAIN && force_nonblock)
		return -EAGAIN;
	if (ret < 0) {
		if (ret == -ERESTARTSYS)
			ret = -EINTR;
		req_set_fail_links(req);
	}
	__io_req_complete(req, issue_flags, ret, 0);
	return 0;
}

static int io_connect_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_connect *conn = &req->connect;
	struct io_async_connect *io = req->async_data;

	if (unlikely(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;
	if (sqe->ioprio || sqe->len || sqe->buf_index || sqe->rw_flags)
		return -EINVAL;

	conn->addr = u64_to_user_ptr(READ_ONCE(sqe->addr));
	conn->addr_len =  READ_ONCE(sqe->addr2);

	if (!io)
		return 0;

	return move_addr_to_kernel(conn->addr, conn->addr_len,
					&io->address);
}

static int io_connect(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_async_connect __io, *io;
	unsigned file_flags;
	int ret;
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;

	if (req->async_data) {
		io = req->async_data;
	} else {
		ret = move_addr_to_kernel(req->connect.addr,
						req->connect.addr_len,
						&__io.address);
		if (ret)
			goto out;
		io = &__io;
	}

	file_flags = force_nonblock ? O_NONBLOCK : 0;

	ret = __sys_connect_file(req->file, &io->address,
					req->connect.addr_len, file_flags);
	if ((ret == -EAGAIN || ret == -EINPROGRESS) && force_nonblock) {
		if (req->async_data)
			return -EAGAIN;
		if (io_alloc_async_data(req)) {
			ret = -ENOMEM;
			goto out;
		}
		io = req->async_data;
		memcpy(req->async_data, &__io, sizeof(__io));
		return -EAGAIN;
	}
	if (ret == -ERESTARTSYS)
		ret = -EINTR;
out:
	if (ret < 0)
		req_set_fail_links(req);
	__io_req_complete(req, issue_flags, ret, 0);
	return 0;
}
#else /* !CONFIG_NET */
static int io_sendmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	return -EOPNOTSUPP;
}

static int io_sendmsg(struct io_kiocb *req, unsigned int issue_flags)
{
	return -EOPNOTSUPP;
}

static int io_send(struct io_kiocb *req, unsigned int issue_flags)
{
	return -EOPNOTSUPP;
}

static int io_recvmsg_prep(struct io_kiocb *req,
			   const struct io_uring_sqe *sqe)
{
	return -EOPNOTSUPP;
}

static int io_recvmsg(struct io_kiocb *req, unsigned int issue_flags)
{
	return -EOPNOTSUPP;
}

static int io_recv(struct io_kiocb *req, unsigned int issue_flags)
{
	return -EOPNOTSUPP;
}

static int io_accept_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	return -EOPNOTSUPP;
}

static int io_accept(struct io_kiocb *req, unsigned int issue_flags)
{
	return -EOPNOTSUPP;
}

static int io_connect_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	return -EOPNOTSUPP;
}

static int io_connect(struct io_kiocb *req, unsigned int issue_flags)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_NET */

struct io_poll_table {
	struct poll_table_struct pt;
	struct io_kiocb *req;
	int error;
};

static int __io_async_wake(struct io_kiocb *req, struct io_poll_iocb *poll,
			   __poll_t mask, task_work_func_t func)
{
	int ret;

	/* for instances that support it check for an event match first: */
	if (mask && !(mask & poll->events))
		return 0;

	trace_io_uring_task_add(req->ctx, req->opcode, req->user_data, mask);

	list_del_init(&poll->wait.entry);

	req->result = mask;
	req->task_work.func = func;
	percpu_ref_get(&req->ctx->refs);

	/*
	 * If this fails, then the task is exiting. When a task exits, the
	 * work gets canceled, so just cancel this request as well instead
	 * of executing it. We can't safely execute it anyway, as we may not
	 * have the needed state needed for it anyway.
	 */
	ret = io_req_task_work_add(req);
	if (unlikely(ret)) {
		WRITE_ONCE(poll->canceled, true);
		io_req_task_work_add_fallback(req, func);
	}
	return 1;
}

static bool io_poll_rewait(struct io_kiocb *req, struct io_poll_iocb *poll)
	__acquires(&req->ctx->completion_lock)
{
	struct io_ring_ctx *ctx = req->ctx;

	if (!req->result && !READ_ONCE(poll->canceled)) {
		struct poll_table_struct pt = { ._key = poll->events };

		req->result = vfs_poll(req->file, &pt) & poll->events;
	}

	spin_lock_irq(&ctx->completion_lock);
	if (!req->result && !READ_ONCE(poll->canceled)) {
		add_wait_queue(poll->head, &poll->wait);
		return true;
	}

	return false;
}

static struct io_poll_iocb *io_poll_get_double(struct io_kiocb *req)
{
	/* pure poll stashes this in ->async_data, poll driven retry elsewhere */
	if (req->opcode == IORING_OP_POLL_ADD)
		return req->async_data;
	return req->apoll->double_poll;
}

static struct io_poll_iocb *io_poll_get_single(struct io_kiocb *req)
{
	if (req->opcode == IORING_OP_POLL_ADD)
		return &req->poll;
	return &req->apoll->poll;
}

static void io_poll_remove_double(struct io_kiocb *req)
{
	struct io_poll_iocb *poll = io_poll_get_double(req);

	lockdep_assert_held(&req->ctx->completion_lock);

	if (poll && poll->head) {
		struct wait_queue_head *head = poll->head;

		spin_lock(&head->lock);
		list_del_init(&poll->wait.entry);
		if (poll->wait.private)
			refcount_dec(&req->refs);
		poll->head = NULL;
		spin_unlock(&head->lock);
	}
}

static void io_poll_complete(struct io_kiocb *req, __poll_t mask, int error)
{
	struct io_ring_ctx *ctx = req->ctx;

	io_poll_remove_double(req);
	req->poll.done = true;
	io_cqring_fill_event(req, error ? error : mangle_poll(mask));
	io_commit_cqring(ctx);
}

static void io_poll_task_func(struct callback_head *cb)
{
	struct io_kiocb *req = container_of(cb, struct io_kiocb, task_work);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_kiocb *nxt;

	if (io_poll_rewait(req, &req->poll)) {
		spin_unlock_irq(&ctx->completion_lock);
	} else {
		hash_del(&req->hash_node);
		io_poll_complete(req, req->result, 0);
		spin_unlock_irq(&ctx->completion_lock);

		nxt = io_put_req_find_next(req);
		io_cqring_ev_posted(ctx);
		if (nxt)
			__io_req_task_submit(nxt);
	}

	percpu_ref_put(&ctx->refs);
}

static int io_poll_double_wake(struct wait_queue_entry *wait, unsigned mode,
			       int sync, void *key)
{
	struct io_kiocb *req = wait->private;
	struct io_poll_iocb *poll = io_poll_get_single(req);
	__poll_t mask = key_to_poll(key);

	/* for instances that support it check for an event match first: */
	if (mask && !(mask & poll->events))
		return 0;

	list_del_init(&wait->entry);

	if (poll && poll->head) {
		bool done;

		spin_lock(&poll->head->lock);
		done = list_empty(&poll->wait.entry);
		if (!done)
			list_del_init(&poll->wait.entry);
		/* make sure double remove sees this as being gone */
		wait->private = NULL;
		spin_unlock(&poll->head->lock);
		if (!done) {
			/* use wait func handler, so it matches the rq type */
			poll->wait.func(&poll->wait, mode, sync, key);
		}
	}
	refcount_dec(&req->refs);
	return 1;
}

static void io_init_poll_iocb(struct io_poll_iocb *poll, __poll_t events,
			      wait_queue_func_t wake_func)
{
	poll->head = NULL;
	poll->done = false;
	poll->canceled = false;
	poll->events = events;
	INIT_LIST_HEAD(&poll->wait.entry);
	init_waitqueue_func_entry(&poll->wait, wake_func);
}

static void __io_queue_proc(struct io_poll_iocb *poll, struct io_poll_table *pt,
			    struct wait_queue_head *head,
			    struct io_poll_iocb **poll_ptr)
{
	struct io_kiocb *req = pt->req;

	/*
	 * If poll->head is already set, it's because the file being polled
	 * uses multiple waitqueues for poll handling (eg one for read, one
	 * for write). Setup a separate io_poll_iocb if this happens.
	 */
	if (unlikely(poll->head)) {
		struct io_poll_iocb *poll_one = poll;

		/* already have a 2nd entry, fail a third attempt */
		if (*poll_ptr) {
			pt->error = -EINVAL;
			return;
		}
		poll = kmalloc(sizeof(*poll), GFP_ATOMIC);
		if (!poll) {
			pt->error = -ENOMEM;
			return;
		}
		io_init_poll_iocb(poll, poll_one->events, io_poll_double_wake);
		refcount_inc(&req->refs);
		poll->wait.private = req;
		*poll_ptr = poll;
	}

	pt->error = 0;
	poll->head = head;

	if (poll->events & EPOLLEXCLUSIVE)
		add_wait_queue_exclusive(head, &poll->wait);
	else
		add_wait_queue(head, &poll->wait);
}

static void io_async_queue_proc(struct file *file, struct wait_queue_head *head,
			       struct poll_table_struct *p)
{
	struct io_poll_table *pt = container_of(p, struct io_poll_table, pt);
	struct async_poll *apoll = pt->req->apoll;

	__io_queue_proc(&apoll->poll, pt, head, &apoll->double_poll);
}

static void io_async_task_func(struct callback_head *cb)
{
	struct io_kiocb *req = container_of(cb, struct io_kiocb, task_work);
	struct async_poll *apoll = req->apoll;
	struct io_ring_ctx *ctx = req->ctx;

	trace_io_uring_task_run(req->ctx, req->opcode, req->user_data);

	if (io_poll_rewait(req, &apoll->poll)) {
		spin_unlock_irq(&ctx->completion_lock);
		percpu_ref_put(&ctx->refs);
		return;
	}

	/* If req is still hashed, it cannot have been canceled. Don't check. */
	if (hash_hashed(&req->hash_node))
		hash_del(&req->hash_node);

	io_poll_remove_double(req);
	spin_unlock_irq(&ctx->completion_lock);

	if (!READ_ONCE(apoll->poll.canceled))
		__io_req_task_submit(req);
	else
		__io_req_task_cancel(req, -ECANCELED);

	percpu_ref_put(&ctx->refs);
	kfree(apoll->double_poll);
	kfree(apoll);
}

static int io_async_wake(struct wait_queue_entry *wait, unsigned mode, int sync,
			void *key)
{
	struct io_kiocb *req = wait->private;
	struct io_poll_iocb *poll = &req->apoll->poll;

	trace_io_uring_poll_wake(req->ctx, req->opcode, req->user_data,
					key_to_poll(key));

	return __io_async_wake(req, poll, key_to_poll(key), io_async_task_func);
}

static void io_poll_req_insert(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct hlist_head *list;

	list = &ctx->cancel_hash[hash_long(req->user_data, ctx->cancel_hash_bits)];
	hlist_add_head(&req->hash_node, list);
}

static __poll_t __io_arm_poll_handler(struct io_kiocb *req,
				      struct io_poll_iocb *poll,
				      struct io_poll_table *ipt, __poll_t mask,
				      wait_queue_func_t wake_func)
	__acquires(&ctx->completion_lock)
{
	struct io_ring_ctx *ctx = req->ctx;
	bool cancel = false;

	INIT_HLIST_NODE(&req->hash_node);
	io_init_poll_iocb(poll, mask, wake_func);
	poll->file = req->file;
	poll->wait.private = req;

	ipt->pt._key = mask;
	ipt->req = req;
	ipt->error = -EINVAL;

	mask = vfs_poll(req->file, &ipt->pt) & poll->events;

	spin_lock_irq(&ctx->completion_lock);
	if (likely(poll->head)) {
		spin_lock(&poll->head->lock);
		if (unlikely(list_empty(&poll->wait.entry))) {
			if (ipt->error)
				cancel = true;
			ipt->error = 0;
			mask = 0;
		}
		if (mask || ipt->error)
			list_del_init(&poll->wait.entry);
		else if (cancel)
			WRITE_ONCE(poll->canceled, true);
		else if (!poll->done) /* actually waiting for an event */
			io_poll_req_insert(req);
		spin_unlock(&poll->head->lock);
	}

	return mask;
}

static bool io_arm_poll_handler(struct io_kiocb *req)
{
	const struct io_op_def *def = &io_op_defs[req->opcode];
	struct io_ring_ctx *ctx = req->ctx;
	struct async_poll *apoll;
	struct io_poll_table ipt;
	__poll_t mask, ret;
	int rw;

	if (!req->file || !file_can_poll(req->file))
		return false;
	if (req->flags & REQ_F_POLLED)
		return false;
	if (def->pollin)
		rw = READ;
	else if (def->pollout)
		rw = WRITE;
	else
		return false;
	/* if we can't nonblock try, then no point in arming a poll handler */
	if (!io_file_supports_async(req->file, rw))
		return false;

	apoll = kmalloc(sizeof(*apoll), GFP_ATOMIC);
	if (unlikely(!apoll))
		return false;
	apoll->double_poll = NULL;

	req->flags |= REQ_F_POLLED;
	req->apoll = apoll;

	mask = 0;
	if (def->pollin)
		mask |= POLLIN | POLLRDNORM;
	if (def->pollout)
		mask |= POLLOUT | POLLWRNORM;

	/* If reading from MSG_ERRQUEUE using recvmsg, ignore POLLIN */
	if ((req->opcode == IORING_OP_RECVMSG) &&
	    (req->sr_msg.msg_flags & MSG_ERRQUEUE))
		mask &= ~POLLIN;

	mask |= POLLERR | POLLPRI;

	ipt.pt._qproc = io_async_queue_proc;

	ret = __io_arm_poll_handler(req, &apoll->poll, &ipt, mask,
					io_async_wake);
	if (ret || ipt.error) {
		io_poll_remove_double(req);
		spin_unlock_irq(&ctx->completion_lock);
		kfree(apoll->double_poll);
		kfree(apoll);
		return false;
	}
	spin_unlock_irq(&ctx->completion_lock);
	trace_io_uring_poll_arm(ctx, req->opcode, req->user_data, mask,
					apoll->poll.events);
	return true;
}

static bool __io_poll_remove_one(struct io_kiocb *req,
				 struct io_poll_iocb *poll)
{
	bool do_complete = false;

	spin_lock(&poll->head->lock);
	WRITE_ONCE(poll->canceled, true);
	if (!list_empty(&poll->wait.entry)) {
		list_del_init(&poll->wait.entry);
		do_complete = true;
	}
	spin_unlock(&poll->head->lock);
	hash_del(&req->hash_node);
	return do_complete;
}

static bool io_poll_remove_one(struct io_kiocb *req)
{
	bool do_complete;

	io_poll_remove_double(req);

	if (req->opcode == IORING_OP_POLL_ADD) {
		do_complete = __io_poll_remove_one(req, &req->poll);
	} else {
		struct async_poll *apoll = req->apoll;

		/* non-poll requests have submit ref still */
		do_complete = __io_poll_remove_one(req, &apoll->poll);
		if (do_complete) {
			io_put_req(req);
			kfree(apoll->double_poll);
			kfree(apoll);
		}
	}

	if (do_complete) {
		io_cqring_fill_event(req, -ECANCELED);
		io_commit_cqring(req->ctx);
		req_set_fail_links(req);
		io_put_req_deferred(req, 1);
	}

	return do_complete;
}

/*
 * Returns true if we found and killed one or more poll requests
 */
static bool io_poll_remove_all(struct io_ring_ctx *ctx, struct task_struct *tsk,
			       struct files_struct *files)
{
	struct hlist_node *tmp;
	struct io_kiocb *req;
	int posted = 0, i;

	spin_lock_irq(&ctx->completion_lock);
	for (i = 0; i < (1U << ctx->cancel_hash_bits); i++) {
		struct hlist_head *list;

		list = &ctx->cancel_hash[i];
		hlist_for_each_entry_safe(req, tmp, list, hash_node) {
			if (io_match_task(req, tsk, files))
				posted += io_poll_remove_one(req);
		}
	}
	spin_unlock_irq(&ctx->completion_lock);

	if (posted)
		io_cqring_ev_posted(ctx);

	return posted != 0;
}

static int io_poll_cancel(struct io_ring_ctx *ctx, __u64 sqe_addr)
{
	struct hlist_head *list;
	struct io_kiocb *req;

	list = &ctx->cancel_hash[hash_long(sqe_addr, ctx->cancel_hash_bits)];
	hlist_for_each_entry(req, list, hash_node) {
		if (sqe_addr != req->user_data)
			continue;
		if (io_poll_remove_one(req))
			return 0;
		return -EALREADY;
	}

	return -ENOENT;
}

static int io_poll_remove_prep(struct io_kiocb *req,
			       const struct io_uring_sqe *sqe)
{
	if (unlikely(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;
	if (sqe->ioprio || sqe->off || sqe->len || sqe->buf_index ||
	    sqe->poll_events)
		return -EINVAL;

	req->poll_remove.addr = READ_ONCE(sqe->addr);
	return 0;
}

/*
 * Find a running poll command that matches one specified in sqe->addr,
 * and remove it if found.
 */
static int io_poll_remove(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ring_ctx *ctx = req->ctx;
	int ret;

	spin_lock_irq(&ctx->completion_lock);
	ret = io_poll_cancel(ctx, req->poll_remove.addr);
	spin_unlock_irq(&ctx->completion_lock);

	if (ret < 0)
		req_set_fail_links(req);
	io_req_complete(req, ret);
	return 0;
}

static int io_poll_wake(struct wait_queue_entry *wait, unsigned mode, int sync,
			void *key)
{
	struct io_kiocb *req = wait->private;
	struct io_poll_iocb *poll = &req->poll;

	return __io_async_wake(req, poll, key_to_poll(key), io_poll_task_func);
}

static void io_poll_queue_proc(struct file *file, struct wait_queue_head *head,
			       struct poll_table_struct *p)
{
	struct io_poll_table *pt = container_of(p, struct io_poll_table, pt);

	__io_queue_proc(&pt->req->poll, pt, head, (struct io_poll_iocb **) &pt->req->async_data);
}

static int io_poll_add_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_poll_iocb *poll = &req->poll;
	u32 events;

	if (unlikely(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;
	if (sqe->addr || sqe->ioprio || sqe->off || sqe->len || sqe->buf_index)
		return -EINVAL;

	events = READ_ONCE(sqe->poll32_events);
#ifdef __BIG_ENDIAN
	events = swahw32(events);
#endif
	poll->events = demangle_poll(events) | EPOLLERR | EPOLLHUP |
		       (events & EPOLLEXCLUSIVE);
	return 0;
}

static int io_poll_add(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_poll_iocb *poll = &req->poll;
	struct io_ring_ctx *ctx = req->ctx;
	struct io_poll_table ipt;
	__poll_t mask;

	ipt.pt._qproc = io_poll_queue_proc;

	mask = __io_arm_poll_handler(req, &req->poll, &ipt, poll->events,
					io_poll_wake);

	if (mask) { /* no async, we'd stolen it */
		ipt.error = 0;
		io_poll_complete(req, mask, 0);
	}
	spin_unlock_irq(&ctx->completion_lock);

	if (mask) {
		io_cqring_ev_posted(ctx);
		io_put_req(req);
	}
	return ipt.error;
}

static enum hrtimer_restart io_timeout_fn(struct hrtimer *timer)
{
	struct io_timeout_data *data = container_of(timer,
						struct io_timeout_data, timer);
	struct io_kiocb *req = data->req;
	struct io_ring_ctx *ctx = req->ctx;
	unsigned long flags;

	spin_lock_irqsave(&ctx->completion_lock, flags);
	list_del_init(&req->timeout.list);
	atomic_set(&req->ctx->cq_timeouts,
		atomic_read(&req->ctx->cq_timeouts) + 1);

	io_cqring_fill_event(req, -ETIME);
	io_commit_cqring(ctx);
	spin_unlock_irqrestore(&ctx->completion_lock, flags);

	io_cqring_ev_posted(ctx);
	req_set_fail_links(req);
	io_put_req(req);
	return HRTIMER_NORESTART;
}

static struct io_kiocb *io_timeout_extract(struct io_ring_ctx *ctx,
					   __u64 user_data)
{
	struct io_timeout_data *io;
	struct io_kiocb *req;
	int ret = -ENOENT;

	list_for_each_entry(req, &ctx->timeout_list, timeout.list) {
		if (user_data == req->user_data) {
			ret = 0;
			break;
		}
	}

	if (ret == -ENOENT)
		return ERR_PTR(ret);

	io = req->async_data;
	ret = hrtimer_try_to_cancel(&io->timer);
	if (ret == -1)
		return ERR_PTR(-EALREADY);
	list_del_init(&req->timeout.list);
	return req;
}

static int io_timeout_cancel(struct io_ring_ctx *ctx, __u64 user_data)
{
	struct io_kiocb *req = io_timeout_extract(ctx, user_data);

	if (IS_ERR(req))
		return PTR_ERR(req);

	req_set_fail_links(req);
	io_cqring_fill_event(req, -ECANCELED);
	io_put_req_deferred(req, 1);
	return 0;
}

static int io_timeout_update(struct io_ring_ctx *ctx, __u64 user_data,
			     struct timespec64 *ts, enum hrtimer_mode mode)
{
	struct io_kiocb *req = io_timeout_extract(ctx, user_data);
	struct io_timeout_data *data;

	if (IS_ERR(req))
		return PTR_ERR(req);

	req->timeout.off = 0; /* noseq */
	data = req->async_data;
	list_add_tail(&req->timeout.list, &ctx->timeout_list);
	hrtimer_init(&data->timer, CLOCK_MONOTONIC, mode);
	data->timer.function = io_timeout_fn;
	hrtimer_start(&data->timer, timespec64_to_ktime(*ts), mode);
	return 0;
}

static int io_timeout_remove_prep(struct io_kiocb *req,
				  const struct io_uring_sqe *sqe)
{
	struct io_timeout_rem *tr = &req->timeout_rem;

	if (unlikely(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;
	if (unlikely(req->flags & (REQ_F_FIXED_FILE | REQ_F_BUFFER_SELECT)))
		return -EINVAL;
	if (sqe->ioprio || sqe->buf_index || sqe->len)
		return -EINVAL;

	tr->addr = READ_ONCE(sqe->addr);
	tr->flags = READ_ONCE(sqe->timeout_flags);
	if (tr->flags & IORING_TIMEOUT_UPDATE) {
		if (tr->flags & ~(IORING_TIMEOUT_UPDATE|IORING_TIMEOUT_ABS))
			return -EINVAL;
		if (get_timespec64(&tr->ts, u64_to_user_ptr(sqe->addr2)))
			return -EFAULT;
	} else if (tr->flags) {
		/* timeout removal doesn't support flags */
		return -EINVAL;
	}

	return 0;
}

static inline enum hrtimer_mode io_translate_timeout_mode(unsigned int flags)
{
	return (flags & IORING_TIMEOUT_ABS) ? HRTIMER_MODE_ABS
					    : HRTIMER_MODE_REL;
}

/*
 * Remove or update an existing timeout command
 */
static int io_timeout_remove(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_timeout_rem *tr = &req->timeout_rem;
	struct io_ring_ctx *ctx = req->ctx;
	int ret;

	spin_lock_irq(&ctx->completion_lock);
	if (!(req->timeout_rem.flags & IORING_TIMEOUT_UPDATE))
		ret = io_timeout_cancel(ctx, tr->addr);
	else
		ret = io_timeout_update(ctx, tr->addr, &tr->ts,
					io_translate_timeout_mode(tr->flags));

	io_cqring_fill_event(req, ret);
	io_commit_cqring(ctx);
	spin_unlock_irq(&ctx->completion_lock);
	io_cqring_ev_posted(ctx);
	if (ret < 0)
		req_set_fail_links(req);
	io_put_req(req);
	return 0;
}

static int io_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe,
			   bool is_timeout_link)
{
	struct io_timeout_data *data;
	unsigned flags;
	u32 off = READ_ONCE(sqe->off);

	if (unlikely(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;
	if (sqe->ioprio || sqe->buf_index || sqe->len != 1)
		return -EINVAL;
	if (off && is_timeout_link)
		return -EINVAL;
	flags = READ_ONCE(sqe->timeout_flags);
	if (flags & ~IORING_TIMEOUT_ABS)
		return -EINVAL;

	req->timeout.off = off;

	if (!req->async_data && io_alloc_async_data(req))
		return -ENOMEM;

	data = req->async_data;
	data->req = req;

	if (get_timespec64(&data->ts, u64_to_user_ptr(sqe->addr)))
		return -EFAULT;

	data->mode = io_translate_timeout_mode(flags);
	hrtimer_init(&data->timer, CLOCK_MONOTONIC, data->mode);
	return 0;
}

static int io_timeout(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_timeout_data *data = req->async_data;
	struct list_head *entry;
	u32 tail, off = req->timeout.off;

	spin_lock_irq(&ctx->completion_lock);

	/*
	 * sqe->off holds how many events that need to occur for this
	 * timeout event to be satisfied. If it isn't set, then this is
	 * a pure timeout request, sequence isn't used.
	 */
	if (io_is_timeout_noseq(req)) {
		entry = ctx->timeout_list.prev;
		goto add;
	}

	tail = ctx->cached_cq_tail - atomic_read(&ctx->cq_timeouts);
	req->timeout.target_seq = tail + off;

	/* Update the last seq here in case io_flush_timeouts() hasn't.
	 * This is safe because ->completion_lock is held, and submissions
	 * and completions are never mixed in the same ->completion_lock section.
	 */
	ctx->cq_last_tm_flush = tail;

	/*
	 * Insertion sort, ensuring the first entry in the list is always
	 * the one we need first.
	 */
	list_for_each_prev(entry, &ctx->timeout_list) {
		struct io_kiocb *nxt = list_entry(entry, struct io_kiocb,
						  timeout.list);

		if (io_is_timeout_noseq(nxt))
			continue;
		/* nxt.seq is behind @tail, otherwise would've been completed */
		if (off >= nxt->timeout.target_seq - tail)
			break;
	}
add:
	list_add(&req->timeout.list, entry);
	data->timer.function = io_timeout_fn;
	hrtimer_start(&data->timer, timespec64_to_ktime(data->ts), data->mode);
	spin_unlock_irq(&ctx->completion_lock);
	return 0;
}

static bool io_cancel_cb(struct io_wq_work *work, void *data)
{
	struct io_kiocb *req = container_of(work, struct io_kiocb, work);

	return req->user_data == (unsigned long) data;
}

static int io_async_cancel_one(struct io_ring_ctx *ctx, void *sqe_addr)
{
	enum io_wq_cancel cancel_ret;
	int ret = 0;

	cancel_ret = io_wq_cancel_cb(ctx->io_wq, io_cancel_cb, sqe_addr, false);
	switch (cancel_ret) {
	case IO_WQ_CANCEL_OK:
		ret = 0;
		break;
	case IO_WQ_CANCEL_RUNNING:
		ret = -EALREADY;
		break;
	case IO_WQ_CANCEL_NOTFOUND:
		ret = -ENOENT;
		break;
	}

	return ret;
}

static void io_async_find_and_cancel(struct io_ring_ctx *ctx,
				     struct io_kiocb *req, __u64 sqe_addr,
				     int success_ret)
{
	unsigned long flags;
	int ret;

	ret = io_async_cancel_one(ctx, (void *) (unsigned long) sqe_addr);
	if (ret != -ENOENT) {
		spin_lock_irqsave(&ctx->completion_lock, flags);
		goto done;
	}

	spin_lock_irqsave(&ctx->completion_lock, flags);
	ret = io_timeout_cancel(ctx, sqe_addr);
	if (ret != -ENOENT)
		goto done;
	ret = io_poll_cancel(ctx, sqe_addr);
done:
	if (!ret)
		ret = success_ret;
	io_cqring_fill_event(req, ret);
	io_commit_cqring(ctx);
	spin_unlock_irqrestore(&ctx->completion_lock, flags);
	io_cqring_ev_posted(ctx);

	if (ret < 0)
		req_set_fail_links(req);
	io_put_req(req);
}

static int io_async_cancel_prep(struct io_kiocb *req,
				const struct io_uring_sqe *sqe)
{
	if (unlikely(req->ctx->flags & IORING_SETUP_IOPOLL))
		return -EINVAL;
	if (unlikely(req->flags & (REQ_F_FIXED_FILE | REQ_F_BUFFER_SELECT)))
		return -EINVAL;
	if (sqe->ioprio || sqe->off || sqe->len || sqe->cancel_flags)
		return -EINVAL;

	req->cancel.addr = READ_ONCE(sqe->addr);
	return 0;
}

static int io_async_cancel(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ring_ctx *ctx = req->ctx;

	io_async_find_and_cancel(ctx, req, req->cancel.addr, 0);
	return 0;
}

static int io_rsrc_update_prep(struct io_kiocb *req,
				const struct io_uring_sqe *sqe)
{
	if (unlikely(req->ctx->flags & IORING_SETUP_SQPOLL))
		return -EINVAL;
	if (unlikely(req->flags & (REQ_F_FIXED_FILE | REQ_F_BUFFER_SELECT)))
		return -EINVAL;
	if (sqe->ioprio || sqe->rw_flags)
		return -EINVAL;

	req->rsrc_update.offset = READ_ONCE(sqe->off);
	req->rsrc_update.nr_args = READ_ONCE(sqe->len);
	if (!req->rsrc_update.nr_args)
		return -EINVAL;
	req->rsrc_update.arg = READ_ONCE(sqe->addr);
	return 0;
}

static int io_files_update(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_uring_rsrc_update up;
	int ret;

	if (issue_flags & IO_URING_F_NONBLOCK)
		return -EAGAIN;

	up.offset = req->rsrc_update.offset;
	up.data = req->rsrc_update.arg;

	mutex_lock(&ctx->uring_lock);
	ret = __io_sqe_files_update(ctx, &up, req->rsrc_update.nr_args);
	mutex_unlock(&ctx->uring_lock);

	if (ret < 0)
		req_set_fail_links(req);
	__io_req_complete(req, issue_flags, ret, 0);
	return 0;
}

static int io_req_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	switch (req->opcode) {
	case IORING_OP_NOP:
		return 0;
	case IORING_OP_READV:
	case IORING_OP_READ_FIXED:
	case IORING_OP_READ:
		return io_read_prep(req, sqe);
	case IORING_OP_WRITEV:
	case IORING_OP_WRITE_FIXED:
	case IORING_OP_WRITE:
		return io_write_prep(req, sqe);
	case IORING_OP_POLL_ADD:
		return io_poll_add_prep(req, sqe);
	case IORING_OP_POLL_REMOVE:
		return io_poll_remove_prep(req, sqe);
	case IORING_OP_FSYNC:
		return io_prep_fsync(req, sqe);
	case IORING_OP_SYNC_FILE_RANGE:
		return io_prep_sfr(req, sqe);
	case IORING_OP_SENDMSG:
	case IORING_OP_SEND:
		return io_sendmsg_prep(req, sqe);
	case IORING_OP_RECVMSG:
	case IORING_OP_RECV:
		return io_recvmsg_prep(req, sqe);
	case IORING_OP_CONNECT:
		return io_connect_prep(req, sqe);
	case IORING_OP_TIMEOUT:
		return io_timeout_prep(req, sqe, false);
	case IORING_OP_TIMEOUT_REMOVE:
		return io_timeout_remove_prep(req, sqe);
	case IORING_OP_ASYNC_CANCEL:
		return io_async_cancel_prep(req, sqe);
	case IORING_OP_LINK_TIMEOUT:
		return io_timeout_prep(req, sqe, true);
	case IORING_OP_ACCEPT:
		return io_accept_prep(req, sqe);
	case IORING_OP_FALLOCATE:
		return io_fallocate_prep(req, sqe);
	case IORING_OP_OPENAT:
		return io_openat_prep(req, sqe);
	case IORING_OP_CLOSE:
		return io_close_prep(req, sqe);
	case IORING_OP_FILES_UPDATE:
		return io_rsrc_update_prep(req, sqe);
	case IORING_OP_STATX:
		return io_statx_prep(req, sqe);
	case IORING_OP_FADVISE:
		return io_fadvise_prep(req, sqe);
	case IORING_OP_MADVISE:
		return io_madvise_prep(req, sqe);
	case IORING_OP_OPENAT2:
		return io_openat2_prep(req, sqe);
	case IORING_OP_EPOLL_CTL:
		return io_epoll_ctl_prep(req, sqe);
	case IORING_OP_SPLICE:
		return io_splice_prep(req, sqe);
	case IORING_OP_PROVIDE_BUFFERS:
		return io_provide_buffers_prep(req, sqe);
	case IORING_OP_REMOVE_BUFFERS:
		return io_remove_buffers_prep(req, sqe);
	case IORING_OP_TEE:
		return io_tee_prep(req, sqe);
	case IORING_OP_SHUTDOWN:
		return io_shutdown_prep(req, sqe);
	case IORING_OP_RENAMEAT:
		return io_renameat_prep(req, sqe);
	case IORING_OP_UNLINKAT:
		return io_unlinkat_prep(req, sqe);
	}

	printk_once(KERN_WARNING "io_uring: unhandled opcode %d\n",
			req->opcode);
	return-EINVAL;
}

static int io_req_defer_prep(struct io_kiocb *req,
			     const struct io_uring_sqe *sqe)
{
	if (!sqe)
		return 0;
	if (io_alloc_async_data(req))
		return -EAGAIN;
	return io_req_prep(req, sqe);
}

static u32 io_get_sequence(struct io_kiocb *req)
{
	struct io_kiocb *pos;
	struct io_ring_ctx *ctx = req->ctx;
	u32 total_submitted, nr_reqs = 0;

	io_for_each_link(pos, req)
		nr_reqs++;

	total_submitted = ctx->cached_sq_head - ctx->cached_sq_dropped;
	return total_submitted - nr_reqs;
}

static int io_req_defer(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_defer_entry *de;
	int ret;
	u32 seq;

	/* Still need defer if there is pending req in defer list. */
	if (likely(list_empty_careful(&ctx->defer_list) &&
		!(req->flags & REQ_F_IO_DRAIN)))
		return 0;

	seq = io_get_sequence(req);
	/* Still a chance to pass the sequence check */
	if (!req_need_defer(req, seq) && list_empty_careful(&ctx->defer_list))
		return 0;

	if (!req->async_data) {
		ret = io_req_defer_prep(req, sqe);
		if (ret)
			return ret;
	}
	io_prep_async_link(req);
	de = kmalloc(sizeof(*de), GFP_KERNEL);
	if (!de)
		return -ENOMEM;

	spin_lock_irq(&ctx->completion_lock);
	if (!req_need_defer(req, seq) && list_empty(&ctx->defer_list)) {
		spin_unlock_irq(&ctx->completion_lock);
		kfree(de);
		io_queue_async_work(req);
		return -EIOCBQUEUED;
	}

	trace_io_uring_defer(ctx, req, req->user_data);
	de->req = req;
	de->seq = seq;
	list_add_tail(&de->list, &ctx->defer_list);
	spin_unlock_irq(&ctx->completion_lock);
	return -EIOCBQUEUED;
}

static void __io_clean_op(struct io_kiocb *req)
{
	if (req->flags & REQ_F_BUFFER_SELECTED) {
		switch (req->opcode) {
		case IORING_OP_READV:
		case IORING_OP_READ_FIXED:
		case IORING_OP_READ:
			kfree((void *)(unsigned long)req->rw.addr);
			break;
		case IORING_OP_RECVMSG:
		case IORING_OP_RECV:
			kfree(req->sr_msg.kbuf);
			break;
		}
		req->flags &= ~REQ_F_BUFFER_SELECTED;
	}

	if (req->flags & REQ_F_NEED_CLEANUP) {
		switch (req->opcode) {
		case IORING_OP_READV:
		case IORING_OP_READ_FIXED:
		case IORING_OP_READ:
		case IORING_OP_WRITEV:
		case IORING_OP_WRITE_FIXED:
		case IORING_OP_WRITE: {
			struct io_async_rw *io = req->async_data;
			if (io->free_iovec)
				kfree(io->free_iovec);
			break;
			}
		case IORING_OP_RECVMSG:
		case IORING_OP_SENDMSG: {
			struct io_async_msghdr *io = req->async_data;

			kfree(io->free_iov);
			break;
			}
		case IORING_OP_SPLICE:
		case IORING_OP_TEE:
			io_put_file(req, req->splice.file_in,
				    (req->splice.flags & SPLICE_F_FD_IN_FIXED));
			break;
		case IORING_OP_OPENAT:
		case IORING_OP_OPENAT2:
			if (req->open.filename)
				putname(req->open.filename);
			break;
		case IORING_OP_RENAMEAT:
			putname(req->rename.oldpath);
			putname(req->rename.newpath);
			break;
		case IORING_OP_UNLINKAT:
			putname(req->unlink.filename);
			break;
		}
		req->flags &= ~REQ_F_NEED_CLEANUP;
	}
}

static int io_issue_sqe(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ring_ctx *ctx = req->ctx;
	int ret;

	switch (req->opcode) {
	case IORING_OP_NOP:
		ret = io_nop(req, issue_flags);
		break;
	case IORING_OP_READV:
	case IORING_OP_READ_FIXED:
	case IORING_OP_READ:
		ret = io_read(req, issue_flags);
		break;
	case IORING_OP_WRITEV:
	case IORING_OP_WRITE_FIXED:
	case IORING_OP_WRITE:
		ret = io_write(req, issue_flags);
		break;
	case IORING_OP_FSYNC:
		ret = io_fsync(req, issue_flags);
		break;
	case IORING_OP_POLL_ADD:
		ret = io_poll_add(req, issue_flags);
		break;
	case IORING_OP_POLL_REMOVE:
		ret = io_poll_remove(req, issue_flags);
		break;
	case IORING_OP_SYNC_FILE_RANGE:
		ret = io_sync_file_range(req, issue_flags);
		break;
	case IORING_OP_SENDMSG:
		ret = io_sendmsg(req, issue_flags);
		break;
	case IORING_OP_SEND:
		ret = io_send(req, issue_flags);
		break;
	case IORING_OP_RECVMSG:
		ret = io_recvmsg(req, issue_flags);
		break;
	case IORING_OP_RECV:
		ret = io_recv(req, issue_flags);
		break;
	case IORING_OP_TIMEOUT:
		ret = io_timeout(req, issue_flags);
		break;
	case IORING_OP_TIMEOUT_REMOVE:
		ret = io_timeout_remove(req, issue_flags);
		break;
	case IORING_OP_ACCEPT:
		ret = io_accept(req, issue_flags);
		break;
	case IORING_OP_CONNECT:
		ret = io_connect(req, issue_flags);
		break;
	case IORING_OP_ASYNC_CANCEL:
		ret = io_async_cancel(req, issue_flags);
		break;
	case IORING_OP_FALLOCATE:
		ret = io_fallocate(req, issue_flags);
		break;
	case IORING_OP_OPENAT:
		ret = io_openat(req, issue_flags);
		break;
	case IORING_OP_CLOSE:
		ret = io_close(req, issue_flags);
		break;
	case IORING_OP_FILES_UPDATE:
		ret = io_files_update(req, issue_flags);
		break;
	case IORING_OP_STATX:
		ret = io_statx(req, issue_flags);
		break;
	case IORING_OP_FADVISE:
		ret = io_fadvise(req, issue_flags);
		break;
	case IORING_OP_MADVISE:
		ret = io_madvise(req, issue_flags);
		break;
	case IORING_OP_OPENAT2:
		ret = io_openat2(req, issue_flags);
		break;
	case IORING_OP_EPOLL_CTL:
		ret = io_epoll_ctl(req, issue_flags);
		break;
	case IORING_OP_SPLICE:
		ret = io_splice(req, issue_flags);
		break;
	case IORING_OP_PROVIDE_BUFFERS:
		ret = io_provide_buffers(req, issue_flags);
		break;
	case IORING_OP_REMOVE_BUFFERS:
		ret = io_remove_buffers(req, issue_flags);
		break;
	case IORING_OP_TEE:
		ret = io_tee(req, issue_flags);
		break;
	case IORING_OP_SHUTDOWN:
		ret = io_shutdown(req, issue_flags);
		break;
	case IORING_OP_RENAMEAT:
		ret = io_renameat(req, issue_flags);
		break;
	case IORING_OP_UNLINKAT:
		ret = io_unlinkat(req, issue_flags);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret)
		return ret;

	/* If the op doesn't have a file, we're not polling for it */
	if ((ctx->flags & IORING_SETUP_IOPOLL) && req->file) {
		const bool in_async = io_wq_current_is_worker();

		/* workqueue context doesn't hold uring_lock, grab it now */
		if (in_async)
			mutex_lock(&ctx->uring_lock);

		io_iopoll_req_issued(req, in_async);

		if (in_async)
			mutex_unlock(&ctx->uring_lock);
	}

	return 0;
}

static void io_wq_submit_work(struct io_wq_work *work)
{
	struct io_kiocb *req = container_of(work, struct io_kiocb, work);
	struct io_kiocb *timeout;
	int ret = 0;

	timeout = io_prep_linked_timeout(req);
	if (timeout)
		io_queue_linked_timeout(timeout);

	if (work->flags & IO_WQ_WORK_CANCEL)
		ret = -ECANCELED;

	if (!ret) {
		do {
			ret = io_issue_sqe(req, 0);
			/*
			 * We can get EAGAIN for polled IO even though we're
			 * forcing a sync submission from here, since we can't
			 * wait for request slots on the block side.
			 */
			if (ret != -EAGAIN)
				break;
			cond_resched();
		} while (1);
	}

	if (ret) {
		struct io_ring_ctx *lock_ctx = NULL;

		if (req->ctx->flags & IORING_SETUP_IOPOLL)
			lock_ctx = req->ctx;

		/*
		 * io_iopoll_complete() does not hold completion_lock to
		 * complete polled io, so here for polled io, we can not call
		 * io_req_complete() directly, otherwise there maybe concurrent
		 * access to cqring, defer_list, etc, which is not safe. Given
		 * that io_iopoll_complete() is always called under uring_lock,
		 * so here for polled io, we also get uring_lock to complete
		 * it.
		 */
		if (lock_ctx)
			mutex_lock(&lock_ctx->uring_lock);

		req_set_fail_links(req);
		io_req_complete(req, ret);

		if (lock_ctx)
			mutex_unlock(&lock_ctx->uring_lock);
	}
}

static inline struct file *io_file_from_index(struct io_ring_ctx *ctx,
					      int index)
{
	struct fixed_rsrc_table *table;

	table = &ctx->file_data->table[index >> IORING_FILE_TABLE_SHIFT];
	return table->files[index & IORING_FILE_TABLE_MASK];
}

static struct file *io_file_get(struct io_submit_state *state,
				struct io_kiocb *req, int fd, bool fixed)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct file *file;

	if (fixed) {
		if (unlikely((unsigned int)fd >= ctx->nr_user_files))
			return NULL;
		fd = array_index_nospec(fd, ctx->nr_user_files);
		file = io_file_from_index(ctx, fd);
		io_set_resource_node(req);
	} else {
		trace_io_uring_file_get(ctx, fd);
		file = __io_file_get(state, fd);
	}

	if (file && unlikely(file->f_op == &io_uring_fops))
		io_req_track_inflight(req);
	return file;
}

static enum hrtimer_restart io_link_timeout_fn(struct hrtimer *timer)
{
	struct io_timeout_data *data = container_of(timer,
						struct io_timeout_data, timer);
	struct io_kiocb *prev, *req = data->req;
	struct io_ring_ctx *ctx = req->ctx;
	unsigned long flags;

	spin_lock_irqsave(&ctx->completion_lock, flags);
	prev = req->timeout.head;
	req->timeout.head = NULL;

	/*
	 * We don't expect the list to be empty, that will only happen if we
	 * race with the completion of the linked work.
	 */
	if (prev && refcount_inc_not_zero(&prev->refs))
		io_remove_next_linked(prev);
	else
		prev = NULL;
	spin_unlock_irqrestore(&ctx->completion_lock, flags);

	if (prev) {
		req_set_fail_links(prev);
		io_async_find_and_cancel(ctx, req, prev->user_data, -ETIME);
		io_put_req_deferred(prev, 1);
	} else {
		io_req_complete_post(req, -ETIME, 0);
		io_put_req_deferred(req, 1);
	}
	return HRTIMER_NORESTART;
}

static void __io_queue_linked_timeout(struct io_kiocb *req)
{
	/*
	 * If the back reference is NULL, then our linked request finished
	 * before we got a chance to setup the timer
	 */
	if (req->timeout.head) {
		struct io_timeout_data *data = req->async_data;

		data->timer.function = io_link_timeout_fn;
		hrtimer_start(&data->timer, timespec64_to_ktime(data->ts),
				data->mode);
	}
}

static void io_queue_linked_timeout(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;

	spin_lock_irq(&ctx->completion_lock);
	__io_queue_linked_timeout(req);
	spin_unlock_irq(&ctx->completion_lock);

	/* drop submission reference */
	io_put_req(req);
}

static struct io_kiocb *io_prep_linked_timeout(struct io_kiocb *req)
{
	struct io_kiocb *nxt = req->link;

	if (!nxt || (req->flags & REQ_F_LINK_TIMEOUT) ||
	    nxt->opcode != IORING_OP_LINK_TIMEOUT)
		return NULL;

	nxt->timeout.head = req;
	nxt->flags |= REQ_F_LTIMEOUT_ACTIVE;
	req->flags |= REQ_F_LINK_TIMEOUT;
	return nxt;
}

static void __io_queue_sqe(struct io_kiocb *req)
{
	struct io_kiocb *linked_timeout = io_prep_linked_timeout(req);
	const struct cred *old_creds = NULL;
	int ret;

	if ((req->flags & REQ_F_WORK_INITIALIZED) &&
	    (req->work.flags & IO_WQ_WORK_CREDS) &&
	    req->work.identity->creds != current_cred())
		old_creds = override_creds(req->work.identity->creds);

	ret = io_issue_sqe(req, IO_URING_F_NONBLOCK|IO_URING_F_COMPLETE_DEFER);

	if (old_creds)
		revert_creds(old_creds);

	/*
	 * We async punt it if the file wasn't marked NOWAIT, or if the file
	 * doesn't support non-blocking read/write attempts
	 */
	if (ret == -EAGAIN && !(req->flags & REQ_F_NOWAIT)) {
		if (!io_arm_poll_handler(req)) {
			/*
			 * Queued up for async execution, worker will release
			 * submit reference when the iocb is actually submitted.
			 */
			io_queue_async_work(req);
		}
	} else if (likely(!ret)) {
		/* drop submission reference */
		if (req->flags & REQ_F_COMPLETE_INLINE) {
			struct io_ring_ctx *ctx = req->ctx;
			struct io_comp_state *cs = &ctx->submit_state.comp;

			cs->reqs[cs->nr++] = req;
			if (cs->nr == ARRAY_SIZE(cs->reqs))
				io_submit_flush_completions(cs, ctx);
		} else {
			io_put_req(req);
		}
	} else {
		req_set_fail_links(req);
		io_put_req(req);
		io_req_complete(req, ret);
	}
	if (linked_timeout)
		io_queue_linked_timeout(linked_timeout);
}

static void io_queue_sqe(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	int ret;

	ret = io_req_defer(req, sqe);
	if (ret) {
		if (ret != -EIOCBQUEUED) {
fail_req:
			req_set_fail_links(req);
			io_put_req(req);
			io_req_complete(req, ret);
		}
	} else if (req->flags & REQ_F_FORCE_ASYNC) {
		if (!req->async_data) {
			ret = io_req_defer_prep(req, sqe);
			if (unlikely(ret))
				goto fail_req;
		}
		io_queue_async_work(req);
	} else {
		if (sqe) {
			ret = io_req_prep(req, sqe);
			if (unlikely(ret))
				goto fail_req;
		}
		__io_queue_sqe(req);
	}
}

static inline void io_queue_link_head(struct io_kiocb *req)
{
	if (unlikely(req->flags & REQ_F_FAIL_LINK)) {
		io_put_req(req);
		io_req_complete(req, -ECANCELED);
	} else
		io_queue_sqe(req, NULL);
}

struct io_submit_link {
	struct io_kiocb *head;
	struct io_kiocb *last;
};

static int io_submit_sqe(struct io_kiocb *req, const struct io_uring_sqe *sqe,
			 struct io_submit_link *link)
{
	struct io_ring_ctx *ctx = req->ctx;
	int ret;

	/*
	 * If we already have a head request, queue this one for async
	 * submittal once the head completes. If we don't have a head but
	 * IOSQE_IO_LINK is set in the sqe, start a new head. This one will be
	 * submitted sync once the chain is complete. If none of those
	 * conditions are true (normal request), then just queue it.
	 */
	if (link->head) {
		struct io_kiocb *head = link->head;

		/*
		 * Taking sequential execution of a link, draining both sides
		 * of the link also fullfils IOSQE_IO_DRAIN semantics for all
		 * requests in the link. So, it drains the head and the
		 * next after the link request. The last one is done via
		 * drain_next flag to persist the effect across calls.
		 */
		if (req->flags & REQ_F_IO_DRAIN) {
			head->flags |= REQ_F_IO_DRAIN;
			ctx->drain_next = 1;
		}
		ret = io_req_defer_prep(req, sqe);
		if (unlikely(ret)) {
			/* fail even hard links since we don't submit */
			head->flags |= REQ_F_FAIL_LINK;
			return ret;
		}
		trace_io_uring_link(ctx, req, head);
		link->last->link = req;
		link->last = req;

		/* last request of a link, enqueue the link */
		if (!(req->flags & (REQ_F_LINK | REQ_F_HARDLINK))) {
			io_queue_link_head(head);
			link->head = NULL;
		}
	} else {
		if (unlikely(ctx->drain_next)) {
			req->flags |= REQ_F_IO_DRAIN;
			ctx->drain_next = 0;
		}
		if (req->flags & (REQ_F_LINK | REQ_F_HARDLINK)) {
			ret = io_req_defer_prep(req, sqe);
			if (unlikely(ret))
				req->flags |= REQ_F_FAIL_LINK;
			link->head = req;
			link->last = req;
		} else {
			io_queue_sqe(req, sqe);
		}
	}

	return 0;
}

/*
 * Batched submission is done, ensure local IO is flushed out.
 */
static void io_submit_state_end(struct io_submit_state *state,
				struct io_ring_ctx *ctx)
{
	if (state->comp.nr)
		io_submit_flush_completions(&state->comp, ctx);
	if (state->plug_started)
		blk_finish_plug(&state->plug);
	io_state_file_put(state);
}

/*
 * Start submission side cache.
 */
static void io_submit_state_start(struct io_submit_state *state,
				  unsigned int max_ios)
{
	state->plug_started = false;
	state->ios_left = max_ios;
}

static void io_commit_sqring(struct io_ring_ctx *ctx)
{
	struct io_rings *rings = ctx->rings;

	/*
	 * Ensure any loads from the SQEs are done at this point,
	 * since once we write the new head, the application could
	 * write new data to them.
	 */
	smp_store_release(&rings->sq.head, ctx->cached_sq_head);
}

/*
 * Fetch an sqe, if one is available. Note that sqe_ptr will point to memory
 * that is mapped by userspace. This means that care needs to be taken to
 * ensure that reads are stable, as we cannot rely on userspace always
 * being a good citizen. If members of the sqe are validated and then later
 * used, it's important that those reads are done through READ_ONCE() to
 * prevent a re-load down the line.
 */
static const struct io_uring_sqe *io_get_sqe(struct io_ring_ctx *ctx)
{
	u32 *sq_array = ctx->sq_array;
	unsigned head;

	/*
	 * The cached sq head (or cq tail) serves two purposes:
	 *
	 * 1) allows us to batch the cost of updating the user visible
	 *    head updates.
	 * 2) allows the kernel side to track the head on its own, even
	 *    though the application is the one updating it.
	 */
	head = READ_ONCE(sq_array[ctx->cached_sq_head++ & ctx->sq_mask]);
	if (likely(head < ctx->sq_entries))
		return &ctx->sq_sqes[head];

	/* drop invalid entries */
	ctx->cached_sq_dropped++;
	WRITE_ONCE(ctx->rings->sq_dropped, ctx->cached_sq_dropped);
	return NULL;
}

/*
 * Check SQE restrictions (opcode and flags).
 *
 * Returns 'true' if SQE is allowed, 'false' otherwise.
 */
static inline bool io_check_restriction(struct io_ring_ctx *ctx,
					struct io_kiocb *req,
					unsigned int sqe_flags)
{
	if (!ctx->restricted)
		return true;

	if (!test_bit(req->opcode, ctx->restrictions.sqe_op))
		return false;

	if ((sqe_flags & ctx->restrictions.sqe_flags_required) !=
	    ctx->restrictions.sqe_flags_required)
		return false;

	if (sqe_flags & ~(ctx->restrictions.sqe_flags_allowed |
			  ctx->restrictions.sqe_flags_required))
		return false;

	return true;
}

#define SQE_VALID_FLAGS	(IOSQE_FIXED_FILE|IOSQE_IO_DRAIN|IOSQE_IO_LINK|	\
				IOSQE_IO_HARDLINK | IOSQE_ASYNC | \
				IOSQE_BUFFER_SELECT)

static int io_init_req(struct io_ring_ctx *ctx, struct io_kiocb *req,
		       const struct io_uring_sqe *sqe)
{
	struct io_submit_state *state;
	unsigned int sqe_flags;
	int id, ret = 0;

	req->opcode = READ_ONCE(sqe->opcode);
	/* same numerical values with corresponding REQ_F_*, safe to copy */
	req->flags = sqe_flags = READ_ONCE(sqe->flags);
	req->user_data = READ_ONCE(sqe->user_data);
	req->async_data = NULL;
	req->file = NULL;
	req->ctx = ctx;
	req->link = NULL;
	req->fixed_rsrc_refs = NULL;
	/* one is dropped after submission, the other at completion */
	refcount_set(&req->refs, 2);
	req->task = current;
	req->result = 0;

	/* enforce forwards compatibility on users */
	if (unlikely(sqe_flags & ~SQE_VALID_FLAGS))
		return -EINVAL;

	if (unlikely(req->opcode >= IORING_OP_LAST))
		return -EINVAL;

	if (unlikely(io_sq_thread_acquire_mm_files(ctx, req)))
		return -EFAULT;

	if (unlikely(!io_check_restriction(ctx, req, sqe_flags)))
		return -EACCES;

	if ((sqe_flags & IOSQE_BUFFER_SELECT) &&
	    !io_op_defs[req->opcode].buffer_select)
		return -EOPNOTSUPP;

	id = READ_ONCE(sqe->personality);
	if (id) {
		struct io_identity *iod;

		iod = idr_find(&ctx->personality_idr, id);
		if (unlikely(!iod))
			return -EINVAL;
		refcount_inc(&iod->count);

		__io_req_init_async(req);
		get_cred(iod->creds);
		req->work.identity = iod;
		req->work.flags |= IO_WQ_WORK_CREDS;
	}

	state = &ctx->submit_state;

	/*
	 * Plug now if we have more than 1 IO left after this, and the target
	 * is potentially a read/write to block based storage.
	 */
	if (!state->plug_started && state->ios_left > 1 &&
	    io_op_defs[req->opcode].plug) {
		blk_start_plug(&state->plug);
		state->plug_started = true;
	}

	if (io_op_defs[req->opcode].needs_file) {
		bool fixed = req->flags & REQ_F_FIXED_FILE;

		req->file = io_file_get(state, req, READ_ONCE(sqe->fd), fixed);
		if (unlikely(!req->file))
			ret = -EBADF;
	}

	state->ios_left--;
	return ret;
}

static int io_submit_sqes(struct io_ring_ctx *ctx, unsigned int nr)
{
	struct io_submit_link link;
	int i, submitted = 0;

	/* if we have a backlog and couldn't flush it all, return BUSY */
	if (test_bit(0, &ctx->sq_check_overflow)) {
		if (!__io_cqring_overflow_flush(ctx, false, NULL, NULL))
			return -EBUSY;
	}

	/* make sure SQ entry isn't read before tail */
	nr = min3(nr, ctx->sq_entries, io_sqring_entries(ctx));

	if (!percpu_ref_tryget_many(&ctx->refs, nr))
		return -EAGAIN;

	percpu_counter_add(&current->io_uring->inflight, nr);
	refcount_add(nr, &current->usage);

	io_submit_state_start(&ctx->submit_state, nr);
	link.head = NULL;

	for (i = 0; i < nr; i++) {
		const struct io_uring_sqe *sqe;
		struct io_kiocb *req;
		int err;

		req = io_alloc_req(ctx);
		if (unlikely(!req)) {
			if (!submitted)
				submitted = -EAGAIN;
			break;
		}
		sqe = io_get_sqe(ctx);
		if (unlikely(!sqe)) {
			kmem_cache_free(req_cachep, req);
			break;
		}
		/* will complete beyond this point, count as submitted */
		submitted++;

		err = io_init_req(ctx, req, sqe);
		if (unlikely(err)) {
fail_req:
			io_put_req(req);
			io_req_complete(req, err);
			break;
		}

		trace_io_uring_submit_sqe(ctx, req->opcode, req->user_data,
					true, ctx->flags & IORING_SETUP_SQPOLL);
		err = io_submit_sqe(req, sqe, &link);
		if (err)
			goto fail_req;
	}

	if (unlikely(submitted != nr)) {
		int ref_used = (submitted == -EAGAIN) ? 0 : submitted;
		struct io_uring_task *tctx = current->io_uring;
		int unused = nr - ref_used;

		percpu_ref_put_many(&ctx->refs, unused);
		percpu_counter_sub(&tctx->inflight, unused);
		put_task_struct_many(current, unused);
	}
	if (link.head)
		io_queue_link_head(link.head);
	io_submit_state_end(&ctx->submit_state, ctx);

	 /* Commit SQ ring head once we've consumed and submitted all SQEs */
	io_commit_sqring(ctx);

	return submitted;
}

static inline void io_ring_set_wakeup_flag(struct io_ring_ctx *ctx)
{
	/* Tell userspace we may need a wakeup call */
	spin_lock_irq(&ctx->completion_lock);
	ctx->rings->sq_flags |= IORING_SQ_NEED_WAKEUP;
	spin_unlock_irq(&ctx->completion_lock);
}

static inline void io_ring_clear_wakeup_flag(struct io_ring_ctx *ctx)
{
	spin_lock_irq(&ctx->completion_lock);
	ctx->rings->sq_flags &= ~IORING_SQ_NEED_WAKEUP;
	spin_unlock_irq(&ctx->completion_lock);
}

static int __io_sq_thread(struct io_ring_ctx *ctx, bool cap_entries)
{
	unsigned int to_submit;
	int ret = 0;

	to_submit = io_sqring_entries(ctx);
	/* if we're handling multiple rings, cap submit size for fairness */
	if (cap_entries && to_submit > 8)
		to_submit = 8;

	if (!list_empty(&ctx->iopoll_list) || to_submit) {
		unsigned nr_events = 0;

		mutex_lock(&ctx->uring_lock);
		if (!list_empty(&ctx->iopoll_list))
			io_do_iopoll(ctx, &nr_events, 0);

		if (to_submit && !ctx->sqo_dead &&
		    likely(!percpu_ref_is_dying(&ctx->refs)))
			ret = io_submit_sqes(ctx, to_submit);
		mutex_unlock(&ctx->uring_lock);
	}

	if (!io_sqring_full(ctx) && wq_has_sleeper(&ctx->sqo_sq_wait))
		wake_up(&ctx->sqo_sq_wait);

	return ret;
}

static void io_sqd_update_thread_idle(struct io_sq_data *sqd)
{
	struct io_ring_ctx *ctx;
	unsigned sq_thread_idle = 0;

	list_for_each_entry(ctx, &sqd->ctx_list, sqd_list) {
		if (sq_thread_idle < ctx->sq_thread_idle)
			sq_thread_idle = ctx->sq_thread_idle;
	}

	sqd->sq_thread_idle = sq_thread_idle;
}

static void io_sqd_init_new(struct io_sq_data *sqd)
{
	struct io_ring_ctx *ctx;

	while (!list_empty(&sqd->ctx_new_list)) {
		ctx = list_first_entry(&sqd->ctx_new_list, struct io_ring_ctx, sqd_list);
		list_move_tail(&ctx->sqd_list, &sqd->ctx_list);
		complete(&ctx->sq_thread_comp);
	}

	io_sqd_update_thread_idle(sqd);
}

static int io_sq_thread(void *data)
{
	struct cgroup_subsys_state *cur_css = NULL;
	struct files_struct *old_files = current->files;
	struct nsproxy *old_nsproxy = current->nsproxy;
	const struct cred *old_cred = NULL;
	struct io_sq_data *sqd = data;
	struct io_ring_ctx *ctx;
	unsigned long timeout = 0;
	DEFINE_WAIT(wait);

	task_lock(current);
	current->files = NULL;
	current->nsproxy = NULL;
	task_unlock(current);

	while (!kthread_should_stop()) {
		int ret;
		bool cap_entries, sqt_spin, needs_sched;

		/*
		 * Any changes to the sqd lists are synchronized through the
		 * kthread parking. This synchronizes the thread vs users,
		 * the users are synchronized on the sqd->ctx_lock.
		 */
		if (kthread_should_park()) {
			kthread_parkme();
			/*
			 * When sq thread is unparked, in case the previous park operation
			 * comes from io_put_sq_data(), which means that sq thread is going
			 * to be stopped, so here needs to have a check.
			 */
			if (kthread_should_stop())
				break;
		}

		if (unlikely(!list_empty(&sqd->ctx_new_list))) {
			io_sqd_init_new(sqd);
			timeout = jiffies + sqd->sq_thread_idle;
		}

		sqt_spin = false;
		cap_entries = !list_is_singular(&sqd->ctx_list);
		list_for_each_entry(ctx, &sqd->ctx_list, sqd_list) {
			if (current->cred != ctx->creds) {
				if (old_cred)
					revert_creds(old_cred);
				old_cred = override_creds(ctx->creds);
			}
			io_sq_thread_associate_blkcg(ctx, &cur_css);
#ifdef CONFIG_AUDIT
			current->loginuid = ctx->loginuid;
			current->sessionid = ctx->sessionid;
#endif

			ret = __io_sq_thread(ctx, cap_entries);
			if (!sqt_spin && (ret > 0 || !list_empty(&ctx->iopoll_list)))
				sqt_spin = true;

			io_sq_thread_drop_mm_files();
		}

		if (sqt_spin || !time_after(jiffies, timeout)) {
			io_run_task_work();
			io_sq_thread_drop_mm_files();
			cond_resched();
			if (sqt_spin)
				timeout = jiffies + sqd->sq_thread_idle;
			continue;
		}

		needs_sched = true;
		prepare_to_wait(&sqd->wait, &wait, TASK_INTERRUPTIBLE);
		list_for_each_entry(ctx, &sqd->ctx_list, sqd_list) {
			if ((ctx->flags & IORING_SETUP_IOPOLL) &&
			    !list_empty_careful(&ctx->iopoll_list)) {
				needs_sched = false;
				break;
			}
			if (io_sqring_entries(ctx)) {
				needs_sched = false;
				break;
			}
		}

		if (needs_sched && !kthread_should_park()) {
			list_for_each_entry(ctx, &sqd->ctx_list, sqd_list)
				io_ring_set_wakeup_flag(ctx);

			schedule();
			list_for_each_entry(ctx, &sqd->ctx_list, sqd_list)
				io_ring_clear_wakeup_flag(ctx);
		}

		finish_wait(&sqd->wait, &wait);
		timeout = jiffies + sqd->sq_thread_idle;
	}

	io_run_task_work();
	io_sq_thread_drop_mm_files();

	if (cur_css)
		io_sq_thread_unassociate_blkcg();
	if (old_cred)
		revert_creds(old_cred);

	task_lock(current);
	current->files = old_files;
	current->nsproxy = old_nsproxy;
	task_unlock(current);

	kthread_parkme();

	return 0;
}

struct io_wait_queue {
	struct wait_queue_entry wq;
	struct io_ring_ctx *ctx;
	unsigned to_wait;
	unsigned nr_timeouts;
};

static inline bool io_should_wake(struct io_wait_queue *iowq)
{
	struct io_ring_ctx *ctx = iowq->ctx;

	/*
	 * Wake up if we have enough events, or if a timeout occurred since we
	 * started waiting. For timeouts, we always want to return to userspace,
	 * regardless of event count.
	 */
	return io_cqring_events(ctx) >= iowq->to_wait ||
			atomic_read(&ctx->cq_timeouts) != iowq->nr_timeouts;
}

static int io_wake_function(struct wait_queue_entry *curr, unsigned int mode,
			    int wake_flags, void *key)
{
	struct io_wait_queue *iowq = container_of(curr, struct io_wait_queue,
							wq);

	/*
	 * Cannot safely flush overflowed CQEs from here, ensure we wake up
	 * the task, and the next invocation will do it.
	 */
	if (io_should_wake(iowq) || test_bit(0, &iowq->ctx->cq_check_overflow))
		return autoremove_wake_function(curr, mode, wake_flags, key);
	return -1;
}

static int io_run_task_work_sig(void)
{
	if (io_run_task_work())
		return 1;
	if (!signal_pending(current))
		return 0;
	if (test_tsk_thread_flag(current, TIF_NOTIFY_SIGNAL))
		return -ERESTARTSYS;
	return -EINTR;
}

/* when returns >0, the caller should retry */
static inline int io_cqring_wait_schedule(struct io_ring_ctx *ctx,
					  struct io_wait_queue *iowq,
					  signed long *timeout)
{
	int ret;

	/* make sure we run task_work before checking for signals */
	ret = io_run_task_work_sig();
	if (ret || io_should_wake(iowq))
		return ret;
	/* let the caller flush overflows, retry */
	if (test_bit(0, &ctx->cq_check_overflow))
		return 1;

	*timeout = schedule_timeout(*timeout);
	return !*timeout ? -ETIME : 1;
}

/*
 * Wait until events become available, if we don't already have some. The
 * application must reap them itself, as they reside on the shared cq ring.
 */
static int io_cqring_wait(struct io_ring_ctx *ctx, int min_events,
			  const sigset_t __user *sig, size_t sigsz,
			  struct __kernel_timespec __user *uts)
{
	struct io_wait_queue iowq = {
		.wq = {
			.private	= current,
			.func		= io_wake_function,
			.entry		= LIST_HEAD_INIT(iowq.wq.entry),
		},
		.ctx		= ctx,
		.to_wait	= min_events,
	};
	struct io_rings *rings = ctx->rings;
	signed long timeout = MAX_SCHEDULE_TIMEOUT;
	int ret;

	do {
		io_cqring_overflow_flush(ctx, false, NULL, NULL);
		if (io_cqring_events(ctx) >= min_events)
			return 0;
		if (!io_run_task_work())
			break;
	} while (1);

	if (sig) {
#ifdef CONFIG_COMPAT
		if (in_compat_syscall())
			ret = set_compat_user_sigmask((const compat_sigset_t __user *)sig,
						      sigsz);
		else
#endif
			ret = set_user_sigmask(sig, sigsz);

		if (ret)
			return ret;
	}

	if (uts) {
		struct timespec64 ts;

		if (get_timespec64(&ts, uts))
			return -EFAULT;
		timeout = timespec64_to_jiffies(&ts);
	}

	iowq.nr_timeouts = atomic_read(&ctx->cq_timeouts);
	trace_io_uring_cqring_wait(ctx, min_events);
	do {
		io_cqring_overflow_flush(ctx, false, NULL, NULL);
		prepare_to_wait_exclusive(&ctx->wait, &iowq.wq,
						TASK_INTERRUPTIBLE);
		ret = io_cqring_wait_schedule(ctx, &iowq, &timeout);
		finish_wait(&ctx->wait, &iowq.wq);
	} while (ret > 0);

	restore_saved_sigmask_unless(ret == -EINTR);

	return READ_ONCE(rings->cq.head) == READ_ONCE(rings->cq.tail) ? ret : 0;
}

static void __io_sqe_files_unregister(struct io_ring_ctx *ctx)
{
#if defined(CONFIG_UNIX)
	if (ctx->ring_sock) {
		struct sock *sock = ctx->ring_sock->sk;
		struct sk_buff *skb;

		while ((skb = skb_dequeue(&sock->sk_receive_queue)) != NULL)
			kfree_skb(skb);
	}
#else
	int i;

	for (i = 0; i < ctx->nr_user_files; i++) {
		struct file *file;

		file = io_file_from_index(ctx, i);
		if (file)
			fput(file);
	}
#endif
}

static void io_rsrc_data_ref_zero(struct percpu_ref *ref)
{
	struct fixed_rsrc_data *data;

	data = container_of(ref, struct fixed_rsrc_data, refs);
	complete(&data->done);
}

static inline void io_rsrc_ref_lock(struct io_ring_ctx *ctx)
{
	spin_lock_bh(&ctx->rsrc_ref_lock);
}

static inline void io_rsrc_ref_unlock(struct io_ring_ctx *ctx)
{
	spin_unlock_bh(&ctx->rsrc_ref_lock);
}

static void io_sqe_rsrc_set_node(struct io_ring_ctx *ctx,
				 struct fixed_rsrc_data *rsrc_data,
				 struct fixed_rsrc_ref_node *ref_node)
{
	io_rsrc_ref_lock(ctx);
	rsrc_data->node = ref_node;
	list_add_tail(&ref_node->node, &ctx->rsrc_ref_list);
	io_rsrc_ref_unlock(ctx);
	percpu_ref_get(&rsrc_data->refs);
}

static int io_rsrc_ref_quiesce(struct fixed_rsrc_data *data,
			       struct io_ring_ctx *ctx,
			       struct fixed_rsrc_ref_node *backup_node)
{
	struct fixed_rsrc_ref_node *ref_node;
	int ret;

	io_rsrc_ref_lock(ctx);
	ref_node = data->node;
	io_rsrc_ref_unlock(ctx);
	if (ref_node)
		percpu_ref_kill(&ref_node->refs);

	percpu_ref_kill(&data->refs);

	/* wait for all refs nodes to complete */
	flush_delayed_work(&ctx->rsrc_put_work);
	do {
		ret = wait_for_completion_interruptible(&data->done);
		if (!ret)
			break;
		ret = io_run_task_work_sig();
		if (ret < 0) {
			percpu_ref_resurrect(&data->refs);
			reinit_completion(&data->done);
			io_sqe_rsrc_set_node(ctx, data, backup_node);
			return ret;
		}
	} while (1);

	destroy_fixed_rsrc_ref_node(backup_node);
	return 0;
}

static struct fixed_rsrc_data *alloc_fixed_rsrc_data(struct io_ring_ctx *ctx)
{
	struct fixed_rsrc_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return NULL;

	if (percpu_ref_init(&data->refs, io_rsrc_data_ref_zero,
			    PERCPU_REF_ALLOW_REINIT, GFP_KERNEL)) {
		kfree(data);
		return NULL;
	}
	data->ctx = ctx;
	init_completion(&data->done);
	return data;
}

static void free_fixed_rsrc_data(struct fixed_rsrc_data *data)
{
	percpu_ref_exit(&data->refs);
	kfree(data->table);
	kfree(data);
}

static int io_sqe_files_unregister(struct io_ring_ctx *ctx)
{
	struct fixed_rsrc_data *data = ctx->file_data;
	struct fixed_rsrc_ref_node *backup_node;
	unsigned nr_tables, i;
	int ret;

	if (!data)
		return -ENXIO;
	backup_node = alloc_fixed_rsrc_ref_node(ctx);
	if (!backup_node)
		return -ENOMEM;
	init_fixed_file_ref_node(ctx, backup_node);

	ret = io_rsrc_ref_quiesce(data, ctx, backup_node);
	if (ret)
		return ret;

	__io_sqe_files_unregister(ctx);
	nr_tables = DIV_ROUND_UP(ctx->nr_user_files, IORING_MAX_FILES_TABLE);
	for (i = 0; i < nr_tables; i++)
		kfree(data->table[i].files);
	free_fixed_rsrc_data(data);
	ctx->file_data = NULL;
	ctx->nr_user_files = 0;
	return 0;
}

static void io_put_sq_data(struct io_sq_data *sqd)
{
	if (refcount_dec_and_test(&sqd->refs)) {
		/*
		 * The park is a bit of a work-around, without it we get
		 * warning spews on shutdown with SQPOLL set and affinity
		 * set to a single CPU.
		 */
		if (sqd->thread) {
			kthread_park(sqd->thread);
			kthread_stop(sqd->thread);
		}

		kfree(sqd);
	}
}

static struct io_sq_data *io_attach_sq_data(struct io_uring_params *p)
{
	struct io_ring_ctx *ctx_attach;
	struct io_sq_data *sqd;
	struct fd f;

	f = fdget(p->wq_fd);
	if (!f.file)
		return ERR_PTR(-ENXIO);
	if (f.file->f_op != &io_uring_fops) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	ctx_attach = f.file->private_data;
	sqd = ctx_attach->sq_data;
	if (!sqd) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	refcount_inc(&sqd->refs);
	fdput(f);
	return sqd;
}

static struct io_sq_data *io_get_sq_data(struct io_uring_params *p)
{
	struct io_sq_data *sqd;

	if (p->flags & IORING_SETUP_ATTACH_WQ)
		return io_attach_sq_data(p);

	sqd = kzalloc(sizeof(*sqd), GFP_KERNEL);
	if (!sqd)
		return ERR_PTR(-ENOMEM);

	refcount_set(&sqd->refs, 1);
	INIT_LIST_HEAD(&sqd->ctx_list);
	INIT_LIST_HEAD(&sqd->ctx_new_list);
	mutex_init(&sqd->ctx_lock);
	mutex_init(&sqd->lock);
	init_waitqueue_head(&sqd->wait);
	return sqd;
}

static void io_sq_thread_unpark(struct io_sq_data *sqd)
	__releases(&sqd->lock)
{
	if (!sqd->thread)
		return;
	kthread_unpark(sqd->thread);
	mutex_unlock(&sqd->lock);
}

static void io_sq_thread_park(struct io_sq_data *sqd)
	__acquires(&sqd->lock)
{
	if (!sqd->thread)
		return;
	mutex_lock(&sqd->lock);
	kthread_park(sqd->thread);
}

static void io_sq_thread_stop(struct io_ring_ctx *ctx)
{
	struct io_sq_data *sqd = ctx->sq_data;

	if (sqd) {
		if (sqd->thread) {
			/*
			 * We may arrive here from the error branch in
			 * io_sq_offload_create() where the kthread is created
			 * without being waked up, thus wake it up now to make
			 * sure the wait will complete.
			 */
			wake_up_process(sqd->thread);
			wait_for_completion(&ctx->sq_thread_comp);

			io_sq_thread_park(sqd);
		}

		mutex_lock(&sqd->ctx_lock);
		list_del(&ctx->sqd_list);
		io_sqd_update_thread_idle(sqd);
		mutex_unlock(&sqd->ctx_lock);

		if (sqd->thread)
			io_sq_thread_unpark(sqd);

		io_put_sq_data(sqd);
		ctx->sq_data = NULL;
	}
}

static void io_finish_async(struct io_ring_ctx *ctx)
{
	io_sq_thread_stop(ctx);

	if (ctx->io_wq) {
		io_wq_destroy(ctx->io_wq);
		ctx->io_wq = NULL;
	}
}

#if defined(CONFIG_UNIX)
/*
 * Ensure the UNIX gc is aware of our file set, so we are certain that
 * the io_uring can be safely unregistered on process exit, even if we have
 * loops in the file referencing.
 */
static int __io_sqe_files_scm(struct io_ring_ctx *ctx, int nr, int offset)
{
	struct sock *sk = ctx->ring_sock->sk;
	struct scm_fp_list *fpl;
	struct sk_buff *skb;
	int i, nr_files;

	fpl = kzalloc(sizeof(*fpl), GFP_KERNEL);
	if (!fpl)
		return -ENOMEM;

	skb = alloc_skb(0, GFP_KERNEL);
	if (!skb) {
		kfree(fpl);
		return -ENOMEM;
	}

	skb->sk = sk;

	nr_files = 0;
	fpl->user = get_uid(ctx->user);
	for (i = 0; i < nr; i++) {
		struct file *file = io_file_from_index(ctx, i + offset);

		if (!file)
			continue;
		fpl->fp[nr_files] = get_file(file);
		unix_inflight(fpl->user, fpl->fp[nr_files]);
		nr_files++;
	}

	if (nr_files) {
		fpl->max = SCM_MAX_FD;
		fpl->count = nr_files;
		UNIXCB(skb).fp = fpl;
		skb->destructor = unix_destruct_scm;
		refcount_add(skb->truesize, &sk->sk_wmem_alloc);
		skb_queue_head(&sk->sk_receive_queue, skb);

		for (i = 0; i < nr_files; i++)
			fput(fpl->fp[i]);
	} else {
		kfree_skb(skb);
		kfree(fpl);
	}

	return 0;
}

/*
 * If UNIX sockets are enabled, fd passing can cause a reference cycle which
 * causes regular reference counting to break down. We rely on the UNIX
 * garbage collection to take care of this problem for us.
 */
static int io_sqe_files_scm(struct io_ring_ctx *ctx)
{
	unsigned left, total;
	int ret = 0;

	total = 0;
	left = ctx->nr_user_files;
	while (left) {
		unsigned this_files = min_t(unsigned, left, SCM_MAX_FD);

		ret = __io_sqe_files_scm(ctx, this_files, total);
		if (ret)
			break;
		left -= this_files;
		total += this_files;
	}

	if (!ret)
		return 0;

	while (total < ctx->nr_user_files) {
		struct file *file = io_file_from_index(ctx, total);

		if (file)
			fput(file);
		total++;
	}

	return ret;
}
#else
static int io_sqe_files_scm(struct io_ring_ctx *ctx)
{
	return 0;
}
#endif

static int io_sqe_alloc_file_tables(struct fixed_rsrc_data *file_data,
				    unsigned nr_tables, unsigned nr_files)
{
	int i;

	for (i = 0; i < nr_tables; i++) {
		struct fixed_rsrc_table *table = &file_data->table[i];
		unsigned this_files;

		this_files = min(nr_files, IORING_MAX_FILES_TABLE);
		table->files = kcalloc(this_files, sizeof(struct file *),
					GFP_KERNEL);
		if (!table->files)
			break;
		nr_files -= this_files;
	}

	if (i == nr_tables)
		return 0;

	for (i = 0; i < nr_tables; i++) {
		struct fixed_rsrc_table *table = &file_data->table[i];
		kfree(table->files);
	}
	return 1;
}

static void io_ring_file_put(struct io_ring_ctx *ctx, struct io_rsrc_put *prsrc)
{
	struct file *file = prsrc->file;
#if defined(CONFIG_UNIX)
	struct sock *sock = ctx->ring_sock->sk;
	struct sk_buff_head list, *head = &sock->sk_receive_queue;
	struct sk_buff *skb;
	int i;

	__skb_queue_head_init(&list);

	/*
	 * Find the skb that holds this file in its SCM_RIGHTS. When found,
	 * remove this entry and rearrange the file array.
	 */
	skb = skb_dequeue(head);
	while (skb) {
		struct scm_fp_list *fp;

		fp = UNIXCB(skb).fp;
		for (i = 0; i < fp->count; i++) {
			int left;

			if (fp->fp[i] != file)
				continue;

			unix_notinflight(fp->user, fp->fp[i]);
			left = fp->count - 1 - i;
			if (left) {
				memmove(&fp->fp[i], &fp->fp[i + 1],
						left * sizeof(struct file *));
			}
			fp->count--;
			if (!fp->count) {
				kfree_skb(skb);
				skb = NULL;
			} else {
				__skb_queue_tail(&list, skb);
			}
			fput(file);
			file = NULL;
			break;
		}

		if (!file)
			break;

		__skb_queue_tail(&list, skb);

		skb = skb_dequeue(head);
	}

	if (skb_peek(&list)) {
		spin_lock_irq(&head->lock);
		while ((skb = __skb_dequeue(&list)) != NULL)
			__skb_queue_tail(head, skb);
		spin_unlock_irq(&head->lock);
	}
#else
	fput(file);
#endif
}

static void __io_rsrc_put_work(struct fixed_rsrc_ref_node *ref_node)
{
	struct fixed_rsrc_data *rsrc_data = ref_node->rsrc_data;
	struct io_ring_ctx *ctx = rsrc_data->ctx;
	struct io_rsrc_put *prsrc, *tmp;

	list_for_each_entry_safe(prsrc, tmp, &ref_node->rsrc_list, list) {
		list_del(&prsrc->list);
		ref_node->rsrc_put(ctx, prsrc);
		kfree(prsrc);
	}

	percpu_ref_exit(&ref_node->refs);
	kfree(ref_node);
	percpu_ref_put(&rsrc_data->refs);
}

static void io_rsrc_put_work(struct work_struct *work)
{
	struct io_ring_ctx *ctx;
	struct llist_node *node;

	ctx = container_of(work, struct io_ring_ctx, rsrc_put_work.work);
	node = llist_del_all(&ctx->rsrc_put_llist);

	while (node) {
		struct fixed_rsrc_ref_node *ref_node;
		struct llist_node *next = node->next;

		ref_node = llist_entry(node, struct fixed_rsrc_ref_node, llist);
		__io_rsrc_put_work(ref_node);
		node = next;
	}
}

static struct file **io_fixed_file_slot(struct fixed_rsrc_data *file_data,
					unsigned i)
{
	struct fixed_rsrc_table *table;

	table = &file_data->table[i >> IORING_FILE_TABLE_SHIFT];
	return &table->files[i & IORING_FILE_TABLE_MASK];
}

static void io_rsrc_node_ref_zero(struct percpu_ref *ref)
{
	struct fixed_rsrc_ref_node *ref_node;
	struct fixed_rsrc_data *data;
	struct io_ring_ctx *ctx;
	bool first_add = false;
	int delay = HZ;

	ref_node = container_of(ref, struct fixed_rsrc_ref_node, refs);
	data = ref_node->rsrc_data;
	ctx = data->ctx;

	io_rsrc_ref_lock(ctx);
	ref_node->done = true;

	while (!list_empty(&ctx->rsrc_ref_list)) {
		ref_node = list_first_entry(&ctx->rsrc_ref_list,
					struct fixed_rsrc_ref_node, node);
		/* recycle ref nodes in order */
		if (!ref_node->done)
			break;
		list_del(&ref_node->node);
		first_add |= llist_add(&ref_node->llist, &ctx->rsrc_put_llist);
	}
	io_rsrc_ref_unlock(ctx);

	if (percpu_ref_is_dying(&data->refs))
		delay = 0;

	if (!delay)
		mod_delayed_work(system_wq, &ctx->rsrc_put_work, 0);
	else if (first_add)
		queue_delayed_work(system_wq, &ctx->rsrc_put_work, delay);
}

static struct fixed_rsrc_ref_node *alloc_fixed_rsrc_ref_node(
			struct io_ring_ctx *ctx)
{
	struct fixed_rsrc_ref_node *ref_node;

	ref_node = kzalloc(sizeof(*ref_node), GFP_KERNEL);
	if (!ref_node)
		return NULL;

	if (percpu_ref_init(&ref_node->refs, io_rsrc_node_ref_zero,
			    0, GFP_KERNEL)) {
		kfree(ref_node);
		return NULL;
	}
	INIT_LIST_HEAD(&ref_node->node);
	INIT_LIST_HEAD(&ref_node->rsrc_list);
	ref_node->done = false;
	return ref_node;
}

static void init_fixed_file_ref_node(struct io_ring_ctx *ctx,
				     struct fixed_rsrc_ref_node *ref_node)
{
	ref_node->rsrc_data = ctx->file_data;
	ref_node->rsrc_put = io_ring_file_put;
}

static void destroy_fixed_rsrc_ref_node(struct fixed_rsrc_ref_node *ref_node)
{
	percpu_ref_exit(&ref_node->refs);
	kfree(ref_node);
}


static int io_sqe_files_register(struct io_ring_ctx *ctx, void __user *arg,
				 unsigned nr_args)
{
	__s32 __user *fds = (__s32 __user *) arg;
	unsigned nr_tables, i;
	struct file *file;
	int fd, ret = -ENOMEM;
	struct fixed_rsrc_ref_node *ref_node;
	struct fixed_rsrc_data *file_data;

	if (ctx->file_data)
		return -EBUSY;
	if (!nr_args)
		return -EINVAL;
	if (nr_args > IORING_MAX_FIXED_FILES)
		return -EMFILE;

	file_data = alloc_fixed_rsrc_data(ctx);
	if (!file_data)
		return -ENOMEM;
	ctx->file_data = file_data;

	nr_tables = DIV_ROUND_UP(nr_args, IORING_MAX_FILES_TABLE);
	file_data->table = kcalloc(nr_tables, sizeof(*file_data->table),
				   GFP_KERNEL);
	if (!file_data->table)
		goto out_free;

	if (io_sqe_alloc_file_tables(file_data, nr_tables, nr_args))
		goto out_free;

	for (i = 0; i < nr_args; i++, ctx->nr_user_files++) {
		if (copy_from_user(&fd, &fds[i], sizeof(fd))) {
			ret = -EFAULT;
			goto out_fput;
		}
		/* allow sparse sets */
		if (fd == -1)
			continue;

		file = fget(fd);
		ret = -EBADF;
		if (!file)
			goto out_fput;

		/*
		 * Don't allow io_uring instances to be registered. If UNIX
		 * isn't enabled, then this causes a reference cycle and this
		 * instance can never get freed. If UNIX is enabled we'll
		 * handle it just fine, but there's still no point in allowing
		 * a ring fd as it doesn't support regular read/write anyway.
		 */
		if (file->f_op == &io_uring_fops) {
			fput(file);
			goto out_fput;
		}
		*io_fixed_file_slot(file_data, i) = file;
	}

	ret = io_sqe_files_scm(ctx);
	if (ret) {
		io_sqe_files_unregister(ctx);
		return ret;
	}

	ref_node = alloc_fixed_rsrc_ref_node(ctx);
	if (!ref_node) {
		io_sqe_files_unregister(ctx);
		return -ENOMEM;
	}
	init_fixed_file_ref_node(ctx, ref_node);

	io_sqe_rsrc_set_node(ctx, file_data, ref_node);
	return ret;
out_fput:
	for (i = 0; i < ctx->nr_user_files; i++) {
		file = io_file_from_index(ctx, i);
		if (file)
			fput(file);
	}
	for (i = 0; i < nr_tables; i++)
		kfree(file_data->table[i].files);
	ctx->nr_user_files = 0;
out_free:
	free_fixed_rsrc_data(ctx->file_data);
	ctx->file_data = NULL;
	return ret;
}

static int io_sqe_file_register(struct io_ring_ctx *ctx, struct file *file,
				int index)
{
#if defined(CONFIG_UNIX)
	struct sock *sock = ctx->ring_sock->sk;
	struct sk_buff_head *head = &sock->sk_receive_queue;
	struct sk_buff *skb;

	/*
	 * See if we can merge this file into an existing skb SCM_RIGHTS
	 * file set. If there's no room, fall back to allocating a new skb
	 * and filling it in.
	 */
	spin_lock_irq(&head->lock);
	skb = skb_peek(head);
	if (skb) {
		struct scm_fp_list *fpl = UNIXCB(skb).fp;

		if (fpl->count < SCM_MAX_FD) {
			__skb_unlink(skb, head);
			spin_unlock_irq(&head->lock);
			fpl->fp[fpl->count] = get_file(file);
			unix_inflight(fpl->user, fpl->fp[fpl->count]);
			fpl->count++;
			spin_lock_irq(&head->lock);
			__skb_queue_head(head, skb);
		} else {
			skb = NULL;
		}
	}
	spin_unlock_irq(&head->lock);

	if (skb) {
		fput(file);
		return 0;
	}

	return __io_sqe_files_scm(ctx, 1, index);
#else
	return 0;
#endif
}

static int io_queue_rsrc_removal(struct fixed_rsrc_data *data, void *rsrc)
{
	struct io_rsrc_put *prsrc;
	struct fixed_rsrc_ref_node *ref_node = data->node;

	prsrc = kzalloc(sizeof(*prsrc), GFP_KERNEL);
	if (!prsrc)
		return -ENOMEM;

	prsrc->rsrc = rsrc;
	list_add(&prsrc->list, &ref_node->rsrc_list);

	return 0;
}

static inline int io_queue_file_removal(struct fixed_rsrc_data *data,
					struct file *file)
{
	return io_queue_rsrc_removal(data, (void *)file);
}

static int __io_sqe_files_update(struct io_ring_ctx *ctx,
				 struct io_uring_rsrc_update *up,
				 unsigned nr_args)
{
	struct fixed_rsrc_data *data = ctx->file_data;
	struct fixed_rsrc_ref_node *ref_node;
	struct file *file, **file_slot;
	__s32 __user *fds;
	int fd, i, err;
	__u32 done;
	bool needs_switch = false;

	if (check_add_overflow(up->offset, nr_args, &done))
		return -EOVERFLOW;
	if (done > ctx->nr_user_files)
		return -EINVAL;

	ref_node = alloc_fixed_rsrc_ref_node(ctx);
	if (!ref_node)
		return -ENOMEM;
	init_fixed_file_ref_node(ctx, ref_node);

	fds = u64_to_user_ptr(up->data);
	for (done = 0; done < nr_args; done++) {
		err = 0;
		if (copy_from_user(&fd, &fds[done], sizeof(fd))) {
			err = -EFAULT;
			break;
		}
		if (fd == IORING_REGISTER_FILES_SKIP)
			continue;

		i = array_index_nospec(up->offset + done, ctx->nr_user_files);
		file_slot = io_fixed_file_slot(ctx->file_data, i);

		if (*file_slot) {
			err = io_queue_file_removal(data, *file_slot);
			if (err)
				break;
			*file_slot = NULL;
			needs_switch = true;
		}
		if (fd != -1) {
			file = fget(fd);
			if (!file) {
				err = -EBADF;
				break;
			}
			/*
			 * Don't allow io_uring instances to be registered. If
			 * UNIX isn't enabled, then this causes a reference
			 * cycle and this instance can never get freed. If UNIX
			 * is enabled we'll handle it just fine, but there's
			 * still no point in allowing a ring fd as it doesn't
			 * support regular read/write anyway.
			 */
			if (file->f_op == &io_uring_fops) {
				fput(file);
				err = -EBADF;
				break;
			}
			*file_slot = file;
			err = io_sqe_file_register(ctx, file, i);
			if (err) {
				*file_slot = NULL;
				fput(file);
				break;
			}
		}
	}

	if (needs_switch) {
		percpu_ref_kill(&data->node->refs);
		io_sqe_rsrc_set_node(ctx, data, ref_node);
	} else
		destroy_fixed_rsrc_ref_node(ref_node);

	return done ? done : err;
}

static int io_sqe_files_update(struct io_ring_ctx *ctx, void __user *arg,
			       unsigned nr_args)
{
	struct io_uring_rsrc_update up;

	if (!ctx->file_data)
		return -ENXIO;
	if (!nr_args)
		return -EINVAL;
	if (copy_from_user(&up, arg, sizeof(up)))
		return -EFAULT;
	if (up.resv)
		return -EINVAL;

	return __io_sqe_files_update(ctx, &up, nr_args);
}

static struct io_wq_work *io_free_work(struct io_wq_work *work)
{
	struct io_kiocb *req = container_of(work, struct io_kiocb, work);

	req = io_put_req_find_next(req);
	return req ? &req->work : NULL;
}

static int io_init_wq_offload(struct io_ring_ctx *ctx,
			      struct io_uring_params *p)
{
	struct io_wq_data data;
	struct fd f;
	struct io_ring_ctx *ctx_attach;
	unsigned int concurrency;
	int ret = 0;

	data.user = ctx->user;
	data.free_work = io_free_work;
	data.do_work = io_wq_submit_work;

	if (!(p->flags & IORING_SETUP_ATTACH_WQ)) {
		/* Do QD, or 4 * CPUS, whatever is smallest */
		concurrency = min(ctx->sq_entries, 4 * num_online_cpus());

		ctx->io_wq = io_wq_create(concurrency, &data);
		if (IS_ERR(ctx->io_wq)) {
			ret = PTR_ERR(ctx->io_wq);
			ctx->io_wq = NULL;
		}
		return ret;
	}

	f = fdget(p->wq_fd);
	if (!f.file)
		return -EBADF;

	if (f.file->f_op != &io_uring_fops) {
		ret = -EINVAL;
		goto out_fput;
	}

	ctx_attach = f.file->private_data;
	/* @io_wq is protected by holding the fd */
	if (!io_wq_get(ctx_attach->io_wq, &data)) {
		ret = -EINVAL;
		goto out_fput;
	}

	ctx->io_wq = ctx_attach->io_wq;
out_fput:
	fdput(f);
	return ret;
}

static int io_uring_alloc_task_context(struct task_struct *task)
{
	struct io_uring_task *tctx;
	int ret;

	tctx = kmalloc(sizeof(*tctx), GFP_KERNEL);
	if (unlikely(!tctx))
		return -ENOMEM;

	ret = percpu_counter_init(&tctx->inflight, 0, GFP_KERNEL);
	if (unlikely(ret)) {
		kfree(tctx);
		return ret;
	}

	xa_init(&tctx->xa);
	init_waitqueue_head(&tctx->wait);
	tctx->last = NULL;
	atomic_set(&tctx->in_idle, 0);
	tctx->sqpoll = false;
	io_init_identity(&tctx->__identity);
	tctx->identity = &tctx->__identity;
	task->io_uring = tctx;
	spin_lock_init(&tctx->task_lock);
	INIT_WQ_LIST(&tctx->task_list);
	tctx->task_state = 0;
	init_task_work(&tctx->task_work, tctx_task_work);
	return 0;
}

void __io_uring_free(struct task_struct *tsk)
{
	struct io_uring_task *tctx = tsk->io_uring;

	WARN_ON_ONCE(!xa_empty(&tctx->xa));
	WARN_ON_ONCE(refcount_read(&tctx->identity->count) != 1);
	if (tctx->identity != &tctx->__identity)
		kfree(tctx->identity);
	percpu_counter_destroy(&tctx->inflight);
	kfree(tctx);
	tsk->io_uring = NULL;
}

static int io_sq_offload_create(struct io_ring_ctx *ctx,
				struct io_uring_params *p)
{
	int ret;

	if (ctx->flags & IORING_SETUP_SQPOLL) {
		struct io_sq_data *sqd;

		ret = -EPERM;
		if (!capable(CAP_SYS_ADMIN) && !capable(CAP_SYS_NICE))
			goto err;

		sqd = io_get_sq_data(p);
		if (IS_ERR(sqd)) {
			ret = PTR_ERR(sqd);
			goto err;
		}

		ctx->sq_data = sqd;
		io_sq_thread_park(sqd);
		mutex_lock(&sqd->ctx_lock);
		list_add(&ctx->sqd_list, &sqd->ctx_new_list);
		mutex_unlock(&sqd->ctx_lock);
		io_sq_thread_unpark(sqd);

		ctx->sq_thread_idle = msecs_to_jiffies(p->sq_thread_idle);
		if (!ctx->sq_thread_idle)
			ctx->sq_thread_idle = HZ;

		if (sqd->thread)
			goto done;

		if (p->flags & IORING_SETUP_SQ_AFF) {
			int cpu = p->sq_thread_cpu;

			ret = -EINVAL;
			if (cpu >= nr_cpu_ids)
				goto err;
			if (!cpu_online(cpu))
				goto err;

			sqd->thread = kthread_create_on_cpu(io_sq_thread, sqd,
							cpu, "io_uring-sq");
		} else {
			sqd->thread = kthread_create(io_sq_thread, sqd,
							"io_uring-sq");
		}
		if (IS_ERR(sqd->thread)) {
			ret = PTR_ERR(sqd->thread);
			sqd->thread = NULL;
			goto err;
		}
		ret = io_uring_alloc_task_context(sqd->thread);
		if (ret)
			goto err;
	} else if (p->flags & IORING_SETUP_SQ_AFF) {
		/* Can't have SQ_AFF without SQPOLL */
		ret = -EINVAL;
		goto err;
	}

done:
	ret = io_init_wq_offload(ctx, p);
	if (ret)
		goto err;

	return 0;
err:
	io_finish_async(ctx);
	return ret;
}

static void io_sq_offload_start(struct io_ring_ctx *ctx)
{
	struct io_sq_data *sqd = ctx->sq_data;

	if ((ctx->flags & IORING_SETUP_SQPOLL) && sqd->thread)
		wake_up_process(sqd->thread);
}

static inline void __io_unaccount_mem(struct user_struct *user,
				      unsigned long nr_pages)
{
	atomic_long_sub(nr_pages, &user->locked_vm);
}

static inline int __io_account_mem(struct user_struct *user,
				   unsigned long nr_pages)
{
	unsigned long page_limit, cur_pages, new_pages;

	/* Don't allow more pages than we can safely lock */
	page_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;

	do {
		cur_pages = atomic_long_read(&user->locked_vm);
		new_pages = cur_pages + nr_pages;
		if (new_pages > page_limit)
			return -ENOMEM;
	} while (atomic_long_cmpxchg(&user->locked_vm, cur_pages,
					new_pages) != cur_pages);

	return 0;
}

static void io_unaccount_mem(struct io_ring_ctx *ctx, unsigned long nr_pages)
{
	if (ctx->limit_mem)
		__io_unaccount_mem(ctx->user, nr_pages);

	if (ctx->mm_account)
		atomic64_sub(nr_pages, &ctx->mm_account->pinned_vm);
}

static int io_account_mem(struct io_ring_ctx *ctx, unsigned long nr_pages)
{
	int ret;

	if (ctx->limit_mem) {
		ret = __io_account_mem(ctx->user, nr_pages);
		if (ret)
			return ret;
	}

	if (ctx->mm_account)
		atomic64_add(nr_pages, &ctx->mm_account->pinned_vm);

	return 0;
}

static void io_mem_free(void *ptr)
{
	struct page *page;

	if (!ptr)
		return;

	page = virt_to_head_page(ptr);
	if (put_page_testzero(page))
		free_compound_page(page);
}

static void *io_mem_alloc(size_t size)
{
	gfp_t gfp_flags = GFP_KERNEL | __GFP_ZERO | __GFP_NOWARN | __GFP_COMP |
				__GFP_NORETRY | __GFP_ACCOUNT;

	return (void *) __get_free_pages(gfp_flags, get_order(size));
}

static unsigned long rings_size(unsigned sq_entries, unsigned cq_entries,
				size_t *sq_offset)
{
	struct io_rings *rings;
	size_t off, sq_array_size;

	off = struct_size(rings, cqes, cq_entries);
	if (off == SIZE_MAX)
		return SIZE_MAX;

#ifdef CONFIG_SMP
	off = ALIGN(off, SMP_CACHE_BYTES);
	if (off == 0)
		return SIZE_MAX;
#endif

	if (sq_offset)
		*sq_offset = off;

	sq_array_size = array_size(sizeof(u32), sq_entries);
	if (sq_array_size == SIZE_MAX)
		return SIZE_MAX;

	if (check_add_overflow(off, sq_array_size, &off))
		return SIZE_MAX;

	return off;
}

static int io_sqe_buffers_unregister(struct io_ring_ctx *ctx)
{
	int i, j;

	if (!ctx->user_bufs)
		return -ENXIO;

	for (i = 0; i < ctx->nr_user_bufs; i++) {
		struct io_mapped_ubuf *imu = &ctx->user_bufs[i];

		for (j = 0; j < imu->nr_bvecs; j++)
			unpin_user_page(imu->bvec[j].bv_page);

		if (imu->acct_pages)
			io_unaccount_mem(ctx, imu->acct_pages);
		kvfree(imu->bvec);
		imu->nr_bvecs = 0;
	}

	kfree(ctx->user_bufs);
	ctx->user_bufs = NULL;
	ctx->nr_user_bufs = 0;
	return 0;
}

static int io_copy_iov(struct io_ring_ctx *ctx, struct iovec *dst,
		       void __user *arg, unsigned index)
{
	struct iovec __user *src;

#ifdef CONFIG_COMPAT
	if (ctx->compat) {
		struct compat_iovec __user *ciovs;
		struct compat_iovec ciov;

		ciovs = (struct compat_iovec __user *) arg;
		if (copy_from_user(&ciov, &ciovs[index], sizeof(ciov)))
			return -EFAULT;

		dst->iov_base = u64_to_user_ptr((u64)ciov.iov_base);
		dst->iov_len = ciov.iov_len;
		return 0;
	}
#endif
	src = (struct iovec __user *) arg;
	if (copy_from_user(dst, &src[index], sizeof(*dst)))
		return -EFAULT;
	return 0;
}

/*
 * Not super efficient, but this is just a registration time. And we do cache
 * the last compound head, so generally we'll only do a full search if we don't
 * match that one.
 *
 * We check if the given compound head page has already been accounted, to
 * avoid double accounting it. This allows us to account the full size of the
 * page, not just the constituent pages of a huge page.
 */
static bool headpage_already_acct(struct io_ring_ctx *ctx, struct page **pages,
				  int nr_pages, struct page *hpage)
{
	int i, j;

	/* check current page array */
	for (i = 0; i < nr_pages; i++) {
		if (!PageCompound(pages[i]))
			continue;
		if (compound_head(pages[i]) == hpage)
			return true;
	}

	/* check previously registered pages */
	for (i = 0; i < ctx->nr_user_bufs; i++) {
		struct io_mapped_ubuf *imu = &ctx->user_bufs[i];

		for (j = 0; j < imu->nr_bvecs; j++) {
			if (!PageCompound(imu->bvec[j].bv_page))
				continue;
			if (compound_head(imu->bvec[j].bv_page) == hpage)
				return true;
		}
	}

	return false;
}

static int io_buffer_account_pin(struct io_ring_ctx *ctx, struct page **pages,
				 int nr_pages, struct io_mapped_ubuf *imu,
				 struct page **last_hpage)
{
	int i, ret;

	for (i = 0; i < nr_pages; i++) {
		if (!PageCompound(pages[i])) {
			imu->acct_pages++;
		} else {
			struct page *hpage;

			hpage = compound_head(pages[i]);
			if (hpage == *last_hpage)
				continue;
			*last_hpage = hpage;
			if (headpage_already_acct(ctx, pages, i, hpage))
				continue;
			imu->acct_pages += page_size(hpage) >> PAGE_SHIFT;
		}
	}

	if (!imu->acct_pages)
		return 0;

	ret = io_account_mem(ctx, imu->acct_pages);
	if (ret)
		imu->acct_pages = 0;
	return ret;
}

static int io_sqe_buffer_register(struct io_ring_ctx *ctx, struct iovec *iov,
				  struct io_mapped_ubuf *imu,
				  struct page **last_hpage)
{
	struct vm_area_struct **vmas = NULL;
	struct page **pages = NULL;
	unsigned long off, start, end, ubuf;
	size_t size;
	int ret, pret, nr_pages, i;

	ubuf = (unsigned long) iov->iov_base;
	end = (ubuf + iov->iov_len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	start = ubuf >> PAGE_SHIFT;
	nr_pages = end - start;

	ret = -ENOMEM;

	pages = kvmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		goto done;

	vmas = kvmalloc_array(nr_pages, sizeof(struct vm_area_struct *),
			      GFP_KERNEL);
	if (!vmas)
		goto done;

	imu->bvec = kvmalloc_array(nr_pages, sizeof(struct bio_vec),
				   GFP_KERNEL);
	if (!imu->bvec)
		goto done;

	ret = 0;
	mmap_read_lock(current->mm);
	pret = pin_user_pages(ubuf, nr_pages, FOLL_WRITE | FOLL_LONGTERM,
			      pages, vmas);
	if (pret == nr_pages) {
		/* don't support file backed memory */
		for (i = 0; i < nr_pages; i++) {
			struct vm_area_struct *vma = vmas[i];

			if (vma->vm_file &&
			    !is_file_hugepages(vma->vm_file)) {
				ret = -EOPNOTSUPP;
				break;
			}
		}
	} else {
		ret = pret < 0 ? pret : -EFAULT;
	}
	mmap_read_unlock(current->mm);
	if (ret) {
		/*
		 * if we did partial map, or found file backed vmas,
		 * release any pages we did get
		 */
		if (pret > 0)
			unpin_user_pages(pages, pret);
		kvfree(imu->bvec);
		goto done;
	}

	ret = io_buffer_account_pin(ctx, pages, pret, imu, last_hpage);
	if (ret) {
		unpin_user_pages(pages, pret);
		kvfree(imu->bvec);
		goto done;
	}

	off = ubuf & ~PAGE_MASK;
	size = iov->iov_len;
	for (i = 0; i < nr_pages; i++) {
		size_t vec_len;

		vec_len = min_t(size_t, size, PAGE_SIZE - off);
		imu->bvec[i].bv_page = pages[i];
		imu->bvec[i].bv_len = vec_len;
		imu->bvec[i].bv_offset = off;
		off = 0;
		size -= vec_len;
	}
	/* store original address for later verification */
	imu->ubuf = ubuf;
	imu->len = iov->iov_len;
	imu->nr_bvecs = nr_pages;
	ret = 0;
done:
	kvfree(pages);
	kvfree(vmas);
	return ret;
}

static int io_buffers_map_alloc(struct io_ring_ctx *ctx, unsigned int nr_args)
{
	if (ctx->user_bufs)
		return -EBUSY;
	if (!nr_args || nr_args > UIO_MAXIOV)
		return -EINVAL;

	ctx->user_bufs = kcalloc(nr_args, sizeof(struct io_mapped_ubuf),
					GFP_KERNEL);
	if (!ctx->user_bufs)
		return -ENOMEM;

	return 0;
}

static int io_buffer_validate(struct iovec *iov)
{
	/*
	 * Don't impose further limits on the size and buffer
	 * constraints here, we'll -EINVAL later when IO is
	 * submitted if they are wrong.
	 */
	if (!iov->iov_base || !iov->iov_len)
		return -EFAULT;

	/* arbitrary limit, but we need something */
	if (iov->iov_len > SZ_1G)
		return -EFAULT;

	return 0;
}

static int io_sqe_buffers_register(struct io_ring_ctx *ctx, void __user *arg,
				   unsigned int nr_args)
{
	int i, ret;
	struct iovec iov;
	struct page *last_hpage = NULL;

	ret = io_buffers_map_alloc(ctx, nr_args);
	if (ret)
		return ret;

	for (i = 0; i < nr_args; i++) {
		struct io_mapped_ubuf *imu = &ctx->user_bufs[i];

		ret = io_copy_iov(ctx, &iov, arg, i);
		if (ret)
			break;

		ret = io_buffer_validate(&iov);
		if (ret)
			break;

		ret = io_sqe_buffer_register(ctx, &iov, imu, &last_hpage);
		if (ret)
			break;

		ctx->nr_user_bufs++;
	}

	if (ret)
		io_sqe_buffers_unregister(ctx);

	return ret;
}

static int io_eventfd_register(struct io_ring_ctx *ctx, void __user *arg)
{
	__s32 __user *fds = arg;
	int fd;

	if (ctx->cq_ev_fd)
		return -EBUSY;

	if (copy_from_user(&fd, fds, sizeof(*fds)))
		return -EFAULT;

	ctx->cq_ev_fd = eventfd_ctx_fdget(fd);
	if (IS_ERR(ctx->cq_ev_fd)) {
		int ret = PTR_ERR(ctx->cq_ev_fd);
		ctx->cq_ev_fd = NULL;
		return ret;
	}

	return 0;
}

static int io_eventfd_unregister(struct io_ring_ctx *ctx)
{
	if (ctx->cq_ev_fd) {
		eventfd_ctx_put(ctx->cq_ev_fd);
		ctx->cq_ev_fd = NULL;
		return 0;
	}

	return -ENXIO;
}

static int __io_destroy_buffers(int id, void *p, void *data)
{
	struct io_ring_ctx *ctx = data;
	struct io_buffer *buf = p;

	__io_remove_buffers(ctx, buf, id, -1U);
	return 0;
}

static void io_destroy_buffers(struct io_ring_ctx *ctx)
{
	idr_for_each(&ctx->io_buffer_idr, __io_destroy_buffers, ctx);
	idr_destroy(&ctx->io_buffer_idr);
}

static void io_req_cache_free(struct list_head *list, struct task_struct *tsk)
{
	struct io_kiocb *req, *nxt;

	list_for_each_entry_safe(req, nxt, list, compl.list) {
		if (tsk && req->task != tsk)
			continue;
		list_del(&req->compl.list);
		kmem_cache_free(req_cachep, req);
	}
}

static void io_req_caches_free(struct io_ring_ctx *ctx, struct task_struct *tsk)
{
	struct io_submit_state *submit_state = &ctx->submit_state;

	mutex_lock(&ctx->uring_lock);

	if (submit_state->free_reqs)
		kmem_cache_free_bulk(req_cachep, submit_state->free_reqs,
				     submit_state->reqs);

	io_req_cache_free(&submit_state->comp.free_list, NULL);

	spin_lock_irq(&ctx->completion_lock);
	io_req_cache_free(&submit_state->comp.locked_free_list, NULL);
	spin_unlock_irq(&ctx->completion_lock);

	mutex_unlock(&ctx->uring_lock);
}

static void io_ring_ctx_free(struct io_ring_ctx *ctx)
{
	/*
	 * Some may use context even when all refs and requests have been put,
	 * and they are free to do so while still holding uring_lock, see
	 * __io_req_task_submit(). Wait for them to finish.
	 */
	mutex_lock(&ctx->uring_lock);
	mutex_unlock(&ctx->uring_lock);

	io_finish_async(ctx);
	io_sqe_buffers_unregister(ctx);

	if (ctx->sqo_task) {
		put_task_struct(ctx->sqo_task);
		ctx->sqo_task = NULL;
		mmdrop(ctx->mm_account);
		ctx->mm_account = NULL;
	}

#ifdef CONFIG_BLK_CGROUP
	if (ctx->sqo_blkcg_css)
		css_put(ctx->sqo_blkcg_css);
#endif

	io_sqe_files_unregister(ctx);
	io_eventfd_unregister(ctx);
	io_destroy_buffers(ctx);
	idr_destroy(&ctx->personality_idr);

#if defined(CONFIG_UNIX)
	if (ctx->ring_sock) {
		ctx->ring_sock->file = NULL; /* so that iput() is called */
		sock_release(ctx->ring_sock);
	}
#endif

	io_mem_free(ctx->rings);
	io_mem_free(ctx->sq_sqes);

	percpu_ref_exit(&ctx->refs);
	free_uid(ctx->user);
	put_cred(ctx->creds);
	io_req_caches_free(ctx, NULL);
	kfree(ctx->cancel_hash);
	kfree(ctx);
}

static __poll_t io_uring_poll(struct file *file, poll_table *wait)
{
	struct io_ring_ctx *ctx = file->private_data;
	__poll_t mask = 0;

	poll_wait(file, &ctx->cq_wait, wait);
	/*
	 * synchronizes with barrier from wq_has_sleeper call in
	 * io_commit_cqring
	 */
	smp_rmb();
	if (!io_sqring_full(ctx))
		mask |= EPOLLOUT | EPOLLWRNORM;

	/*
	 * Don't flush cqring overflow list here, just do a simple check.
	 * Otherwise there could possible be ABBA deadlock:
	 *      CPU0                    CPU1
	 *      ----                    ----
	 * lock(&ctx->uring_lock);
	 *                              lock(&ep->mtx);
	 *                              lock(&ctx->uring_lock);
	 * lock(&ep->mtx);
	 *
	 * Users may get EPOLLIN meanwhile seeing nothing in cqring, this
	 * pushs them to do the flush.
	 */
	if (io_cqring_events(ctx) || test_bit(0, &ctx->cq_check_overflow))
		mask |= EPOLLIN | EPOLLRDNORM;

	return mask;
}

static int io_uring_fasync(int fd, struct file *file, int on)
{
	struct io_ring_ctx *ctx = file->private_data;

	return fasync_helper(fd, file, on, &ctx->cq_fasync);
}

static int io_unregister_personality(struct io_ring_ctx *ctx, unsigned id)
{
	struct io_identity *iod;

	iod = idr_remove(&ctx->personality_idr, id);
	if (iod) {
		put_cred(iod->creds);
		if (refcount_dec_and_test(&iod->count))
			kfree(iod);
		return 0;
	}

	return -EINVAL;
}

static int io_remove_personalities(int id, void *p, void *data)
{
	struct io_ring_ctx *ctx = data;

	io_unregister_personality(ctx, id);
	return 0;
}

static void io_ring_exit_work(struct work_struct *work)
{
	struct io_ring_ctx *ctx = container_of(work, struct io_ring_ctx,
					       exit_work);

	/*
	 * If we're doing polled IO and end up having requests being
	 * submitted async (out-of-line), then completions can come in while
	 * we're waiting for refs to drop. We need to reap these manually,
	 * as nobody else will be looking for them.
	 */
	do {
		io_uring_try_cancel_requests(ctx, NULL, NULL);
	} while (!wait_for_completion_timeout(&ctx->ref_comp, HZ/20));
	io_ring_ctx_free(ctx);
}

static bool io_cancel_ctx_cb(struct io_wq_work *work, void *data)
{
	struct io_kiocb *req = container_of(work, struct io_kiocb, work);

	return req->ctx == data;
}

static void io_ring_ctx_wait_and_kill(struct io_ring_ctx *ctx)
{
	mutex_lock(&ctx->uring_lock);
	percpu_ref_kill(&ctx->refs);

	if (WARN_ON_ONCE((ctx->flags & IORING_SETUP_SQPOLL) && !ctx->sqo_dead))
		ctx->sqo_dead = 1;

	/* if force is set, the ring is going away. always drop after that */
	ctx->cq_overflow_flushed = 1;
	if (ctx->rings)
		__io_cqring_overflow_flush(ctx, true, NULL, NULL);
	idr_for_each(&ctx->personality_idr, io_remove_personalities, ctx);
	mutex_unlock(&ctx->uring_lock);

	io_kill_timeouts(ctx, NULL, NULL);
	io_poll_remove_all(ctx, NULL, NULL);

	if (ctx->io_wq)
		io_wq_cancel_cb(ctx->io_wq, io_cancel_ctx_cb, ctx, true);

	/* if we failed setting up the ctx, we might not have any rings */
	io_iopoll_try_reap_events(ctx);

	INIT_WORK(&ctx->exit_work, io_ring_exit_work);
	/*
	 * Use system_unbound_wq to avoid spawning tons of event kworkers
	 * if we're exiting a ton of rings at the same time. It just adds
	 * noise and overhead, there's no discernable change in runtime
	 * over using system_wq.
	 */
	queue_work(system_unbound_wq, &ctx->exit_work);
}

static int io_uring_release(struct inode *inode, struct file *file)
{
	struct io_ring_ctx *ctx = file->private_data;

	file->private_data = NULL;
	io_ring_ctx_wait_and_kill(ctx);
	return 0;
}

struct io_task_cancel {
	struct task_struct *task;
	struct files_struct *files;
};

static bool io_cancel_task_cb(struct io_wq_work *work, void *data)
{
	struct io_kiocb *req = container_of(work, struct io_kiocb, work);
	struct io_task_cancel *cancel = data;
	bool ret;

	if (cancel->files && (req->flags & REQ_F_LINK_TIMEOUT)) {
		unsigned long flags;
		struct io_ring_ctx *ctx = req->ctx;

		/* protect against races with linked timeouts */
		spin_lock_irqsave(&ctx->completion_lock, flags);
		ret = io_match_task(req, cancel->task, cancel->files);
		spin_unlock_irqrestore(&ctx->completion_lock, flags);
	} else {
		ret = io_match_task(req, cancel->task, cancel->files);
	}
	return ret;
}

static void io_cancel_defer_files(struct io_ring_ctx *ctx,
				  struct task_struct *task,
				  struct files_struct *files)
{
	struct io_defer_entry *de = NULL;
	LIST_HEAD(list);

	spin_lock_irq(&ctx->completion_lock);
	list_for_each_entry_reverse(de, &ctx->defer_list, list) {
		if (io_match_task(de->req, task, files)) {
			list_cut_position(&list, &ctx->defer_list, &de->list);
			break;
		}
	}
	spin_unlock_irq(&ctx->completion_lock);

	while (!list_empty(&list)) {
		de = list_first_entry(&list, struct io_defer_entry, list);
		list_del_init(&de->list);
		req_set_fail_links(de->req);
		io_put_req(de->req);
		io_req_complete(de->req, -ECANCELED);
		kfree(de);
	}
}

static void io_uring_try_cancel_requests(struct io_ring_ctx *ctx,
					 struct task_struct *task,
					 struct files_struct *files)
{
	struct io_task_cancel cancel = { .task = task, .files = files, };

	while (1) {
		enum io_wq_cancel cret;
		bool ret = false;

		if (ctx->io_wq) {
			cret = io_wq_cancel_cb(ctx->io_wq, io_cancel_task_cb,
					       &cancel, true);
			ret |= (cret != IO_WQ_CANCEL_NOTFOUND);
		}

		/* SQPOLL thread does its own polling */
		if (!(ctx->flags & IORING_SETUP_SQPOLL) && !files) {
			while (!list_empty_careful(&ctx->iopoll_list)) {
				io_iopoll_try_reap_events(ctx);
				ret = true;
			}
		}

		ret |= io_poll_remove_all(ctx, task, files);
		ret |= io_kill_timeouts(ctx, task, files);
		ret |= io_run_task_work();
		io_cqring_overflow_flush(ctx, true, task, files);
		if (!ret)
			break;
		cond_resched();
	}
}

static int io_uring_count_inflight(struct io_ring_ctx *ctx,
				   struct task_struct *task,
				   struct files_struct *files)
{
	struct io_kiocb *req;
	int cnt = 0;

	spin_lock_irq(&ctx->inflight_lock);
	list_for_each_entry(req, &ctx->inflight_list, inflight_entry)
		cnt += io_match_task(req, task, files);
	spin_unlock_irq(&ctx->inflight_lock);
	return cnt;
}

static void io_uring_cancel_files(struct io_ring_ctx *ctx,
				  struct task_struct *task,
				  struct files_struct *files)
{
	while (!list_empty_careful(&ctx->inflight_list)) {
		DEFINE_WAIT(wait);
		int inflight;

		inflight = io_uring_count_inflight(ctx, task, files);
		if (!inflight)
			break;

		io_uring_try_cancel_requests(ctx, task, files);

		if (ctx->sq_data)
			io_sq_thread_unpark(ctx->sq_data);
		prepare_to_wait(&task->io_uring->wait, &wait,
				TASK_UNINTERRUPTIBLE);
		if (inflight == io_uring_count_inflight(ctx, task, files))
			schedule();
		finish_wait(&task->io_uring->wait, &wait);
		if (ctx->sq_data)
			io_sq_thread_park(ctx->sq_data);
	}
}

static void io_disable_sqo_submit(struct io_ring_ctx *ctx)
{
	mutex_lock(&ctx->uring_lock);
	ctx->sqo_dead = 1;
	mutex_unlock(&ctx->uring_lock);

	/* make sure callers enter the ring to get error */
	if (ctx->rings)
		io_ring_set_wakeup_flag(ctx);
}

/*
 * We need to iteratively cancel requests, in case a request has dependent
 * hard links. These persist even for failure of cancelations, hence keep
 * looping until none are found.
 */
static void io_uring_cancel_task_requests(struct io_ring_ctx *ctx,
					  struct files_struct *files)
{
	struct task_struct *task = current;

	if ((ctx->flags & IORING_SETUP_SQPOLL) && ctx->sq_data) {
		io_disable_sqo_submit(ctx);
		task = ctx->sq_data->thread;
		atomic_inc(&task->io_uring->in_idle);
		io_sq_thread_park(ctx->sq_data);
	}

	io_cancel_defer_files(ctx, task, files);

	io_uring_cancel_files(ctx, task, files);
	if (!files)
		io_uring_try_cancel_requests(ctx, task, NULL);

	if ((ctx->flags & IORING_SETUP_SQPOLL) && ctx->sq_data) {
		atomic_dec(&task->io_uring->in_idle);
		io_sq_thread_unpark(ctx->sq_data);
	}
}

/*
 * Note that this task has used io_uring. We use it for cancelation purposes.
 */
static int io_uring_add_task_file(struct io_ring_ctx *ctx, struct file *file)
{
	struct io_uring_task *tctx = current->io_uring;
	int ret;

	if (unlikely(!tctx)) {
		ret = io_uring_alloc_task_context(current);
		if (unlikely(ret))
			return ret;
		tctx = current->io_uring;
	}
	if (tctx->last != file) {
		void *old = xa_load(&tctx->xa, (unsigned long)file);

		if (!old) {
			get_file(file);
			ret = xa_err(xa_store(&tctx->xa, (unsigned long)file,
						file, GFP_KERNEL));
			if (ret) {
				fput(file);
				return ret;
			}

			/* one and only SQPOLL file note, held by sqo_task */
			WARN_ON_ONCE((ctx->flags & IORING_SETUP_SQPOLL) &&
				     current != ctx->sqo_task);
		}
		tctx->last = file;
	}

	/*
	 * This is race safe in that the task itself is doing this, hence it
	 * cannot be going through the exit/cancel paths at the same time.
	 * This cannot be modified while exit/cancel is running.
	 */
	if (!tctx->sqpoll && (ctx->flags & IORING_SETUP_SQPOLL))
		tctx->sqpoll = true;

	return 0;
}

/*
 * Remove this io_uring_file -> task mapping.
 */
static void io_uring_del_task_file(struct file *file)
{
	struct io_uring_task *tctx = current->io_uring;

	if (tctx->last == file)
		tctx->last = NULL;
	file = xa_erase(&tctx->xa, (unsigned long)file);
	if (file)
		fput(file);
}

static void io_uring_remove_task_files(struct io_uring_task *tctx)
{
	struct file *file;
	unsigned long index;

	xa_for_each(&tctx->xa, index, file)
		io_uring_del_task_file(file);
}

void __io_uring_files_cancel(struct files_struct *files)
{
	struct io_uring_task *tctx = current->io_uring;
	struct file *file;
	unsigned long index;

	/* make sure overflow events are dropped */
	atomic_inc(&tctx->in_idle);
	xa_for_each(&tctx->xa, index, file)
		io_uring_cancel_task_requests(file->private_data, files);
	atomic_dec(&tctx->in_idle);

	if (files)
		io_uring_remove_task_files(tctx);
}

static s64 tctx_inflight(struct io_uring_task *tctx)
{
	return percpu_counter_sum(&tctx->inflight);
}

static void io_uring_cancel_sqpoll(struct io_ring_ctx *ctx)
{
	struct io_uring_task *tctx;
	s64 inflight;
	DEFINE_WAIT(wait);

	if (!ctx->sq_data)
		return;
	tctx = ctx->sq_data->thread->io_uring;
	io_disable_sqo_submit(ctx);

	atomic_inc(&tctx->in_idle);
	do {
		/* read completions before cancelations */
		inflight = tctx_inflight(tctx);
		if (!inflight)
			break;
		io_uring_cancel_task_requests(ctx, NULL);

		prepare_to_wait(&tctx->wait, &wait, TASK_UNINTERRUPTIBLE);
		/*
		 * If we've seen completions, retry without waiting. This
		 * avoids a race where a completion comes in before we did
		 * prepare_to_wait().
		 */
		if (inflight == tctx_inflight(tctx))
			schedule();
		finish_wait(&tctx->wait, &wait);
	} while (1);
	atomic_dec(&tctx->in_idle);
}

/*
 * Find any io_uring fd that this task has registered or done IO on, and cancel
 * requests.
 */
void __io_uring_task_cancel(void)
{
	struct io_uring_task *tctx = current->io_uring;
	DEFINE_WAIT(wait);
	s64 inflight;

	/* make sure overflow events are dropped */
	atomic_inc(&tctx->in_idle);

	/* trigger io_disable_sqo_submit() */
	if (tctx->sqpoll) {
		struct file *file;
		unsigned long index;

		xa_for_each(&tctx->xa, index, file)
			io_uring_cancel_sqpoll(file->private_data);
	}

	do {
		/* read completions before cancelations */
		inflight = tctx_inflight(tctx);
		if (!inflight)
			break;
		__io_uring_files_cancel(NULL);

		prepare_to_wait(&tctx->wait, &wait, TASK_UNINTERRUPTIBLE);

		/*
		 * If we've seen completions, retry without waiting. This
		 * avoids a race where a completion comes in before we did
		 * prepare_to_wait().
		 */
		if (inflight == tctx_inflight(tctx))
			schedule();
		finish_wait(&tctx->wait, &wait);
	} while (1);

	atomic_dec(&tctx->in_idle);

	io_uring_remove_task_files(tctx);
}

static int io_uring_flush(struct file *file, void *data)
{
	struct io_uring_task *tctx = current->io_uring;
	struct io_ring_ctx *ctx = file->private_data;

	if (fatal_signal_pending(current) || (current->flags & PF_EXITING)) {
		io_uring_cancel_task_requests(ctx, NULL);
		io_req_caches_free(ctx, current);
	}

	if (!tctx)
		return 0;

	/* we should have cancelled and erased it before PF_EXITING */
	WARN_ON_ONCE((current->flags & PF_EXITING) &&
		     xa_load(&tctx->xa, (unsigned long)file));

	/*
	 * fput() is pending, will be 2 if the only other ref is our potential
	 * task file note. If the task is exiting, drop regardless of count.
	 */
	if (atomic_long_read(&file->f_count) != 2)
		return 0;

	if (ctx->flags & IORING_SETUP_SQPOLL) {
		/* there is only one file note, which is owned by sqo_task */
		WARN_ON_ONCE(ctx->sqo_task != current &&
			     xa_load(&tctx->xa, (unsigned long)file));
		/* sqo_dead check is for when this happens after cancellation */
		WARN_ON_ONCE(ctx->sqo_task == current && !ctx->sqo_dead &&
			     !xa_load(&tctx->xa, (unsigned long)file));

		io_disable_sqo_submit(ctx);
	}

	if (!(ctx->flags & IORING_SETUP_SQPOLL) || ctx->sqo_task == current)
		io_uring_del_task_file(file);
	return 0;
}

static void *io_uring_validate_mmap_request(struct file *file,
					    loff_t pgoff, size_t sz)
{
	struct io_ring_ctx *ctx = file->private_data;
	loff_t offset = pgoff << PAGE_SHIFT;
	struct page *page;
	void *ptr;

	switch (offset) {
	case IORING_OFF_SQ_RING:
	case IORING_OFF_CQ_RING:
		ptr = ctx->rings;
		break;
	case IORING_OFF_SQES:
		ptr = ctx->sq_sqes;
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	page = virt_to_head_page(ptr);
	if (sz > page_size(page))
		return ERR_PTR(-EINVAL);

	return ptr;
}

#ifdef CONFIG_MMU

static int io_uring_mmap(struct file *file, struct vm_area_struct *vma)
{
	size_t sz = vma->vm_end - vma->vm_start;
	unsigned long pfn;
	void *ptr;

	ptr = io_uring_validate_mmap_request(file, vma->vm_pgoff, sz);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	pfn = virt_to_phys(ptr) >> PAGE_SHIFT;
	return remap_pfn_range(vma, vma->vm_start, pfn, sz, vma->vm_page_prot);
}

#else /* !CONFIG_MMU */

static int io_uring_mmap(struct file *file, struct vm_area_struct *vma)
{
	return vma->vm_flags & (VM_SHARED | VM_MAYSHARE) ? 0 : -EINVAL;
}

static unsigned int io_uring_nommu_mmap_capabilities(struct file *file)
{
	return NOMMU_MAP_DIRECT | NOMMU_MAP_READ | NOMMU_MAP_WRITE;
}

static unsigned long io_uring_nommu_get_unmapped_area(struct file *file,
	unsigned long addr, unsigned long len,
	unsigned long pgoff, unsigned long flags)
{
	void *ptr;

	ptr = io_uring_validate_mmap_request(file, pgoff, len);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	return (unsigned long) ptr;
}

#endif /* !CONFIG_MMU */

static int io_sqpoll_wait_sq(struct io_ring_ctx *ctx)
{
	int ret = 0;
	DEFINE_WAIT(wait);

	do {
		if (!io_sqring_full(ctx))
			break;

		prepare_to_wait(&ctx->sqo_sq_wait, &wait, TASK_INTERRUPTIBLE);

		if (unlikely(ctx->sqo_dead)) {
			ret = -EOWNERDEAD;
			goto out;
		}

		if (!io_sqring_full(ctx))
			break;

		schedule();
	} while (!signal_pending(current));

	finish_wait(&ctx->sqo_sq_wait, &wait);
out:
	return ret;
}

static int io_get_ext_arg(unsigned flags, const void __user *argp, size_t *argsz,
			  struct __kernel_timespec __user **ts,
			  const sigset_t __user **sig)
{
	struct io_uring_getevents_arg arg;

	/*
	 * If EXT_ARG isn't set, then we have no timespec and the argp pointer
	 * is just a pointer to the sigset_t.
	 */
	if (!(flags & IORING_ENTER_EXT_ARG)) {
		*sig = (const sigset_t __user *) argp;
		*ts = NULL;
		return 0;
	}

	/*
	 * EXT_ARG is set - ensure we agree on the size of it and copy in our
	 * timespec and sigset_t pointers if good.
	 */
	if (*argsz != sizeof(arg))
		return -EINVAL;
	if (copy_from_user(&arg, argp, sizeof(arg)))
		return -EFAULT;
	*sig = u64_to_user_ptr(arg.sigmask);
	*argsz = arg.sigmask_sz;
	*ts = u64_to_user_ptr(arg.ts);
	return 0;
}

SYSCALL_DEFINE6(io_uring_enter, unsigned int, fd, u32, to_submit,
		u32, min_complete, u32, flags, const void __user *, argp,
		size_t, argsz)
{
	struct io_ring_ctx *ctx;
	long ret = -EBADF;
	int submitted = 0;
	struct fd f;

	io_run_task_work();

	if (flags & ~(IORING_ENTER_GETEVENTS | IORING_ENTER_SQ_WAKEUP |
			IORING_ENTER_SQ_WAIT | IORING_ENTER_EXT_ARG))
		return -EINVAL;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	ret = -EOPNOTSUPP;
	if (f.file->f_op != &io_uring_fops)
		goto out_fput;

	ret = -ENXIO;
	ctx = f.file->private_data;
	if (!percpu_ref_tryget(&ctx->refs))
		goto out_fput;

	ret = -EBADFD;
	if (ctx->flags & IORING_SETUP_R_DISABLED)
		goto out;

	/*
	 * For SQ polling, the thread will do all submissions and completions.
	 * Just return the requested submit count, and wake the thread if
	 * we were asked to.
	 */
	ret = 0;
	if (ctx->flags & IORING_SETUP_SQPOLL) {
		io_cqring_overflow_flush(ctx, false, NULL, NULL);

		ret = -EOWNERDEAD;
		if (unlikely(ctx->sqo_dead))
			goto out;
		if (flags & IORING_ENTER_SQ_WAKEUP)
			wake_up(&ctx->sq_data->wait);
		if (flags & IORING_ENTER_SQ_WAIT) {
			ret = io_sqpoll_wait_sq(ctx);
			if (ret)
				goto out;
		}
		submitted = to_submit;
	} else if (to_submit) {
		ret = io_uring_add_task_file(ctx, f.file);
		if (unlikely(ret))
			goto out;
		mutex_lock(&ctx->uring_lock);
		submitted = io_submit_sqes(ctx, to_submit);
		mutex_unlock(&ctx->uring_lock);

		if (submitted != to_submit)
			goto out;
	}
	if (flags & IORING_ENTER_GETEVENTS) {
		const sigset_t __user *sig;
		struct __kernel_timespec __user *ts;

		ret = io_get_ext_arg(flags, argp, &argsz, &ts, &sig);
		if (unlikely(ret))
			goto out;

		min_complete = min(min_complete, ctx->cq_entries);

		/*
		 * When SETUP_IOPOLL and SETUP_SQPOLL are both enabled, user
		 * space applications don't need to do io completion events
		 * polling again, they can rely on io_sq_thread to do polling
		 * work, which can reduce cpu usage and uring_lock contention.
		 */
		if (ctx->flags & IORING_SETUP_IOPOLL &&
		    !(ctx->flags & IORING_SETUP_SQPOLL)) {
			ret = io_iopoll_check(ctx, min_complete);
		} else {
			ret = io_cqring_wait(ctx, min_complete, sig, argsz, ts);
		}
	}

out:
	percpu_ref_put(&ctx->refs);
out_fput:
	fdput(f);
	return submitted ? submitted : ret;
}

#ifdef CONFIG_PROC_FS
static int io_uring_show_cred(int id, void *p, void *data)
{
	struct io_identity *iod = p;
	const struct cred *cred = iod->creds;
	struct seq_file *m = data;
	struct user_namespace *uns = seq_user_ns(m);
	struct group_info *gi;
	kernel_cap_t cap;
	unsigned __capi;
	int g;

	seq_printf(m, "%5d\n", id);
	seq_put_decimal_ull(m, "\tUid:\t", from_kuid_munged(uns, cred->uid));
	seq_put_decimal_ull(m, "\t\t", from_kuid_munged(uns, cred->euid));
	seq_put_decimal_ull(m, "\t\t", from_kuid_munged(uns, cred->suid));
	seq_put_decimal_ull(m, "\t\t", from_kuid_munged(uns, cred->fsuid));
	seq_put_decimal_ull(m, "\n\tGid:\t", from_kgid_munged(uns, cred->gid));
	seq_put_decimal_ull(m, "\t\t", from_kgid_munged(uns, cred->egid));
	seq_put_decimal_ull(m, "\t\t", from_kgid_munged(uns, cred->sgid));
	seq_put_decimal_ull(m, "\t\t", from_kgid_munged(uns, cred->fsgid));
	seq_puts(m, "\n\tGroups:\t");
	gi = cred->group_info;
	for (g = 0; g < gi->ngroups; g++) {
		seq_put_decimal_ull(m, g ? " " : "",
					from_kgid_munged(uns, gi->gid[g]));
	}
	seq_puts(m, "\n\tCapEff:\t");
	cap = cred->cap_effective;
	CAP_FOR_EACH_U32(__capi)
		seq_put_hex_ll(m, NULL, cap.cap[CAP_LAST_U32 - __capi], 8);
	seq_putc(m, '\n');
	return 0;
}

static void __io_uring_show_fdinfo(struct io_ring_ctx *ctx, struct seq_file *m)
{
	struct io_sq_data *sq = NULL;
	bool has_lock;
	int i;

	/*
	 * Avoid ABBA deadlock between the seq lock and the io_uring mutex,
	 * since fdinfo case grabs it in the opposite direction of normal use
	 * cases. If we fail to get the lock, we just don't iterate any
	 * structures that could be going away outside the io_uring mutex.
	 */
	has_lock = mutex_trylock(&ctx->uring_lock);

	if (has_lock && (ctx->flags & IORING_SETUP_SQPOLL))
		sq = ctx->sq_data;

	seq_printf(m, "SqThread:\t%d\n", sq ? task_pid_nr(sq->thread) : -1);
	seq_printf(m, "SqThreadCpu:\t%d\n", sq ? task_cpu(sq->thread) : -1);
	seq_printf(m, "UserFiles:\t%u\n", ctx->nr_user_files);
	for (i = 0; has_lock && i < ctx->nr_user_files; i++) {
		struct file *f = *io_fixed_file_slot(ctx->file_data, i);

		if (f)
			seq_printf(m, "%5u: %s\n", i, file_dentry(f)->d_iname);
		else
			seq_printf(m, "%5u: <none>\n", i);
	}
	seq_printf(m, "UserBufs:\t%u\n", ctx->nr_user_bufs);
	for (i = 0; has_lock && i < ctx->nr_user_bufs; i++) {
		struct io_mapped_ubuf *buf = &ctx->user_bufs[i];

		seq_printf(m, "%5u: 0x%llx/%u\n", i, buf->ubuf,
						(unsigned int) buf->len);
	}
	if (has_lock && !idr_is_empty(&ctx->personality_idr)) {
		seq_printf(m, "Personalities:\n");
		idr_for_each(&ctx->personality_idr, io_uring_show_cred, m);
	}
	seq_printf(m, "PollList:\n");
	spin_lock_irq(&ctx->completion_lock);
	for (i = 0; i < (1U << ctx->cancel_hash_bits); i++) {
		struct hlist_head *list = &ctx->cancel_hash[i];
		struct io_kiocb *req;

		hlist_for_each_entry(req, list, hash_node)
			seq_printf(m, "  op=%d, task_works=%d\n", req->opcode,
					req->task->task_works != NULL);
	}
	spin_unlock_irq(&ctx->completion_lock);
	if (has_lock)
		mutex_unlock(&ctx->uring_lock);
}

static void io_uring_show_fdinfo(struct seq_file *m, struct file *f)
{
	struct io_ring_ctx *ctx = f->private_data;

	if (percpu_ref_tryget(&ctx->refs)) {
		__io_uring_show_fdinfo(ctx, m);
		percpu_ref_put(&ctx->refs);
	}
}
#endif

static const struct file_operations io_uring_fops = {
	.release	= io_uring_release,
	.flush		= io_uring_flush,
	.mmap		= io_uring_mmap,
#ifndef CONFIG_MMU
	.get_unmapped_area = io_uring_nommu_get_unmapped_area,
	.mmap_capabilities = io_uring_nommu_mmap_capabilities,
#endif
	.poll		= io_uring_poll,
	.fasync		= io_uring_fasync,
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= io_uring_show_fdinfo,
#endif
};

static int io_allocate_scq_urings(struct io_ring_ctx *ctx,
				  struct io_uring_params *p)
{
	struct io_rings *rings;
	size_t size, sq_array_offset;

	/* make sure these are sane, as we already accounted them */
	ctx->sq_entries = p->sq_entries;
	ctx->cq_entries = p->cq_entries;

	size = rings_size(p->sq_entries, p->cq_entries, &sq_array_offset);
	if (size == SIZE_MAX)
		return -EOVERFLOW;

	rings = io_mem_alloc(size);
	if (!rings)
		return -ENOMEM;

	ctx->rings = rings;
	ctx->sq_array = (u32 *)((char *)rings + sq_array_offset);
	rings->sq_ring_mask = p->sq_entries - 1;
	rings->cq_ring_mask = p->cq_entries - 1;
	rings->sq_ring_entries = p->sq_entries;
	rings->cq_ring_entries = p->cq_entries;
	ctx->sq_mask = rings->sq_ring_mask;
	ctx->cq_mask = rings->cq_ring_mask;

	size = array_size(sizeof(struct io_uring_sqe), p->sq_entries);
	if (size == SIZE_MAX) {
		io_mem_free(ctx->rings);
		ctx->rings = NULL;
		return -EOVERFLOW;
	}

	ctx->sq_sqes = io_mem_alloc(size);
	if (!ctx->sq_sqes) {
		io_mem_free(ctx->rings);
		ctx->rings = NULL;
		return -ENOMEM;
	}

	return 0;
}

static int io_uring_install_fd(struct io_ring_ctx *ctx, struct file *file)
{
	int ret, fd;

	fd = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return fd;

	ret = io_uring_add_task_file(ctx, file);
	if (ret) {
		put_unused_fd(fd);
		return ret;
	}
	fd_install(fd, file);
	return fd;
}

/*
 * Allocate an anonymous fd, this is what constitutes the application
 * visible backing of an io_uring instance. The application mmaps this
 * fd to gain access to the SQ/CQ ring details. If UNIX sockets are enabled,
 * we have to tie this fd to a socket for file garbage collection purposes.
 */
static struct file *io_uring_get_file(struct io_ring_ctx *ctx)
{
	struct file *file;
#if defined(CONFIG_UNIX)
	int ret;

	ret = sock_create_kern(&init_net, PF_UNIX, SOCK_RAW, IPPROTO_IP,
				&ctx->ring_sock);
	if (ret)
		return ERR_PTR(ret);
#endif

	file = anon_inode_getfile("[io_uring]", &io_uring_fops, ctx,
					O_RDWR | O_CLOEXEC);
#if defined(CONFIG_UNIX)
	if (IS_ERR(file)) {
		sock_release(ctx->ring_sock);
		ctx->ring_sock = NULL;
	} else {
		ctx->ring_sock->file = file;
	}
#endif
	return file;
}

static int io_uring_create(unsigned entries, struct io_uring_params *p,
			   struct io_uring_params __user *params)
{
	struct user_struct *user = NULL;
	struct io_ring_ctx *ctx;
	struct file *file;
	int ret;

	if (!entries)
		return -EINVAL;
	if (entries > IORING_MAX_ENTRIES) {
		if (!(p->flags & IORING_SETUP_CLAMP))
			return -EINVAL;
		entries = IORING_MAX_ENTRIES;
	}

	/*
	 * Use twice as many entries for the CQ ring. It's possible for the
	 * application to drive a higher depth than the size of the SQ ring,
	 * since the sqes are only used at submission time. This allows for
	 * some flexibility in overcommitting a bit. If the application has
	 * set IORING_SETUP_CQSIZE, it will have passed in the desired number
	 * of CQ ring entries manually.
	 */
	p->sq_entries = roundup_pow_of_two(entries);
	if (p->flags & IORING_SETUP_CQSIZE) {
		/*
		 * If IORING_SETUP_CQSIZE is set, we do the same roundup
		 * to a power-of-two, if it isn't already. We do NOT impose
		 * any cq vs sq ring sizing.
		 */
		if (!p->cq_entries)
			return -EINVAL;
		if (p->cq_entries > IORING_MAX_CQ_ENTRIES) {
			if (!(p->flags & IORING_SETUP_CLAMP))
				return -EINVAL;
			p->cq_entries = IORING_MAX_CQ_ENTRIES;
		}
		p->cq_entries = roundup_pow_of_two(p->cq_entries);
		if (p->cq_entries < p->sq_entries)
			return -EINVAL;
	} else {
		p->cq_entries = 2 * p->sq_entries;
	}

	user = get_uid(current_user());

	ctx = io_ring_ctx_alloc(p);
	if (!ctx) {
		free_uid(user);
		return -ENOMEM;
	}
	ctx->compat = in_compat_syscall();
	ctx->limit_mem = !capable(CAP_IPC_LOCK);
	ctx->user = user;
	ctx->creds = get_current_cred();
#ifdef CONFIG_AUDIT
	ctx->loginuid = current->loginuid;
	ctx->sessionid = current->sessionid;
#endif
	ctx->sqo_task = get_task_struct(current);

	/*
	 * This is just grabbed for accounting purposes. When a process exits,
	 * the mm is exited and dropped before the files, hence we need to hang
	 * on to this mm purely for the purposes of being able to unaccount
	 * memory (locked/pinned vm). It's not used for anything else.
	 */
	mmgrab(current->mm);
	ctx->mm_account = current->mm;

#ifdef CONFIG_BLK_CGROUP
	/*
	 * The sq thread will belong to the original cgroup it was inited in.
	 * If the cgroup goes offline (e.g. disabling the io controller), then
	 * issued bios will be associated with the closest cgroup later in the
	 * block layer.
	 */
	rcu_read_lock();
	ctx->sqo_blkcg_css = blkcg_css();
	ret = css_tryget_online(ctx->sqo_blkcg_css);
	rcu_read_unlock();
	if (!ret) {
		/* don't init against a dying cgroup, have the user try again */
		ctx->sqo_blkcg_css = NULL;
		ret = -ENODEV;
		goto err;
	}
#endif
	ret = io_allocate_scq_urings(ctx, p);
	if (ret)
		goto err;

	ret = io_sq_offload_create(ctx, p);
	if (ret)
		goto err;

	if (!(p->flags & IORING_SETUP_R_DISABLED))
		io_sq_offload_start(ctx);

	memset(&p->sq_off, 0, sizeof(p->sq_off));
	p->sq_off.head = offsetof(struct io_rings, sq.head);
	p->sq_off.tail = offsetof(struct io_rings, sq.tail);
	p->sq_off.ring_mask = offsetof(struct io_rings, sq_ring_mask);
	p->sq_off.ring_entries = offsetof(struct io_rings, sq_ring_entries);
	p->sq_off.flags = offsetof(struct io_rings, sq_flags);
	p->sq_off.dropped = offsetof(struct io_rings, sq_dropped);
	p->sq_off.array = (char *)ctx->sq_array - (char *)ctx->rings;

	memset(&p->cq_off, 0, sizeof(p->cq_off));
	p->cq_off.head = offsetof(struct io_rings, cq.head);
	p->cq_off.tail = offsetof(struct io_rings, cq.tail);
	p->cq_off.ring_mask = offsetof(struct io_rings, cq_ring_mask);
	p->cq_off.ring_entries = offsetof(struct io_rings, cq_ring_entries);
	p->cq_off.overflow = offsetof(struct io_rings, cq_overflow);
	p->cq_off.cqes = offsetof(struct io_rings, cqes);
	p->cq_off.flags = offsetof(struct io_rings, cq_flags);

	p->features = IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP |
			IORING_FEAT_SUBMIT_STABLE | IORING_FEAT_RW_CUR_POS |
			IORING_FEAT_CUR_PERSONALITY | IORING_FEAT_FAST_POLL |
			IORING_FEAT_POLL_32BITS | IORING_FEAT_SQPOLL_NONFIXED |
			IORING_FEAT_EXT_ARG;

	if (copy_to_user(params, p, sizeof(*p))) {
		ret = -EFAULT;
		goto err;
	}

	file = io_uring_get_file(ctx);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto err;
	}

	/*
	 * Install ring fd as the very last thing, so we don't risk someone
	 * having closed it before we finish setup
	 */
	ret = io_uring_install_fd(ctx, file);
	if (ret < 0) {
		io_disable_sqo_submit(ctx);
		/* fput will clean it up */
		fput(file);
		return ret;
	}

	trace_io_uring_create(ret, ctx, p->sq_entries, p->cq_entries, p->flags);
	return ret;
err:
	io_disable_sqo_submit(ctx);
	io_ring_ctx_wait_and_kill(ctx);
	return ret;
}

/*
 * Sets up an aio uring context, and returns the fd. Applications asks for a
 * ring size, we return the actual sq/cq ring sizes (among other things) in the
 * params structure passed in.
 */
static long io_uring_setup(u32 entries, struct io_uring_params __user *params)
{
	struct io_uring_params p;
	int i;

	if (copy_from_user(&p, params, sizeof(p)))
		return -EFAULT;
	for (i = 0; i < ARRAY_SIZE(p.resv); i++) {
		if (p.resv[i])
			return -EINVAL;
	}

	if (p.flags & ~(IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL |
			IORING_SETUP_SQ_AFF | IORING_SETUP_CQSIZE |
			IORING_SETUP_CLAMP | IORING_SETUP_ATTACH_WQ |
			IORING_SETUP_R_DISABLED))
		return -EINVAL;

	return  io_uring_create(entries, &p, params);
}

SYSCALL_DEFINE2(io_uring_setup, u32, entries,
		struct io_uring_params __user *, params)
{
	return io_uring_setup(entries, params);
}

static int io_probe(struct io_ring_ctx *ctx, void __user *arg, unsigned nr_args)
{
	struct io_uring_probe *p;
	size_t size;
	int i, ret;

	size = struct_size(p, ops, nr_args);
	if (size == SIZE_MAX)
		return -EOVERFLOW;
	p = kzalloc(size, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	ret = -EFAULT;
	if (copy_from_user(p, arg, size))
		goto out;
	ret = -EINVAL;
	if (memchr_inv(p, 0, size))
		goto out;

	p->last_op = IORING_OP_LAST - 1;
	if (nr_args > IORING_OP_LAST)
		nr_args = IORING_OP_LAST;

	for (i = 0; i < nr_args; i++) {
		p->ops[i].op = i;
		if (!io_op_defs[i].not_supported)
			p->ops[i].flags = IO_URING_OP_SUPPORTED;
	}
	p->ops_len = i;

	ret = 0;
	if (copy_to_user(arg, p, size))
		ret = -EFAULT;
out:
	kfree(p);
	return ret;
}

static int io_register_personality(struct io_ring_ctx *ctx)
{
	struct io_identity *id;
	int ret;

	id = kmalloc(sizeof(*id), GFP_KERNEL);
	if (unlikely(!id))
		return -ENOMEM;

	io_init_identity(id);
	id->creds = get_current_cred();

	ret = idr_alloc_cyclic(&ctx->personality_idr, id, 1, USHRT_MAX, GFP_KERNEL);
	if (ret < 0) {
		put_cred(id->creds);
		kfree(id);
	}
	return ret;
}

static int io_register_restrictions(struct io_ring_ctx *ctx, void __user *arg,
				    unsigned int nr_args)
{
	struct io_uring_restriction *res;
	size_t size;
	int i, ret;

	/* Restrictions allowed only if rings started disabled */
	if (!(ctx->flags & IORING_SETUP_R_DISABLED))
		return -EBADFD;

	/* We allow only a single restrictions registration */
	if (ctx->restrictions.registered)
		return -EBUSY;

	if (!arg || nr_args > IORING_MAX_RESTRICTIONS)
		return -EINVAL;

	size = array_size(nr_args, sizeof(*res));
	if (size == SIZE_MAX)
		return -EOVERFLOW;

	res = memdup_user(arg, size);
	if (IS_ERR(res))
		return PTR_ERR(res);

	ret = 0;

	for (i = 0; i < nr_args; i++) {
		switch (res[i].opcode) {
		case IORING_RESTRICTION_REGISTER_OP:
			if (res[i].register_op >= IORING_REGISTER_LAST) {
				ret = -EINVAL;
				goto out;
			}

			__set_bit(res[i].register_op,
				  ctx->restrictions.register_op);
			break;
		case IORING_RESTRICTION_SQE_OP:
			if (res[i].sqe_op >= IORING_OP_LAST) {
				ret = -EINVAL;
				goto out;
			}

			__set_bit(res[i].sqe_op, ctx->restrictions.sqe_op);
			break;
		case IORING_RESTRICTION_SQE_FLAGS_ALLOWED:
			ctx->restrictions.sqe_flags_allowed = res[i].sqe_flags;
			break;
		case IORING_RESTRICTION_SQE_FLAGS_REQUIRED:
			ctx->restrictions.sqe_flags_required = res[i].sqe_flags;
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
	}

out:
	/* Reset all restrictions if an error happened */
	if (ret != 0)
		memset(&ctx->restrictions, 0, sizeof(ctx->restrictions));
	else
		ctx->restrictions.registered = true;

	kfree(res);
	return ret;
}

static int io_register_enable_rings(struct io_ring_ctx *ctx)
{
	if (!(ctx->flags & IORING_SETUP_R_DISABLED))
		return -EBADFD;

	if (ctx->restrictions.registered)
		ctx->restricted = 1;

	ctx->flags &= ~IORING_SETUP_R_DISABLED;

	io_sq_offload_start(ctx);

	return 0;
}

static bool io_register_op_must_quiesce(int op)
{
	switch (op) {
	case IORING_UNREGISTER_FILES:
	case IORING_REGISTER_FILES_UPDATE:
	case IORING_REGISTER_PROBE:
	case IORING_REGISTER_PERSONALITY:
	case IORING_UNREGISTER_PERSONALITY:
		return false;
	default:
		return true;
	}
}

static int __io_uring_register(struct io_ring_ctx *ctx, unsigned opcode,
			       void __user *arg, unsigned nr_args)
	__releases(ctx->uring_lock)
	__acquires(ctx->uring_lock)
{
	int ret;

	/*
	 * We're inside the ring mutex, if the ref is already dying, then
	 * someone else killed the ctx or is already going through
	 * io_uring_register().
	 */
	if (percpu_ref_is_dying(&ctx->refs))
		return -ENXIO;

	if (io_register_op_must_quiesce(opcode)) {
		percpu_ref_kill(&ctx->refs);

		/*
		 * Drop uring mutex before waiting for references to exit. If
		 * another thread is currently inside io_uring_enter() it might
		 * need to grab the uring_lock to make progress. If we hold it
		 * here across the drain wait, then we can deadlock. It's safe
		 * to drop the mutex here, since no new references will come in
		 * after we've killed the percpu ref.
		 */
		mutex_unlock(&ctx->uring_lock);
		do {
			ret = wait_for_completion_interruptible(&ctx->ref_comp);
			if (!ret)
				break;
			ret = io_run_task_work_sig();
			if (ret < 0)
				break;
		} while (1);

		mutex_lock(&ctx->uring_lock);

		if (ret) {
			percpu_ref_resurrect(&ctx->refs);
			goto out_quiesce;
		}
	}

	if (ctx->restricted) {
		if (opcode >= IORING_REGISTER_LAST) {
			ret = -EINVAL;
			goto out;
		}

		if (!test_bit(opcode, ctx->restrictions.register_op)) {
			ret = -EACCES;
			goto out;
		}
	}

	switch (opcode) {
	case IORING_REGISTER_BUFFERS:
		ret = io_sqe_buffers_register(ctx, arg, nr_args);
		break;
	case IORING_UNREGISTER_BUFFERS:
		ret = -EINVAL;
		if (arg || nr_args)
			break;
		ret = io_sqe_buffers_unregister(ctx);
		break;
	case IORING_REGISTER_FILES:
		ret = io_sqe_files_register(ctx, arg, nr_args);
		break;
	case IORING_UNREGISTER_FILES:
		ret = -EINVAL;
		if (arg || nr_args)
			break;
		ret = io_sqe_files_unregister(ctx);
		break;
	case IORING_REGISTER_FILES_UPDATE:
		ret = io_sqe_files_update(ctx, arg, nr_args);
		break;
	case IORING_REGISTER_EVENTFD:
	case IORING_REGISTER_EVENTFD_ASYNC:
		ret = -EINVAL;
		if (nr_args != 1)
			break;
		ret = io_eventfd_register(ctx, arg);
		if (ret)
			break;
		if (opcode == IORING_REGISTER_EVENTFD_ASYNC)
			ctx->eventfd_async = 1;
		else
			ctx->eventfd_async = 0;
		break;
	case IORING_UNREGISTER_EVENTFD:
		ret = -EINVAL;
		if (arg || nr_args)
			break;
		ret = io_eventfd_unregister(ctx);
		break;
	case IORING_REGISTER_PROBE:
		ret = -EINVAL;
		if (!arg || nr_args > 256)
			break;
		ret = io_probe(ctx, arg, nr_args);
		break;
	case IORING_REGISTER_PERSONALITY:
		ret = -EINVAL;
		if (arg || nr_args)
			break;
		ret = io_register_personality(ctx);
		break;
	case IORING_UNREGISTER_PERSONALITY:
		ret = -EINVAL;
		if (arg)
			break;
		ret = io_unregister_personality(ctx, nr_args);
		break;
	case IORING_REGISTER_ENABLE_RINGS:
		ret = -EINVAL;
		if (arg || nr_args)
			break;
		ret = io_register_enable_rings(ctx);
		break;
	case IORING_REGISTER_RESTRICTIONS:
		ret = io_register_restrictions(ctx, arg, nr_args);
		break;
	default:
		ret = -EINVAL;
		break;
	}

out:
	if (io_register_op_must_quiesce(opcode)) {
		/* bring the ctx back to life */
		percpu_ref_reinit(&ctx->refs);
out_quiesce:
		reinit_completion(&ctx->ref_comp);
	}
	return ret;
}

SYSCALL_DEFINE4(io_uring_register, unsigned int, fd, unsigned int, opcode,
		void __user *, arg, unsigned int, nr_args)
{
	struct io_ring_ctx *ctx;
	long ret = -EBADF;
	struct fd f;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	ret = -EOPNOTSUPP;
	if (f.file->f_op != &io_uring_fops)
		goto out_fput;

	ctx = f.file->private_data;

	mutex_lock(&ctx->uring_lock);
	ret = __io_uring_register(ctx, opcode, arg, nr_args);
	mutex_unlock(&ctx->uring_lock);
	trace_io_uring_register(ctx, opcode, ctx->nr_user_files, ctx->nr_user_bufs,
							ctx->cq_ev_fd != NULL, ret);
out_fput:
	fdput(f);
	return ret;
}

static int __init io_uring_init(void)
{
#define __BUILD_BUG_VERIFY_ELEMENT(stype, eoffset, etype, ename) do { \
	BUILD_BUG_ON(offsetof(stype, ename) != eoffset); \
	BUILD_BUG_ON(sizeof(etype) != sizeof_field(stype, ename)); \
} while (0)

#define BUILD_BUG_SQE_ELEM(eoffset, etype, ename) \
	__BUILD_BUG_VERIFY_ELEMENT(struct io_uring_sqe, eoffset, etype, ename)
	BUILD_BUG_ON(sizeof(struct io_uring_sqe) != 64);
	BUILD_BUG_SQE_ELEM(0,  __u8,   opcode);
	BUILD_BUG_SQE_ELEM(1,  __u8,   flags);
	BUILD_BUG_SQE_ELEM(2,  __u16,  ioprio);
	BUILD_BUG_SQE_ELEM(4,  __s32,  fd);
	BUILD_BUG_SQE_ELEM(8,  __u64,  off);
	BUILD_BUG_SQE_ELEM(8,  __u64,  addr2);
	BUILD_BUG_SQE_ELEM(16, __u64,  addr);
	BUILD_BUG_SQE_ELEM(16, __u64,  splice_off_in);
	BUILD_BUG_SQE_ELEM(24, __u32,  len);
	BUILD_BUG_SQE_ELEM(28,     __kernel_rwf_t, rw_flags);
	BUILD_BUG_SQE_ELEM(28, /* compat */   int, rw_flags);
	BUILD_BUG_SQE_ELEM(28, /* compat */ __u32, rw_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  fsync_flags);
	BUILD_BUG_SQE_ELEM(28, /* compat */ __u16,  poll_events);
	BUILD_BUG_SQE_ELEM(28, __u32,  poll32_events);
	BUILD_BUG_SQE_ELEM(28, __u32,  sync_range_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  msg_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  timeout_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  accept_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  cancel_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  open_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  statx_flags);
	BUILD_BUG_SQE_ELEM(28, __u32,  fadvise_advice);
	BUILD_BUG_SQE_ELEM(28, __u32,  splice_flags);
	BUILD_BUG_SQE_ELEM(32, __u64,  user_data);
	BUILD_BUG_SQE_ELEM(40, __u16,  buf_index);
	BUILD_BUG_SQE_ELEM(42, __u16,  personality);
	BUILD_BUG_SQE_ELEM(44, __s32,  splice_fd_in);

	BUILD_BUG_ON(ARRAY_SIZE(io_op_defs) != IORING_OP_LAST);
	BUILD_BUG_ON(__REQ_F_LAST_BIT >= 8 * sizeof(int));
	req_cachep = KMEM_CACHE(io_kiocb, SLAB_HWCACHE_ALIGN | SLAB_PANIC |
				SLAB_ACCOUNT);
	return 0;
};
__initcall(io_uring_init);
