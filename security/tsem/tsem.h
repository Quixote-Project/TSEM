/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Copyright (C) 2023 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * This is the single include file that documents all of the externally
 * visible types and functions that are used by TSEM.  This file is
 * currently organized into four major sections: includes, definitions,
 * enumerations, structures and function declarations.
 *
 * Include files that are referenced by more than a single compilation
 * should be included in this file.  Includes that are needed to
 * satisfy compilation requirements for only a single file should be
 * included in the needing that include.
 */

#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <linux/wait.h>
#include <linux/kref.h>
#include <linux/lsm_hooks.h>
#include <linux/capability.h>
#include <crypto/hash.h>
#include <crypto/hash_info.h>
#include <net/af_unix.h>

/* The capability needed to manage TSEM. */
#define TSEM_CONTROL_CAPABILITY CAP_TRUST

/*
 * The number of 'slots' in the structure magazines that are used to
 * satisfy modeling of security events that are called in atomic context.
 */
#define TSEM_MAGAZINE_SIZE 8

/**
 * enum tsem_event_type - Ordinal value for a security event.
 * @TSEM_BPRM_SET_CREDS: Ordinal value for bprm_creds_for_exec.
 * @TSEM_GENERIC_EVENT: Ordinal value for a generically modeled event.
 * @TSEM_TASK_KILL: Ordinal value for task kill.
 * @....: Remainder follows with a similar naming format that has
 *        TSEM_ prep ended to the raw LSM security hook name.
 * @TSEM_EVENT_CNT: The final ordinal value is used to define the
 *		    length of the following arrays that are indexed
 *		    by the ordinal value of the hook:
 *
 * This enumeration is used to designate an ordinal value for each
 * security event, ie. LSM hook, that TSEM is implementing modeling
 * for.  This value is used to identify the hook that is either having
 * its event description being exported to an external Trusted Modeling
 * Agent (TMA) or modeled by the internal TMA implementation.
 *
 * The primary use of this enumeration is to conditionalize code paths
 * based on the security hook being processed and to index the
 * tsem_names array and the array that defines the action that is to
 * be taken in response to an event that generates a permissions
 * violation.
 */
enum tsem_event_type {
	TSEM_BPRM_SET_CREDS = 1,
	TSEM_GENERIC_EVENT,
	TSEM_TASK_KILL,
	TSEM_TASK_SETPGID,
	TSEM_TASK_GETPGID,
	TSEM_TASK_GETSID,
	TSEM_TASK_SETNICE,
	TSEM_TASK_SETIOPRIO,
	TSEM_TASK_GETIOPRIO,
	TSEM_TASK_PRLIMIT,
	TSEM_TASK_SETRLIMIT,
	TSEM_TASK_SETSCHEDULER,
	TSEM_TASK_GETSCHEDULER,
	TSEM_TASK_PRCTL,
	TSEM_FILE_OPEN,
	TSEM_MMAP_FILE,
	TSEM_FILE_IOCTL,
	TSEM_FILE_LOCK,
	TSEM_FILE_FCNTL,
	TSEM_FILE_RECEIVE,
	TSEM_UNIX_STREAM_CONNECT,
	TSEM_UNIX_MAY_SEND,
	TSEM_SOCKET_CREATE,
	TSEM_SOCKET_CONNECT,
	TSEM_SOCKET_BIND,
	TSEM_SOCKET_ACCEPT,
	TSEM_SOCKET_LISTEN,
	TSEM_SOCKET_SOCKETPAIR,
	TSEM_SOCKET_SENDMSG,
	TSEM_SOCKET_RECVMSG,
	TSEM_SOCKET_GETSOCKNAME,
	TSEM_SOCKET_GETPEERNAME,
	TSEM_SOCKET_SETSOCKOPT,
	TSEM_SOCKET_SHUTDOWN,
	TSEM_PTRACE_TRACEME,
	TSEM_KERNEL_MODULE_REQUEST,
	TSEM_KERNEL_LOAD_DATA,
	TSEM_KERNEL_READ_FILE,
	TSEM_SB_MOUNT,
	TSEM_SB_UMOUNT,
	TSEM_SB_REMOUNT,
	TSEM_SB_PIVOTROOT,
	TSEM_SB_STATFS,
	TSEM_MOVE_MOUNT,
	TSEM_SHM_ASSOCIATE,
	TSEM_SHM_SHMCTL,
	TSEM_SHM_SHMAT,
	TSEM_SEM_ASSOCIATE,
	TSEM_SEM_SEMCTL,
	TSEM_SEM_SEMOP,
	TSEM_SYSLOG,
	TSEM_SETTIME,
	TSEM_QUOTACTL,
	TSEM_QUOTA_ON,
	TSEM_MSG_QUEUE_ASSOCIATE,
	TSEM_MSG_QUEUE_MSGCTL,
	TSEM_MSG_QUEUE_MSGSND,
	TSEM_MSG_QUEUE_MSGRCV,
	TSEM_IPC_PERMISSION,
	TSEM_KEY_ALLOC,
	TSEM_KEY_PERMISSION,
	TSEM_NETLINK_SEND,
	TSEM_INODE_CREATE,
	TSEM_INODE_LINK,
	TSEM_INODE_UNLINK,
	TSEM_INODE_SYMLINK,
	TSEM_INODE_MKDIR,
	TSEM_INODE_RMDIR,
	TSEM_INODE_MKNOD,
	TSEM_INODE_RENAME,
	TSEM_INODE_SETATTR,
	TSEM_INODE_GETATTR,
	TSEM_INODE_SETXATTR,
	TSEM_INODE_GETXATTR,
	TSEM_INODE_LISTXATTR,
	TSEM_INODE_REMOVEXATTR,
	TSEM_INODE_KILLPRIV,
	TSEM_TUN_DEV_CREATE,
	TSEM_TUN_DEV_ATTACH_QUEUE,
	TSEM_TUN_DEV_ATTACH,
	TSEM_TUN_DEV_OPEN,
	TSEM_BPF,
	TSEM_BPF_MAP,
	TSEM_BPF_PROG,
	TSEM_EVENT_CNT
};

/**
 * enum tsem_action_type - Ordinal value for security responses.
 * @TSEM_ACTION_LOG: Ordinal value to indicate that a security event
 *		     that results in a model permissions violation
 *		     should be logged.
 * @TSEM_ACTION_EPERM: Ordinal value to indicate that a security event
 *		       generating a model permissions violation should
 *		       return -EPERM to the caller.
 *
 * This enumeration type is used to designate what type of action is
 * to be taken when the processing of a security event hook results in
 * a model violation.  The TSEM_ACTION_LOG and TSEM_ACTION_EPERM
 * translate into the classical concepts of logging or enforcing
 * actions used by other mandatory access control architectures.
 */
enum tsem_action_type {
	TSEM_ACTION_LOG = 0,
	TSEM_ACTION_EPERM,
	TSEM_ACTION_CNT
};

/**
 * enum tsem_control_type - Ordinal values for TSEM control actions.
 * @TSEM_CONTROL_INTERNAL: This ordinal value is set when the first
 *			   word of an argument string written to the
 *			   control file is the word 'internal'.  This
 *			   designates that the security namespace will
 *			   be modeled by the internal TMA.
 * @TSEM_CONTROL_EXTERNAL: This ordinal value is set when the first
 *			   word of an argument string written to the
 *			   control file is the word 'external'.  This
 *			   designates that the security namespace will
 *			   be model by an external TMA.
 * @TSEM_CONTROL_ENFORCE: This ordinal value is set when the word
 *			  'enforce' is written to the control file.
 *			  This indicates that model is to be placed
 *			  in 'enforcing' mode and security events that
 *			  result in model violations will return EPERM.
 * @TSEM_CONTROL_SEAL: This ordinal value is set when the word 'seal'
 *		       is written to the control file.  This indicates
 *		       that the model for security domain will treat
 *		       all security events that do not conform to the
 *		       model as 'forensics' events.
 * @TSEM_CONTROL_TRUSTED: This ordinal value is used when the first
 *			  word of an argument string written to the
 *			  control file is the word 'trusted'.  This
 *			  is interpreted as a directive to set the
 *			  trust status of the task that executed the
 *			  security event to be trusted.
 * @TSEM_CONTROL_UNTRUSTED: This ordinal value is used when the first
 *			    word of an argument string written to the
 *			    control file is the word 'untrusted'.
 *			    This is interpreted as a directive to set
 *			    the trust status of the task that executed
 *			    the security event to be untrusted.
 * @TSEM_CONTROL_MAP_STATE: This ordinal value is used when the first
 *			    word of an argument string written to the
 *			    control file is the word 'state'.  The
 *			    argument to this directive will be an
 *			    ASCII hexadecimally encoded string of the
 *			    current model's digest size that will be
 *			    treated as a security state point for
 *			    inclusion in the security model for the
 *			    security domain/namespace.
 * @TSEM_CONTROL_MAP_PSEUDONYM: This ordinal value is used when the
 *				first word of an argument string
 *				written to the control file is the
 *				word 'pseudonym'.  The argument to
 *				this directive will be an ASCII
 *				hexadecimally encoded string of the
 *				current model's digest size that will
 *				be treated as a pseudonym directive
 *				for the security domain/namespace.
 * TSEM_CONTROL_MAP_BASE: This ordinal value is used when the first
 *			  word of an argument string written to the
 *			  control file is the word 'base'.  The
 *			  argument to this directive will be an ASCII
 *			  hexadecimally encoded string of the current
 *			  model's digest size that will be treated as
 *			  the base value for the computation of the
 *			  functional values (measurement and state) of
 *			  the security domain/namespace.

 * This enumeration type is used to designate what type of control
 * action is to be implemented when arguments are written to the TSEM
 * control file (/sys/kernel/security/tsem/control).  The ordinal
 * values govern the processing of the command and the interpretation
 * of the rest of the command argument string.
 */
enum tsem_control_type {
	TSEM_CONTROL_INTERNAL = 0,
	TSEM_CONTROL_EXTERNAL,
	TSEM_CONTROL_ENFORCE,
	TSEM_CONTROL_SEAL,
	TSEM_CONTROL_TRUSTED,
	TSEM_CONTROL_UNTRUSTED,
	TSEM_CONTROL_MAP_STATE,
	TSEM_CONTROL_MAP_PSEUDONYM,
	TSEM_CONTROL_MAP_BASE
};

/**
 * enum tsem_ns_reference - Ordinal value for DAC namespace reference.
 * @TSEM_NS_INITIAL: This ordinal value indicates that the uid/gid
 *		     values should be interpreted against the initial
 *		     user namespace.
 * @TSEM_NS_CURRENT: This ordinal value indicates that the uid/gid
 *		     values should be interpreted against the user
 *		     namespace that is in effect for the process being
 *		     modeled.
 *
 * This enumeration type is used to indicate what user namespace
 * should be referenced when the uid/gid values are interpreted for
 * the creation of either the COE or CELL identities.  The enumeration
 * ordinal passed to the tsem_ns_create() function, to configure the
 * security domain/namespace, is set by the nsref argument to either
 * the 'internal' or 'external' control commands.
 */
enum tsem_ns_reference {
	TSEM_NS_INITIAL = 1,
	TSEM_NS_CURRENT
};

/**
 * enum tsem_task_trust - Ordinal value describing task trust status.
 * @TSEM_TASK_TRUSTED: This ordinal value indicates that the task has
 *		       not executed a security event that has resulted
 *		       in a security behavior not described by the
 *		       security model the task is being governed by.
 * @TSEM_TASK_UNTRUSTED: This ordinal value indicates that the task
 *		          has requested the execution of a security event
 *		          that resulted in a security behavior not
 *		          permitted by the security model the task is
 *		          being governed by.
 * @TSEM_TASK_TRUST_PENDING: This ordinal value indicates that the setting
 *			     of the task trust status is pending a response
 *		             from an external TMA.
 *
 * This enumeration type is used to specify the three different trust
 * states that a task can be in.  The trust status of a task is
 * regulated by the trust_status member of struct tsem_task.  A task
 * carrying the status of TSEM_TASK_TRUSTED means that it has
 * not requested the execution of any security events that are
 * inconsistent with the security model that the task is running in.
 *
 * If a task requests execution of a security event that is
 * inconsistent with the security model it is operating in, and the
 * domain is running in 'sealed' mode, the task trust status is set to
 * TSEM_TASK_UNTRUSTED.  This value is 'sticky' in that it will be
 * propagated to any child tasks that are spawned from an untrusted
 * task.
 *
 * In the case of an externally modeled security domain/namespace, the
 * task trust status cannot be determined until the modeling of the
 * security event has been completed.  The tsem_export_event()
 * function sets the trust status TSEM_TASK_TRUST_PENDING and then
 * places the task into an interruptible sleep state.
 *
 * Only two events will cause the task to be removed from sleep state.
 * Either the task is killed or a control message is written to the
 * TSEM control file that specifies the trust status of the task.  See
 * the description of the TSEM_CONTROL_TRUSTED and
 * TSEM_CONTROL_UNTRUSTED enumeration types.
 */
enum tsem_task_trust {
	TSEM_TASK_TRUSTED = 1,
	TSEM_TASK_UNTRUSTED = 2,
	TSEM_TASK_TRUST_PENDING = 4
};

/**
 * enum tsem_inode_state - Ordinal value for inode reference state.
 * @TSEM_INODE_COLLECTING: This ordinal value indicates that the uid/gid
 *		     	   values should be interpreted against the initial
 *		     	   user namespace.
 * @TSEM_INODE_COLLECTED: This ordinal value indicates that the uid/gid
 *		     	  values should be interpreted against the user
 *		     	  namespace that is in effect for the process being
 *		          modeled.
 *
 * This enumeration type is used to specify the status of the inode
 * that is having a digest value computed on the file that it is
 * referencing.  The purpose of this enumeration is so that the
 * recursive call to the TSEM_FILE_OPEN hook, caused by the kernel
 * opening the file to compute the checksum, can be bypassed.
 *
 * The state value of the inode is carried in struct tsem_inode and is
 * set and interrogated by the add_file_digest() function.  If the
 * status of the inode is TSEM_INODE_COLLECTED and the iversion of the
 * inode is the same as the collection time, the cached value for
 * currently active model digest is returned.

 * If the test for the relevancy of the cached digest value fails the
 * status of the inode is set to TSEM_INODE_COLLECTING.  The
 * tsem_file_open() function will check the inode status when it is
 * invoked by the integrity_kernel_read() function and if it is
 * set to 'collecting', a successful permissions check is returned so
 * that the kernel can open the file and compute its digest.
 */
enum tsem_inode_state {
	TSEM_INODE_COLLECTING = 1,
	TSEM_INODE_COLLECTED
};

struct tsem_COE {
	uid_t uid;
	uid_t euid;
	uid_t suid;

	gid_t gid;
	gid_t egid;
	gid_t sgid;

	uid_t fsuid;
	gid_t fsgid;

	union {
		kernel_cap_t mask;
		u64 value;
	} capeff;
};

struct tsem_file {
	uid_t uid;
	gid_t gid;
	umode_t mode;
	u32 flags;

	u32 name_length;
	u8 name[HASH_MAX_DIGESTSIZE];

	u32 s_magic;
	u8 s_id[32];
	u8 s_uuid[16];

	u8 digest[HASH_MAX_DIGESTSIZE];
};

struct tsem_event_point {
	struct list_head list;
	bool valid;
	uint64_t count;
	u8 point[HASH_MAX_DIGESTSIZE];
};

struct tsem_mmap_file_args {
	struct file *file;
	u32 anonymous;
	u32 reqprot;
	u32 prot;
	u32 flags;
};

struct tsem_socket_create_args {
	int family;
	int type;
	int protocol;
	int kern;
};

struct tsem_socket_connect_args {
	struct tsem_inode *tsip;
	struct sockaddr *addr;
	int addr_len;
	u16 family;
	union {
		struct sockaddr_in ipv4;
		struct sockaddr_in6 ipv6;
		char path[UNIX_PATH_MAX + 1];
		u8 mapping[HASH_MAX_DIGESTSIZE];
	} u;
};

struct tsem_socket_accept_args {
	u16 family;
	u16 type;
	__be16 port;
	__be32 ipv4;
	struct in6_addr ipv6;
	struct unix_sock *af_unix;
	char path[UNIX_PATH_MAX + 1];
	u8 mapping[HASH_MAX_DIGESTSIZE];
};

struct tsem_task_kill_args {
	u32 cross_model;
	u32 signal;
	u8 target[HASH_MAX_DIGESTSIZE];
};

struct tsem_event {
	struct kref kref;
	struct list_head list;
	struct work_struct work;
	enum tsem_event_type event;
	bool locked;
	pid_t pid;
	char *pathname;
	char comm[TASK_COMM_LEN];
	unsigned int digestsize;
	u8 task_id[HASH_MAX_DIGESTSIZE];
	u8 mapping[HASH_MAX_DIGESTSIZE];
	struct tsem_COE COE;
	struct tsem_file file;
	union {
		u32 event_type;
		struct tsem_mmap_file_args mmap_file;
		struct tsem_socket_create_args socket_create;
		struct tsem_socket_connect_args socket_connect;
		struct tsem_socket_accept_args socket_accept;
		struct tsem_task_kill_args task_kill;
	} CELL;
};

struct tsem_event_parameters {
	union {
		u32 event_type;
		struct file *file;
		struct tsem_mmap_file_args *mmap_file;
		struct tsem_socket_create_args *socket_create;
		struct tsem_socket_connect_args *socket_connect;
		struct tsem_socket_accept_args *socket_accept;
		struct tsem_task_kill_args *task_kill;
	} u;
};

struct tsem_work {
	unsigned int index;
	union {
		struct tsem_context *ctx;
		struct tsem_model *model;
		struct tsem_external *ext;
	} u;
	struct work_struct work;
};

struct tsem_model {
	bool have_aggregate;
	u8 base[HASH_MAX_DIGESTSIZE];
	u8 measurement[HASH_MAX_DIGESTSIZE];
	u8 state[HASH_MAX_DIGESTSIZE];

	spinlock_t point_lock;
	struct list_head point_list;
	struct mutex point_end_mutex;
	unsigned int point_count;
	struct list_head *point_end;

	spinlock_t trajectory_lock;
	struct list_head trajectory_list;
	struct mutex trajectory_end_mutex;
	struct list_head *trajectory_end;

	spinlock_t forensics_lock;
	unsigned int max_forensics_count;
	struct list_head forensics_list;
	struct mutex forensics_end_mutex;
	struct list_head *forensics_end;

	struct mutex pseudonym_mutex;
	struct list_head pseudonym_list;

	unsigned int magazine_size;
	spinlock_t magazine_lock;
	unsigned long *magazine_index;
	struct tsem_work *ws;
	struct tsem_event_point **magazine;
};

struct export_event;

struct tsem_external {
	spinlock_t export_lock;
	struct list_head export_list;
	struct dentry *dentry;
	bool have_event;
	wait_queue_head_t wq;

	unsigned int magazine_size;
	spinlock_t magazine_lock;
	unsigned long *magazine_index;
	struct tsem_work *ws;
	struct export_event **magazine;
};

struct tsem_context {
	struct kref kref;
	struct work_struct work;
	u64 id;
	bool sealed;
	bool use_current_ns;
	enum tsem_action_type actions[TSEM_EVENT_CNT];
	char *digestname;
	u8 zero_digest[HASH_MAX_DIGESTSIZE];
	struct crypto_shash *tfm;

	unsigned int magazine_size;
	spinlock_t magazine_lock;
	unsigned long *magazine_index;
	struct tsem_work *ws;
	struct tsem_event **magazine;

	struct tsem_model *model;
	struct tsem_external *external;
};

struct tsem_task {
	int trust_status;
	u8 task_id[HASH_MAX_DIGESTSIZE];
	u8 task_key[HASH_MAX_DIGESTSIZE];
	struct tsem_context *context;
};

struct tsem_inode {
	struct mutex mutex;
	struct list_head digest_list;
	enum tsem_inode_state status;
};

/**
 * struct tsem_inode_digest - Hash function specific file checksum.
 * @list:	The list structure used to link multiple digest values
 *		for an inode.
 * @version:	The version number of the inode that generated the digest
 *		value that is currently represented.
 * @name:	A pointer to a null-terminated character buffer containing
 *		the name of the hash function that generated the current
 *		digest value.
 * @value:	The digest value of the file.
 *
 * A linked list of these structures is maintained for each inode that
 * is modeled by TSEM and is used to support multiple hash specific
 * digest values for a file represented by the inode.  The tsem_inode
 * structure that represents the TSEM security status of the inode
 * contains the pointer to this list of structures.
 *
 * The version member of the structure contains the inode version number
 * that was in effect when the last digest value of this type was computed.
 * This version number value is used to detect changes and to trigger an
 * update of the digest value.
 *
 * The name member of structure contains the name of the hash function
 * that generated the checksum value.  This name is used to locate the
 * correct structure by comparing its value against the hash function
 * that is being used for the modeling domain that is accessing the
 * inode.
 */
struct tsem_inode_digest {
	struct list_head list;
	char *name;
	u64 version;
	u8 value[HASH_MAX_DIGESTSIZE];
};

extern struct lsm_blob_sizes tsem_blob_sizes;
extern const char * const tsem_names[TSEM_EVENT_CNT];
extern enum tsem_action_type tsem_root_actions[TSEM_EVENT_CNT];

extern struct dentry *tsem_fs_create_external(const char *name);
extern void tsem_fs_show_trajectory(struct seq_file *c, struct tsem_event *ep);
extern void tsem_fs_show_field(struct seq_file *c, const char *field);
extern void tsem_fs_show_key(struct seq_file *c, char *term, char *key,
			     char *fmt, ...);
extern int tsem_fs_init(void);

extern struct tsem_model *tsem_model_allocate(void);
extern void tsem_model_free(struct tsem_context *ctx);
extern int tsem_model_event(struct tsem_event *ep);
extern int tsem_model_load_point(u8 *point);
extern int tsem_model_load_pseudonym(u8 *mapping);
extern int tsem_model_has_pseudonym(struct tsem_inode *tsip,
				    struct tsem_file *ep);
extern void tsem_model_load_base(u8 *mapping);
extern int tsem_model_add_aggregate(void);
extern void tsem_model_compute_state(void);
extern void tsem_model_magazine_free(struct tsem_model *model);
extern int tsem_model_cache_init(struct tsem_model *model);

extern void tsem_ns_put(struct tsem_context *ctx);
extern int tsem_ns_event_key(u8 *task_key, const char *keystr, u8 *key);
extern int tsem_ns_create(const enum tsem_control_type type,
			  const char *digest, const enum tsem_ns_reference ns,
			  const char *key, const unsigned int cache_size);

extern int tsem_export_show(struct seq_file *m, void *v);
extern int tsem_export_event(struct tsem_event *ep);
extern int tsem_export_action(enum tsem_event_type event);
extern int tsem_export_aggregate(void);
extern int tsem_export_magazine_allocate(struct tsem_external *ext,
					 size_t size);
extern void tsem_export_magazine_free(struct tsem_external *ext);
extern int tsem_export_cache_init(void);

extern int tsem_map_task(struct file *file, u8 *mapping);
struct tsem_event *tsem_map_event(enum tsem_event_type event,
				  struct tsem_event_parameters *param);
struct tsem_event *tsem_map_event_locked(enum tsem_event_type event,
					 struct tsem_event_parameters *param);

extern struct tsem_event *tsem_event_allocate(bool locked);
extern struct tsem_event *tsem_event_init(enum tsem_event_type event,
					  struct tsem_event_parameters *params,
					  bool locked);
extern void tsem_event_put(struct tsem_event *ep);
extern void tsem_event_get(struct tsem_event *ep);
extern int tsem_event_magazine_allocate(struct tsem_context *ctx, size_t size);
extern void tsem_event_magazine_free(struct tsem_context *ctx);
extern int tsem_event_cache_init(void);

extern u8 *tsem_trust_aggregate(void);
extern int tsem_trust_add_event(struct tsem_event *ep);

static inline struct tsem_task *tsem_task(struct task_struct *task)
{
	return task->security + tsem_blob_sizes.lbs_task;
}

static inline bool tsem_task_trusted(struct task_struct *task)
{
	return tsem_task(task)->trust_status & TSEM_TASK_TRUSTED;
}

static inline bool tsem_task_untrusted(struct task_struct *task)
{
	return tsem_task(task)->trust_status & ~TSEM_TASK_TRUSTED;
}

static inline struct tsem_context *tsem_context(struct task_struct *task)
{
	return tsem_task(task)->context;
}

static inline struct tsem_model *tsem_model(struct task_struct *task)
{
	return tsem_task(task)->context->model;
}

static inline struct tsem_inode *tsem_inode(struct inode *inode)
{
	return inode->i_security + tsem_blob_sizes.lbs_inode;
}

static inline struct crypto_shash *tsem_digest(void)
{
	return tsem_context(current)->tfm;
}

static inline unsigned int tsem_digestsize(void)
{
	return crypto_shash_digestsize(tsem_digest());
}

/*  LocalWords:  SPDX GPL Enjellic LLC TSEM uapi linux crypto enum tsem bprm ie
 */
/*  LocalWords:  creds LSM TMA conditionalize SETPGID GETPGID GETSID SETNICE ns
 */
/*  LocalWords:  SETIOPRIO GETIOPRIO PRLIMIT SETRLIMIT SETSCHEDULER PRCTL MMAP
 */
/*  LocalWords:  GETSCHEDULER FCNTL SOCKETPAIR SENDMSG RECVMSG GETSOCKNAME SHM
 */
/*  LocalWords:  GETPEERNAME SETSOCKOPT PTRACE TRACEME UMOUNT PIVOTROOT STATFS
 */
/*  LocalWords:  SHMCTL SHMAT SEM SEMCTL SEMOP SYSLOG SETTIME QUOTACTL MSGCTL
 */
/*  LocalWords:  MSGSND MSGRCV IPC ALLOC NETLINK INODE SYMLINK MKDIR RMDIR BPF
 */
/*  LocalWords:  MKNOD SETATTR GETATTR SETXATTR GETXATTR LISTXATTR REMOVEXATTR
 */
/*  LocalWords:  KILLPRIV PROG CNT EPERM namespace hexadecimally DAC uid gid af
 */
/*  LocalWords:  COE nsref struct interruptible inode euid suid egid sgid fsuid
 */
/*  LocalWords:  fsgid capeff umode DIGESTSIZE uuid bool uint mmap args reqprot
 */
/*  LocalWords:  prot kern tsip sockaddr addr len ipv unix kref pid pathname ws
 */
/*  LocalWords:  digestsize ctx spinlock mutex dentry wq digestname shash tfm
 */
/*  LocalWords:  checksum extern lsm const fs ep fmt init keystr param params
 */
/*  LocalWords:  inline iversion
 */
