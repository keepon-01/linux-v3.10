#ifndef _LINUX_WAIT_H
#define _LINUX_WAIT_H


#include <linux/list.h>
#include <linux/stddef.h>
#include <linux/spinlock.h>
#include <asm/current.h>
#include <uapi/linux/wait.h>

typedef struct __wait_queue wait_queue_t;
typedef int (*wait_queue_func_t)(wait_queue_t *wait, unsigned mode, int flags, void *key);
int default_wake_function(wait_queue_t *wait, unsigned mode, int flags, void *key);

struct __wait_queue {
	unsigned int flags;
#define WQ_FLAG_EXCLUSIVE	0x01
	void *private;
	wait_queue_func_t func;
	struct list_head task_list;
};

struct wait_bit_key {
	void *flags;
	int bit_nr;
};

struct wait_bit_queue {
	struct wait_bit_key key;
	wait_queue_t wait;
};

struct __wait_queue_head {
	spinlock_t lock;  //自旋锁，适合锁持有时间短的场景，因为线程在等待的时候是持续检查锁的状态，不会进入睡眠状态，所以在多核心的时候没有上下文切换的开销
	struct list_head task_list;
};
typedef struct __wait_queue_head wait_queue_head_t;

struct task_struct;

/*
 * Macros for declaration and initialisaton of the datatypes
 */

#define __WAITQUEUE_INITIALIZER(name, tsk) {				\
	.private	= tsk,						\
	.func		= default_wake_function,			\
	.task_list	= { NULL, NULL } }

#define DECLARE_WAITQUEUE(name, tsk)					\
	wait_queue_t name = __WAITQUEUE_INITIALIZER(name, tsk)

#define __WAIT_QUEUE_HEAD_INITIALIZER(name) {				\
	.lock		= __SPIN_LOCK_UNLOCKED(name.lock),		\
	.task_list	= { &(name).task_list, &(name).task_list } }

#define DECLARE_WAIT_QUEUE_HEAD(name) \
	wait_queue_head_t name = __WAIT_QUEUE_HEAD_INITIALIZER(name)

#define __WAIT_BIT_KEY_INITIALIZER(word, bit)				\
	{ .flags = word, .bit_nr = bit, }

extern void __init_waitqueue_head(wait_queue_head_t *q, const char *name, struct lock_class_key *);

#define init_waitqueue_head(q)				\
	do {						\
		static struct lock_class_key __key;	\
							\
		__init_waitqueue_head((q), #q, &__key);	\
	} while (0)

#ifdef CONFIG_LOCKDEP
# define __WAIT_QUEUE_HEAD_INIT_ONSTACK(name) \
	({ init_waitqueue_head(&name); name; })
# define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(name) \
	wait_queue_head_t name = __WAIT_QUEUE_HEAD_INIT_ONSTACK(name)
#else
# define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(name) DECLARE_WAIT_QUEUE_HEAD(name)
#endif

static inline void init_waitqueue_entry(wait_queue_t *q, struct task_struct *p)
{
	q->flags = 0;
	q->private = p;
	q->func = default_wake_function;//回调函数，eventpoll中的执行epoll_wait时，没有数据时阻塞自己进来的。
}

static inline void init_waitqueue_func_entry(wait_queue_t *q,
					wait_queue_func_t func)
{
	q->flags = 0;
	q->private = NULL;
	q->func = func;
}

static inline int waitqueue_active(wait_queue_head_t *q)
{
	return !list_empty(&q->task_list);
}

extern void add_wait_queue(wait_queue_head_t *q, wait_queue_t *wait);
extern void add_wait_queue_exclusive(wait_queue_head_t *q, wait_queue_t *wait);
extern void remove_wait_queue(wait_queue_head_t *q, wait_queue_t *wait);

static inline void __add_wait_queue(wait_queue_head_t *head, wait_queue_t *new)
{
	list_add(&new->task_list, &head->task_list);
}

/*
 * Used for wake-one threads:
 */
static inline void __add_wait_queue_exclusive(wait_queue_head_t *q,
					      wait_queue_t *wait)
{
	wait->flags |= WQ_FLAG_EXCLUSIVE;
	__add_wait_queue(q, wait);
}

static inline void __add_wait_queue_tail(wait_queue_head_t *head,
					 wait_queue_t *new)
{
	list_add_tail(&new->task_list, &head->task_list);
}

static inline void __add_wait_queue_tail_exclusive(wait_queue_head_t *q,
					      wait_queue_t *wait)
{
	wait->flags |= WQ_FLAG_EXCLUSIVE;
	__add_wait_queue_tail(q, wait);
}

static inline void __remove_wait_queue(wait_queue_head_t *head,
							wait_queue_t *old)
{
	list_del(&old->task_list);
}

void __wake_up(wait_queue_head_t *q, unsigned int mode, int nr, void *key);
void __wake_up_locked_key(wait_queue_head_t *q, unsigned int mode, void *key);
void __wake_up_sync_key(wait_queue_head_t *q, unsigned int mode, int nr,
			void *key);
void __wake_up_locked(wait_queue_head_t *q, unsigned int mode, int nr);
void __wake_up_sync(wait_queue_head_t *q, unsigned int mode, int nr);
void __wake_up_bit(wait_queue_head_t *, void *, int);
int __wait_on_bit(wait_queue_head_t *, struct wait_bit_queue *, int (*)(void *), unsigned);
int __wait_on_bit_lock(wait_queue_head_t *, struct wait_bit_queue *, int (*)(void *), unsigned);
void wake_up_bit(void *, int);
int out_of_line_wait_on_bit(void *, int, int (*)(void *), unsigned);
int out_of_line_wait_on_bit_lock(void *, int, int (*)(void *), unsigned);
wait_queue_head_t *bit_waitqueue(void *, int);

#define wake_up(x)			__wake_up(x, TASK_NORMAL, 1, NULL)
#define wake_up_nr(x, nr)		__wake_up(x, TASK_NORMAL, nr, NULL)
#define wake_up_all(x)			__wake_up(x, TASK_NORMAL, 0, NULL)
#define wake_up_locked(x)		__wake_up_locked((x), TASK_NORMAL, 1)
#define wake_up_all_locked(x)		__wake_up_locked((x), TASK_NORMAL, 0)

#define wake_up_interruptible(x)	__wake_up(x, TASK_INTERRUPTIBLE, 1, NULL)
#define wake_up_interruptible_nr(x, nr)	__wake_up(x, TASK_INTERRUPTIBLE, nr, NULL)
#define wake_up_interruptible_all(x)	__wake_up(x, TASK_INTERRUPTIBLE, 0, NULL)
#define wake_up_interruptible_sync(x)	__wake_up_sync((x), TASK_INTERRUPTIBLE, 1)

/*
 * Wakeup macros to be used to report events to the targets.
 */
#define wake_up_poll(x, m)				\
	__wake_up(x, TASK_NORMAL, 1, (void *) (m))
#define wake_up_locked_poll(x, m)				\
	__wake_up_locked_key((x), TASK_NORMAL, (void *) (m))
#define wake_up_interruptible_poll(x, m)			\
	__wake_up(x, TASK_INTERRUPTIBLE, 1, (void *) (m))
#define wake_up_interruptible_sync_poll(x, m)				\
	__wake_up_sync_key((x), TASK_INTERRUPTIBLE, 1, (void *) (m))

#define __wait_event(wq, condition) 					\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_UNINTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		schedule();						\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)

/**
 * wait_event - sleep until a condition gets true
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_UNINTERRUPTIBLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 */
#define wait_event(wq, condition) 					\
do {									\
	if (condition)	 						\
		break;							\
	__wait_event(wq, condition);					\
} while (0)

#define __wait_event_timeout(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_UNINTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		ret = schedule_timeout(ret);				\
		if (!ret)						\
			break;						\
	}								\
	if (!ret && (condition))					\
		ret = 1;						\
	finish_wait(&wq, &__wait);					\
} while (0)

/**
 * wait_event_timeout - sleep until a condition gets true or a timeout elapses
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, in jiffies
 *
 * The process is put to sleep (TASK_UNINTERRUPTIBLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function returns 0 if the @timeout elapsed, or the remaining
 * jiffies (at least 1) if the @condition evaluated to %true before
 * the @timeout elapsed.
 */
#define wait_event_timeout(wq, condition, timeout)			\
({									\
	long __ret = timeout;						\
	if (!(condition)) 						\
		__wait_event_timeout(wq, condition, __ret);		\
	__ret;								\
})

#define __wait_event_interruptible(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_INTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)

/**
 * wait_event_interruptible - sleep until a condition gets true
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function will return -ERESTARTSYS if it was interrupted by a
 * signal and 0 if @condition evaluated to true.
 */
#define wait_event_interruptible(wq, condition)				\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_interruptible(wq, condition, __ret);	\
	__ret;								\
})

#define __wait_event_interruptible_timeout(wq, condition, ret)		\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_INTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			ret = schedule_timeout(ret);			\
			if (!ret)					\
				break;					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	if (!ret && (condition))					\
		ret = 1;						\
	finish_wait(&wq, &__wait);					\
} while (0)

/**
 * wait_event_interruptible_timeout - sleep until a condition gets true or a timeout elapses
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, in jiffies
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * Returns:
 * 0 if the @timeout elapsed, -%ERESTARTSYS if it was interrupted by
 * a signal, or the remaining jiffies (at least 1) if the @condition
 * evaluated to %true before the @timeout elapsed.
 */
#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition, __ret); \
	__ret;								\
})

#define __wait_event_hrtimeout(wq, condition, timeout, state)		\
({									\
	int __ret = 0;							\
	DEFINE_WAIT(__wait);						\
	struct hrtimer_sleeper __t;					\
									\
	hrtimer_init_on_stack(&__t.timer, CLOCK_MONOTONIC,		\
			      HRTIMER_MODE_REL);			\
	hrtimer_init_sleeper(&__t, current);				\
	if ((timeout).tv64 != KTIME_MAX)				\
		hrtimer_start_range_ns(&__t.timer, timeout,		\
				       current->timer_slack_ns,		\
				       HRTIMER_MODE_REL);		\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, state);			\
		if (condition)						\
			break;						\
		if (state == TASK_INTERRUPTIBLE &&			\
		    signal_pending(current)) {				\
			__ret = -ERESTARTSYS;				\
			break;						\
		}							\
		if (!__t.task) {					\
			__ret = -ETIME;					\
			break;						\
		}							\
		schedule();						\
	}								\
									\
	hrtimer_cancel(&__t.timer);					\
	destroy_hrtimer_on_stack(&__t.timer);				\
	finish_wait(&wq, &__wait);					\
	__ret;								\
})

/**
 * wait_event_hrtimeout - sleep until a condition gets true or a timeout elapses
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, as a ktime_t
 *
 * The process is put to sleep (TASK_UNINTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function returns 0 if @condition became true, or -ETIME if the timeout
 * elapsed.
 */
#define wait_event_hrtimeout(wq, condition, timeout)			\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__ret = __wait_event_hrtimeout(wq, condition, timeout,	\
					       TASK_UNINTERRUPTIBLE);	\
	__ret;								\
})

/**
 * wait_event_interruptible_hrtimeout - sleep until a condition gets true or a timeout elapses
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, as a ktime_t
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function returns 0 if @condition became true, -ERESTARTSYS if it was
 * interrupted by a signal, or -ETIME if the timeout elapsed.
 */
#define wait_event_interruptible_hrtimeout(wq, condition, timeout)	\
({									\
	long __ret = 0;							\
	if (!(condition))						\
		__ret = __wait_event_hrtimeout(wq, condition, timeout,	\
					       TASK_INTERRUPTIBLE);	\
	__ret;								\
})

#define __wait_event_interruptible_exclusive(wq, condition, ret)	\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait_exclusive(&wq, &__wait,			\
					TASK_INTERRUPTIBLE);		\
		if (condition) {					\
			finish_wait(&wq, &__wait);			\
			break;						\
		}							\
		if (!signal_pending(current)) {				\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		abort_exclusive_wait(&wq, &__wait, 			\
				TASK_INTERRUPTIBLE, NULL);		\
		break;							\
	}								\
} while (0)

#define wait_event_interruptible_exclusive(wq, condition)		\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_interruptible_exclusive(wq, condition, __ret);\
	__ret;								\
})


#define __wait_event_interruptible_locked(wq, condition, exclusive, irq) \
({									\
	int __ret = 0;							\
	DEFINE_WAIT(__wait);						\
	if (exclusive)							\
		__wait.flags |= WQ_FLAG_EXCLUSIVE;			\
	do {								\
		if (likely(list_empty(&__wait.task_list)))		\
			__add_wait_queue_tail(&(wq), &__wait);		\
		set_current_state(TASK_INTERRUPTIBLE);			\
		if (signal_pending(current)) {				\
			__ret = -ERESTARTSYS;				\
			break;						\
		}							\
		if (irq)						\
			spin_unlock_irq(&(wq).lock);			\
		else							\
			spin_unlock(&(wq).lock);			\
		schedule();						\
		if (irq)						\
			spin_lock_irq(&(wq).lock);			\
		else							\
			spin_lock(&(wq).lock);				\
	} while (!(condition));						\
	__remove_wait_queue(&(wq), &__wait);				\
	__set_current_state(TASK_RUNNING);				\
	__ret;								\
})


/**
 * wait_event_interruptible_locked - sleep until a condition gets true
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * It must be called with wq.lock being held.  This spinlock is
 * unlocked while sleeping but @condition testing is done while lock
 * is held and when this macro exits the lock is held.
 *
 * The lock is locked/unlocked using spin_lock()/spin_unlock()
 * functions which must match the way they are locked/unlocked outside
 * of this macro.
 *
 * wake_up_locked() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function will return -ERESTARTSYS if it was interrupted by a
 * signal and 0 if @condition evaluated to true.
 */
#define wait_event_interruptible_locked(wq, condition)			\
	((condition)							\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 0, 0))

/**
 * wait_event_interruptible_locked_irq - sleep until a condition gets true
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * It must be called with wq.lock being held.  This spinlock is
 * unlocked while sleeping but @condition testing is done while lock
 * is held and when this macro exits the lock is held.
 *
 * The lock is locked/unlocked using spin_lock_irq()/spin_unlock_irq()
 * functions which must match the way they are locked/unlocked outside
 * of this macro.
 *
 * wake_up_locked() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function will return -ERESTARTSYS if it was interrupted by a
 * signal and 0 if @condition evaluated to true.
 */
#define wait_event_interruptible_locked_irq(wq, condition)		\
	((condition)							\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 0, 1))

/**
 * wait_event_interruptible_exclusive_locked - sleep exclusively until a condition gets true
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * It must be called with wq.lock being held.  This spinlock is
 * unlocked while sleeping but @condition testing is done while lock
 * is held and when this macro exits the lock is held.
 *
 * The lock is locked/unlocked using spin_lock()/spin_unlock()
 * functions which must match the way they are locked/unlocked outside
 * of this macro.
 *
 * The process is put on the wait queue with an WQ_FLAG_EXCLUSIVE flag
 * set thus when other process waits process on the list if this
 * process is awaken further processes are not considered.
 *
 * wake_up_locked() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function will return -ERESTARTSYS if it was interrupted by a
 * signal and 0 if @condition evaluated to true.
 */
#define wait_event_interruptible_exclusive_locked(wq, condition)	\
	((condition)							\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 1, 0))

/**
 * wait_event_interruptible_exclusive_locked_irq - sleep until a condition gets true
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * It must be called with wq.lock being held.  This spinlock is
 * unlocked while sleeping but @condition testing is done while lock
 * is held and when this macro exits the lock is held.
 *
 * The lock is locked/unlocked using spin_lock_irq()/spin_unlock_irq()
 * functions which must match the way they are locked/unlocked outside
 * of this macro.
 *
 * The process is put on the wait queue with an WQ_FLAG_EXCLUSIVE flag
 * set thus when other process waits process on the list if this
 * process is awaken further processes are not considered.
 *
 * wake_up_locked() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function will return -ERESTARTSYS if it was interrupted by a
 * signal and 0 if @condition evaluated to true.
 */
#define wait_event_interruptible_exclusive_locked_irq(wq, condition)	\
	((condition)							\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 1, 1))



#define __wait_event_killable(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_KILLABLE);		\
		if (condition)						\
			break;						\
		if (!fatal_signal_pending(current)) {			\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)

/**
 * wait_event_killable - sleep until a condition gets true
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_KILLABLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function will return -ERESTARTSYS if it was interrupted by a
 * signal and 0 if @condition evaluated to true.
 */
#define wait_event_killable(wq, condition)				\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_killable(wq, condition, __ret);		\
	__ret;								\
})


#define __wait_event_lock_irq(wq, condition, lock, cmd)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_UNINTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		spin_unlock_irq(&lock);					\
		cmd;							\
		schedule();						\
		spin_lock_irq(&lock);					\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)

/**
 * wait_event_lock_irq_cmd - sleep until a condition gets true. The
 *			     condition is checked under the lock. This
 *			     is expected to be called with the lock
 *			     taken.
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @lock: a locked spinlock_t, which will be released before cmd
 *	  and schedule() and reacquired afterwards.
 * @cmd: a command which is invoked outside the critical section before
 *	 sleep
 *
 * The process is put to sleep (TASK_UNINTERRUPTIBLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * This is supposed to be called while holding the lock. The lock is
 * dropped before invoking the cmd and going to sleep and is reacquired
 * afterwards.
 */
#define wait_event_lock_irq_cmd(wq, condition, lock, cmd)		\
do {									\
	if (condition)							\
		break;							\
	__wait_event_lock_irq(wq, condition, lock, cmd);		\
} while (0)

/**
 * wait_event_lock_irq - sleep until a condition gets true. The
 *			 condition is checked under the lock. This
 *			 is expected to be called with the lock
 *			 taken.
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @lock: a locked spinlock_t, which will be released before schedule()
 *	  and reacquired afterwards.
 *
 * The process is put to sleep (TASK_UNINTERRUPTIBLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * This is supposed to be called while holding the lock. The lock is
 * dropped before going to sleep and is reacquired afterwards.
 */
#define wait_event_lock_irq(wq, condition, lock)			\
do {									\
	if (condition)							\
		break;							\
	__wait_event_lock_irq(wq, condition, lock, );			\
} while (0)


#define __wait_event_interruptible_lock_irq(wq, condition,		\
					    lock, ret, cmd)		\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_INTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		if (signal_pending(current)) {				\
			ret = -ERESTARTSYS;				\
			break;						\
		}							\
		spin_unlock_irq(&lock);					\
		cmd;							\
		schedule();						\
		spin_lock_irq(&lock);					\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)

/**
 * wait_event_interruptible_lock_irq_cmd - sleep until a condition gets true.
 *		The condition is checked under the lock. This is expected to
 *		be called with the lock taken.
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @lock: a locked spinlock_t, which will be released before cmd and
 *	  schedule() and reacquired afterwards.
 * @cmd: a command which is invoked outside the critical section before
 *	 sleep
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received. The @condition is
 * checked each time the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * This is supposed to be called while holding the lock. The lock is
 * dropped before invoking the cmd and going to sleep and is reacquired
 * afterwards.
 *
 * The macro will return -ERESTARTSYS if it was interrupted by a signal
 * and 0 if @condition evaluated to true.
 */
#define wait_event_interruptible_lock_irq_cmd(wq, condition, lock, cmd)	\
({									\
	int __ret = 0;							\
									\
	if (!(condition))						\
		__wait_event_interruptible_lock_irq(wq, condition,	\
						    lock, __ret, cmd);	\
	__ret;								\
})

/**
 * wait_event_interruptible_lock_irq - sleep until a condition gets true.
 *		The condition is checked under the lock. This is expected
 *		to be called with the lock taken.
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @lock: a locked spinlock_t, which will be released before schedule()
 *	  and reacquired afterwards.
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or signal is received. The @condition is
 * checked each time the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * This is supposed to be called while holding the lock. The lock is
 * dropped before going to sleep and is reacquired afterwards.
 *
 * The macro will return -ERESTARTSYS if it was interrupted by a signal
 * and 0 if @condition evaluated to true.
 */
#define wait_event_interruptible_lock_irq(wq, condition, lock)		\
({									\
	int __ret = 0;							\
									\
	if (!(condition))						\
		__wait_event_interruptible_lock_irq(wq, condition,	\
						    lock, __ret, );	\
	__ret;								\
})


/*
 * These are the old interfaces to sleep waiting for an event.
 * They are racy.  DO NOT use them, use the wait_event* interfaces above.
 * We plan to remove these interfaces.
 */
extern void sleep_on(wait_queue_head_t *q);
extern long sleep_on_timeout(wait_queue_head_t *q,
				      signed long timeout);
extern void interruptible_sleep_on(wait_queue_head_t *q);
extern long interruptible_sleep_on_timeout(wait_queue_head_t *q,
					   signed long timeout);

/*
 * Waitqueues which are removed from the waitqueue_head at wakeup time
 */
void prepare_to_wait(wait_queue_head_t *q, wait_queue_t *wait, int state);
void prepare_to_wait_exclusive(wait_queue_head_t *q, wait_queue_t *wait, int state);
void finish_wait(wait_queue_head_t *q, wait_queue_t *wait);
void abort_exclusive_wait(wait_queue_head_t *q, wait_queue_t *wait,
			unsigned int mode, void *key);
int autoremove_wake_function(wait_queue_t *wait, unsigned mode, int sync, void *key);
int wake_bit_function(wait_queue_t *wait, unsigned mode, int sync, void *key);

//注册了回调函数autoremove_wake_function， 并把当前的进程描述符current关联到.private成员上
#define DEFINE_WAIT_FUNC(name, function)				\
	wait_queue_t name = {						\
		.private	= current,				\
		.func		= function,				\
		.task_list	= LIST_HEAD_INIT((name).task_list),	\
	}

#define DEFINE_WAIT(name) DEFINE_WAIT_FUNC(name, autoremove_wake_function)

#define DEFINE_WAIT_BIT(name, word, bit)				\
	struct wait_bit_queue name = {					\
		.key = __WAIT_BIT_KEY_INITIALIZER(word, bit),		\
		.wait	= {						\
			.private	= current,			\
			.func		= wake_bit_function,		\
			.task_list	=				\
				LIST_HEAD_INIT((name).wait.task_list),	\
		},							\
	}

#define init_wait(wait)							\
	do {								\
		(wait)->private = current;				\
		(wait)->func = autoremove_wake_function;		\
		INIT_LIST_HEAD(&(wait)->task_list);			\
		(wait)->flags = 0;					\
	} while (0)

/**
 * wait_on_bit - wait for a bit to be cleared
 * @word: the word being waited on, a kernel virtual address
 * @bit: the bit of the word being waited on
 * @action: the function used to sleep, which may take special actions
 * @mode: the task state to sleep in
 *
 * There is a standard hashed waitqueue table for generic use. This
 * is the part of the hashtable's accessor API that waits on a bit.
 * For instance, if one were to have waiters on a bitflag, one would
 * call wait_on_bit() in threads waiting for the bit to clear.
 * One uses wait_on_bit() where one is waiting for the bit to clear,
 * but has no intention of setting it.
 */
static inline int wait_on_bit(void *word, int bit,
				int (*action)(void *), unsigned mode)
{
	if (!test_bit(bit, word))
		return 0;
	return out_of_line_wait_on_bit(word, bit, action, mode);
}

/**
 * wait_on_bit_lock - wait for a bit to be cleared, when wanting to set it
 * @word: the word being waited on, a kernel virtual address
 * @bit: the bit of the word being waited on
 * @action: the function used to sleep, which may take special actions
 * @mode: the task state to sleep in
 *
 * There is a standard hashed waitqueue table for generic use. This
 * is the part of the hashtable's accessor API that waits on a bit
 * when one intends to set it, for instance, trying to lock bitflags.
 * For instance, if one were to have waiters trying to set bitflag
 * and waiting for it to clear before setting it, one would call
 * wait_on_bit() in threads waiting to be able to set the bit.
 * One uses wait_on_bit_lock() where one is waiting for the bit to
 * clear with the intention of setting it, and when done, clearing it.
 */
static inline int wait_on_bit_lock(void *word, int bit,
				int (*action)(void *), unsigned mode)
{
	if (!test_and_set_bit(bit, word))
		return 0;
	return out_of_line_wait_on_bit_lock(word, bit, action, mode);
}
	
#endif
