/* block processing, T13.654-T14.618 $DVS:time$ */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
// #include <unistd.h>
#include <math.h>
#include "system.h"
#include "../ldus/source/include/ldus/rbtree.h"
#include "block.h"
#include "crypt.h"
#include "wallet.h"
#include "storage.h"
#include "transport.h"
#include "utils/log.h"
#include "init.h"
#include "sync.h"
#include "pool.h"
#include "miner.h"
#include "memory.h"
#include "address.h"
#include "commands.h"
#include "utils/utils.h"
#include "utils/moving_statistics/moving_average.h"
#include "mining_common.h"
#include "time.h"
#include "math.h"
#include "utils/atomic.h"

#define MAX_WAITING_MAIN        1
#define MAIN_START_AMOUNT       (1ll << 42)
#define MAIN_BIG_PERIOD_LOG     21
#define MAX_LINKS               15
#define MAKE_BLOCK_PERIOD       13

#define CACHE			1
#define CACHE_MAX_SIZE		600000
#define CACHE_MAX_SAMPLES	100
#define ORPHAN_HASH_SIZE	2
#define MAX_ALLOWED_EXTRA	0x10000

#define MAIN_APOLLO_AMOUNT      (1ll << 39)
// 13500 is 10 days
// nmain = 834646 ,          at 2019-09-17 00:30:00
// nmain = 834646 + 13500  , at 2019-09-27 00:30:00
#define MAIN_APOLLO_HIGHT       (3481 + 1)
//#define MAIN_APOLLO_HIGHT       2  // for test

struct block_backrefs;
struct orphan_block;
struct block_internal_index;

struct block_internal {
	union {
		struct ldus_rbtree node;
		struct block_internal_index *index;
	};
	xdag_hash_t hash;
	xdag_diff_t difficulty;
	xdag_amount_t amount, linkamount[MAX_LINKS], fee; //linkamount保存的是每个链接需要支付或者收到的金额 fee是区块被链接所需支付的金额 amount是当前区块的金额
	xtime_t time;
	uint64_t storage_pos;
	//要么指向ref 要么指向oref 不过都得需要等输入输出即link的都link完后 有剩余的空间才会放ref或oref 指向孤块
	union {
		struct block_internal *ref; //指向引用自身的区块 即若A引用了B 则B中的ref为A
		struct orphan_block *oref;
	};
	struct block_internal *link[MAX_LINKS]; //最后一个指向ourblock的next 倒数第二个指向ourblock的prev
	//backrefs 用于反向
	atomic_uintptr_t backrefs;
	atomic_uintptr_t remark;
	uint16_t flags, in_mask, n_our_key;
	//nlinks 跟 max_diff_link 设置为占4位
	uint8_t nlinks:4, max_diff_link:4, reserved;
};

struct block_internal_index {
	struct ldus_rbtree node;
	xdag_hash_t hash;
	struct block_internal *bi;
};

#define N_BACKREFS      (sizeof(struct block_internal) / sizeof(struct block_internal *) - 1)

//一个链表存放下一个next和元素值
struct block_backrefs {
	struct block_internal *backrefs[N_BACKREFS];
	struct block_backrefs *next;
};


//自己的区块的上一个和下一个 prev在13的位置 next在14的位置
#define ourprev link[MAX_LINKS - 2]
#define ournext link[MAX_LINKS - 1]


//缓存链表
struct cache_block {
	struct ldus_rbtree node;
	xdag_hash_t hash;
	struct xdag_block block;
	struct cache_block *next;
};


//orphan区块 双向链表 用来指向内存中实际的bi 里面还存放了原始xdag块
struct orphan_block {
	struct block_internal *orphan_bi;
	struct orphan_block *next;
	struct orphan_block *prev;
	struct xdag_block block[0];
};

//移除orphan的操作 常规 重用 额外？？
enum orphan_remove_actions {
	ORPHAN_REMOVE_NORMAL,
	ORPHAN_REMOVE_REUSE,
	ORPHAN_REMOVE_EXTRA
};

//获取索引 要么0 要么1 如果bi是extra块的话返回1 否则返回0
#define get_orphan_index(bi)      (!!((bi)->flags & BI_EXTRA))

int g_bi_index_enable = 1, g_block_production_on;
static pthread_mutex_t g_create_block_mutex = PTHREAD_MUTEX_INITIALIZER;
static xdag_amount_t g_balance = 0;
extern xtime_t g_time_limit;
static struct ldus_rbtree *root = 0, *cache_root = 0;
static struct block_internal *volatile top_main_chain = 0, *volatile pretop_main_chain = 0; //volatile 为了线程安全
static struct block_internal *ourfirst = 0, *ourlast = 0; //这里放的是用户自己的区块
static struct cache_block *cache_first = NULL, *cache_last = NULL;
static pthread_mutex_t block_mutex;
static pthread_mutex_t rbtree_mutex;
//TODO: this variable duplicates existing global variable g_is_pool. Probably should be removed
//跟g_is_pool功能类似
static int g_light_mode = 0;
static uint32_t cache_bounded_counter = 0;
//g_orphan_first存放两个orphasn_block指针 g_orphan_last存放两个orphan_block指针 一个存orphan 一个存extrablock first存放第一个最早的 last存放最后的
static struct orphan_block *g_orphan_first[ORPHAN_HASH_SIZE], *g_orphan_last[ORPHAN_HASH_SIZE];

//functions
void cache_retarget(int32_t, int32_t);
void cache_add(struct xdag_block*, xdag_hash_t);
int32_t check_signature_out_cached(struct block_internal*, struct xdag_public_key*, const int, int32_t*, int32_t*);
int32_t check_signature_out(struct block_internal*, struct xdag_public_key*, const int);
static int32_t find_and_verify_signature_out(struct xdag_block*, struct xdag_public_key*, const int);
int do_mining(struct xdag_block *block, struct block_internal **pretop, xtime_t send_time);
void remove_orphan(struct block_internal*,int);
void add_orphan(struct block_internal*,struct xdag_block*);
static inline size_t remark_acceptance(xdag_remark_t);
static int add_remark_bi(struct block_internal*, xdag_remark_t);
static void add_backref(struct block_internal*, struct block_internal*);
static inline int get_nfield(struct xdag_block*, int);
static inline const char* get_remark(struct block_internal*);
static int load_remark(struct block_internal*);
static void order_ourblocks_by_amount(struct block_internal *bi);
static inline void add_ourblock(struct block_internal *nodeBlock);
static inline void remove_ourblock(struct block_internal *nodeBlock);
void *add_block_callback(void *block, void *data);
extern void *sync_thread(void *arg);

static inline int lessthan(struct ldus_rbtree *l, struct ldus_rbtree *r)
{
	return memcmp(l + 1, r + 1, 24) < 0;
}

ldus_rbtree_define_prefix(lessthan, static inline, )


//通过hash找到区块
static inline struct block_internal *block_by_hash(const xdag_hashlow_t hash)
{
	if(g_bi_index_enable) {
		struct block_internal_index *index;
		pthread_mutex_lock(&rbtree_mutex);
		index = (struct block_internal_index *)ldus_rbtree_find(root, (struct ldus_rbtree *)hash - 1);
		pthread_mutex_unlock(&rbtree_mutex);
		return index ? index->bi : NULL;
	} else {
		struct block_internal *bi;
		pthread_mutex_lock(&rbtree_mutex);
		bi = (struct block_internal *)ldus_rbtree_find(root, (struct ldus_rbtree *)hash - 1);
		pthread_mutex_unlock(&rbtree_mutex);
		return bi;
	}
}


//在缓存中 通过hash找到区块
static inline struct cache_block *cache_block_by_hash(const xdag_hashlow_t hash)
{
	return (struct cache_block *)ldus_rbtree_find(cache_root, (struct ldus_rbtree *)hash - 1);
}


static void log_block(const char *mess, xdag_hash_t h, xtime_t t, uint64_t pos)
{
	/* Do not log blocks as we are loading from local storage */
	if(g_xdag_state != XDAG_STATE_LOAD) {
		xdag_info("%s: %016llx%016llx%016llx%016llx t=%llx pos=%llx", mess,
			((uint64_t*)h)[3], ((uint64_t*)h)[2], ((uint64_t*)h)[1], ((uint64_t*)h)[0], t, pos);
	}
}


//给区块bi的amount添加sum的金额
static inline void accept_amount(struct block_internal *bi, xdag_amount_t sum)
{
	if (!sum) {
		return;
	}

	bi->amount += sum;
	if (bi->flags & BI_OURS) {
		g_balance += sum;
		order_ourblocks_by_amount(bi);
	}
}

//apply_block
//交易手续费放到bi中 执行区块bi改变状态 要看看apply_block的是哪个block
static uint64_t apply_block(struct block_internal *bi)
{
	xdag_amount_t sum_in, sum_out;

//如果区块已经被主块指向过 即已经在主链中 即已经处理过
	if (bi->flags & BI_MAIN_REF) {
		return -1l;
	}

	bi->flags |= BI_MAIN_REF;

	for (int i = 0; i < bi->nlinks; ++i) {
		//返回区块fee
		xdag_amount_t ref_amount = apply_block(bi->link[i]);
		//已经被主链指向过 如果是地址块的话 不应该也是被指向了吗 如果是主链指向过的 不用再支付手续费
		if (ref_amount == -1l) {
			continue;
		}
		//被应用的区块的ref指向链接他们的bi
		bi->link[i]->ref = bi;
		if (bi->amount + ref_amount >= bi->amount) {
			//给区块bi添加每个链接的手续费
			accept_amount(bi, ref_amount);
		}
	}

	sum_in = 0, sum_out = bi->fee;

	for (int i = 0; i < bi->nlinks; ++i) {
		//看输入区块
		if (1 << i & bi->in_mask) {
			//如果指向的区块金额还小于需要用到的金额
			if (bi->link[i]->amount < bi->linkamount[i]) {
				return 0;
			}
			if (sum_in + bi->linkamount[i] < sum_in) {
				return 0;
			}
			sum_in += bi->linkamount[i];
		} else {
			//计算输出的金额
			if (sum_out + bi->linkamount[i] < sum_out) {
				return 0;
			}
			sum_out += bi->linkamount[i];
		}
	}

	if (sum_in + bi->amount < sum_in || sum_in + bi->amount < sum_out) {
		return 0;
	}

	for (int i = 0; i < bi->nlinks; ++i) {
		if (1 << i & bi->in_mask) {
			//对输入的区块减钱
			accept_amount(bi->link[i], (xdag_amount_t)0 - bi->linkamount[i]);
		} else {
			accept_amount(bi->link[i], bi->linkamount[i]);
		}
	}

	//给区块bi加 sum_in - sum_out
	accept_amount(bi, sum_in - sum_out);
	bi->flags |= BI_APPLIED;//将该区块标为使用过

	return bi->fee;
}

//取消区块bi的执行 类似回滚 将区块bi置为 未应用 和 未被主链引用
static uint64_t unapply_block(struct block_internal *bi)
{
	int i;

	if (bi->flags & BI_APPLIED) {
		xdag_amount_t sum = bi->fee;

		for (i = 0; i < bi->nlinks; ++i) {
			if (1 << i & bi->in_mask) {
				accept_amount(bi->link[i], bi->linkamount[i]);
				sum -= bi->linkamount[i];
			} else {
				accept_amount(bi->link[i], (xdag_amount_t)0 - bi->linkamount[i]);
				sum += bi->linkamount[i];
			}
		}

		accept_amount(bi, sum);
		bi->flags &= ~BI_APPLIED;
	}

	bi->flags &= ~BI_MAIN_REF;
	bi->ref = 0;

	for (i = 0; i < bi->nlinks; ++i) {
		if (bi->link[i]->ref == bi && bi->link[i]->flags & BI_MAIN_REF) {
			accept_amount(bi, unapply_block(bi->link[i]));
		}
	}

	return (xdag_amount_t)0 - bi->fee;
}


//**
static xdag_amount_t get_start_amount(uint64_t nmain) {
    xdag_amount_t start_amount = 0;
    if(nmain >= MAIN_APOLLO_HIGHT) {
        start_amount = MAIN_APOLLO_AMOUNT;
    } else {
        start_amount = MAIN_START_AMOUNT;
    }
    return start_amount;
}

static xdag_amount_t get_amount(uint64_t nmain) {
    xdag_amount_t amount = 0;
    xdag_amount_t start_amount = 0;

    start_amount = get_start_amount(nmain);
    amount = start_amount >> (nmain >> MAIN_BIG_PERIOD_LOG);
    return amount;
}
//**
// calculates current supply by specified count of main blocks
//根据当前主块数量计算当前xdag的供应量
// xdag_amount_t xdag_get_supply(uint64_t nmain)
// {
// 	xdag_amount_t res = 0, amount = MAIN_START_AMOUNT;

// 	while (nmain >> MAIN_BIG_PERIOD_LOG) {
// 		res += (1l << MAIN_BIG_PERIOD_LOG) * amount;
// 		nmain -= 1l << MAIN_BIG_PERIOD_LOG;
// 		amount >>= 1;
// 	}
// 	res += nmain * amount;
// 	return res;
// }

xdag_amount_t xdag_get_supply(uint64_t nmain)
{
	xdag_amount_t res = 0, amount = get_start_amount(nmain);
    uint64_t current_nmain = nmain;
    while (current_nmain >> MAIN_BIG_PERIOD_LOG) {
        res += (1l << MAIN_BIG_PERIOD_LOG) * amount;
        current_nmain -= 1l << MAIN_BIG_PERIOD_LOG;
        amount >>= 1;
    }
    res += current_nmain * amount;
    if(nmain >= MAIN_APOLLO_HIGHT) {
        // add before apollo amount
        res += (MAIN_APOLLO_HIGHT - 1) * (MAIN_START_AMOUNT - MAIN_APOLLO_AMOUNT);
    }
	return res;
}


//设置主块 主块的ref指向自己m
// static void set_main(struct block_internal *m)
// {
// 	//计算奖励
// 	xdag_amount_t amount = MAIN_START_AMOUNT >> (g_xdag_stats.nmain >> MAIN_BIG_PERIOD_LOG);

// //将区块设置为主块
// 	m->flags |= BI_MAIN;
// 	//给区块m添加奖励
// 	accept_amount(m, amount);
// 	//总区块数量加1
// 	g_xdag_stats.nmain++;


// 	if (g_xdag_stats.nmain > g_xdag_stats.total_nmain) {
// 		g_xdag_stats.total_nmain = g_xdag_stats.nmain;
// 	}

// //给m添加手续费
// 	accept_amount(m, apply_block(m));
// 	m->ref = m;
// 	log_block((m->flags & BI_OURS ? "MAIN +" : "MAIN  "), m->hash, m->time, m->storage_pos);
// }

static void set_main(struct block_internal *m)
{
	//计算奖励
	// xdag_amount_t amount = MAIN_START_AMOUNT >> (g_xdag_stats.nmain >> MAIN_BIG_PERIOD_LOG);
	xdag_amount_t amount = 0;

    amount = get_amount(g_xdag_stats.nmain);

//将区块设置为主块
	m->flags |= BI_MAIN;
	//给区块m添加奖励
	accept_amount(m, amount);
	//总区块数量加1
	g_xdag_stats.nmain++;


	if (g_xdag_stats.nmain > g_xdag_stats.total_nmain) {
		g_xdag_stats.total_nmain = g_xdag_stats.nmain;
	}

//给m添加手续费
	accept_amount(m, apply_block(m));
	m->ref = m;
	//如果是本地矿池生成的主块 用 “MAIN+”输出log 否则则是收到由其他矿池发过来的 用“MAIN ”输出log
	log_block((m->flags & BI_OURS ? "MAIN +" : "MAIN  "), m->hash, m->time, m->storage_pos);
}

static void unset_main(struct block_internal *m)
{
    xdag_amount_t amount = 0;
	g_xdag_stats.nmain--;
	g_xdag_stats.total_nmain--;
	// xdag_amount_t amount = MAIN_START_AMOUNT >> (g_xdag_stats.nmain >> MAIN_BIG_PERIOD_LOG);
	amount = get_amount(g_xdag_stats.nmain);
	m->flags &= ~BI_MAIN;
	accept_amount(m, (xdag_amount_t)0 - amount);
	accept_amount(m, unapply_block(m));
	log_block("UNMAIN", m->hash, m->time, m->storage_pos);
}

//回滚 将区块设置为非主块
// static void unset_main(struct block_internal *m)
// {
// 	g_xdag_stats.nmain--;
// 	g_xdag_stats.total_nmain--;
// 	xdag_amount_t amount = MAIN_START_AMOUNT >> (g_xdag_stats.nmain >> MAIN_BIG_PERIOD_LOG);
// 	m->flags &= ~BI_MAIN;
// 	accept_amount(m, (xdag_amount_t)0 - amount);
// 	accept_amount(m, unapply_block(m));
// 	log_block("UNMAIN", m->hash, m->time, m->storage_pos);
// }


//检查主链
static void check_new_main(void)
{
	struct block_internal *b, *p = 0;
	int i;

	//从top的区块中 找到一个最大难度的区块p将该区块 top_main_chain保存的区块是什么 是可以成为区块的备选
	//根据max_diff_link这条链找到当前是BI_MAIN的后一个区块 且该区块必须是MAIN_CHAIN 即p 如果p标志为BI_REF 且满足时间条件 则设置为主块
	//即是 从top_main_chain开始找 最早的一个不是BI_MAIN但是是BI_MAIN_CHAIN的区块 如果该区块还是BI_REF且该时间比当前时间戳早两秒以上 则可以成为主块

	//top_main_chain 是有max_diff_link 连接起来的一条链 里面存放的块中如果有MAIN_CHAIN标志的 
	for (b = top_main_chain, i = 0; b && !(b->flags & BI_MAIN); b = b->link[b->max_diff_link]) {
		if (b->flags & BI_MAIN_CHAIN) {
			p = b;
			++i;
		}
	}

	//判断当前时间是否比p的时间大两秒 且BI_REF即区块不是孤块中的
	if (p && (p->flags & BI_REF) && i > MAX_WAITING_MAIN && xdag_get_xtimestamp() >= p->time + 2 * 1024) {
		set_main(p);
	}
}


//取消主块知道回到b
static void unwind_main(struct block_internal *b)
{
	for (struct block_internal *t = top_main_chain; t && t != b; t = t->link[t->max_diff_link]) {
		t->flags &= ~BI_MAIN_CHAIN;
		if (t->flags & BI_MAIN) {
			unset_main(t);
		}
	}
}

//计算出可以用于签名的hash值 
//把key->pub & ~1 放在block后面 大小为sizeof(struct xdag_block) + sizeof(xdag_hash_t) + 1
//modified_block表示待签名的区块数据，modified_block中所有的输入交易和输出交易的签名字段都置为0 置零这块在哪里
//摘要计算 hash(modified_block # key_prefix_byte # public_key) public_key表示公钥的参数x，长度为32字节
static inline void hash_for_signature(struct xdag_block b[2], const struct xdag_public_key *key, xdag_hash_t hash)
{
	// int i;
	// fprintf(stdout,"\nhash_for_signature ");

	// for(i = 0; i < XDAG_BLOCK_FIELDS; ++i) {
	// 	uint64_t *tmphh = b[0].field[i].data;
	// 	fprintf(stdout,"(before signature block in )XDAG_FIELD : -> %d  :hash: %016llx%016llx%016llx%016llx\n",i,
	// 	(unsigned long long)tmphh[3], (unsigned long long)tmphh[2], (unsigned long long)tmphh[1], (unsigned long long)tmphh[0]);
	// }

//b+1指的是b[1]
	memcpy((uint8_t*)(b + 1) + 1, (void*)((uintptr_t)key->pub & ~1l), sizeof(xdag_hash_t));

	*(uint8_t*)(b + 1) = ((uintptr_t)key->pub & 1) | 0x02;

	xdag_hash(b, sizeof(struct xdag_block) + sizeof(xdag_hash_t) + 1, hash);

	// for(i = 0; i < XDAG_BLOCK_FIELDS; ++i) {
	// 	uint64_t *tmphh = b[0].field[i].data;
	// 	fprintf(stdout,"(after signature block in )XDAG_FIELD : -> %d  :hash: %016llx%016llx%016llx%016llx\n",i,
	// 	(unsigned long long)tmphh[3], (unsigned long long)tmphh[2], (unsigned long long)tmphh[1], (unsigned long long)tmphh[0]);
	// }

	xdag_debug("Hash  : hash=[%s] data=[%s]", xdag_log_hash(hash),
		xdag_log_array(b, sizeof(struct xdag_block) + sizeof(xdag_hash_t) + 1));
}

// returns a number of public key from 'keys' array with lengh 'keysLength', which conforms to the signature starting from field signo_r of the block b
// returns -1 if nothing is found
//验证签名  
static int valid_signature(const struct xdag_block *b, int signo_r, int keysLength, struct xdag_public_key *keys)
{
	struct xdag_block buf[2];
	xdag_hash_t hash;
	int i, signo_s = -1;

	memcpy(buf, b, sizeof(struct xdag_block));

//因为签名也是两个字段的一个字段是r 一个字段是s
	for(i = signo_r; i < XDAG_BLOCK_FIELDS; ++i) {
		if(xdag_type(b, i) == XDAG_FIELD_SIGN_IN || xdag_type(b, i) == XDAG_FIELD_SIGN_OUT) {
			memset(&buf[0].field[i], 0, sizeof(struct xdag_field));
			if(i > signo_r && signo_s < 0 && xdag_type(b, i) == xdag_type(b, signo_r)) {
				signo_s = i;
			}
		}
	}

	if(signo_s >= 0) {
		for(i = 0; i < keysLength; ++i) {
			hash_for_signature(buf, keys + i, hash);

#if USE_OPTIMIZED_EC == 1
			if(!xdag_verify_signature_optimized_ec(keys[i].pub, hash, b->field[signo_r].data, b->field[signo_s].data)) {
#elif USE_OPTIMIZED_EC == 2
			int res1 = !xdag_verify_signature_optimized_ec(keys[i].pub, hash, b->field[signo_r].data, b->field[signo_s].data);
			int res2 = !xdag_verify_signature(keys[i].key, hash, b->field[signo_r].data, b->field[signo_s].data);
			if(res1 != res2) {
				xdag_warn("Different result between openssl and secp256k1: res openssl=%2d res secp256k1=%2d key parity bit = %ld key=[%s] hash=[%s] r=[%s], s=[%s]",
					res2, res1, ((uintptr_t)keys[i].pub & 1), xdag_log_hash((uint64_t*)((uintptr_t)keys[i].pub & ~1l)),
					xdag_log_hash(hash), xdag_log_hash(b->field[signo_r].data), xdag_log_hash(b->field[signo_s].data));
			}
			if(res2) {
#else
		//验证成功的话 返回i
			if(!xdag_verify_signature(keys[i].key, hash, b->field[signo_r].data, b->field[signo_s].data)) {
#endif
				return i;
			}
		}
	}

	return -1;
}

//移除索引
static int remove_index(struct block_internal *bi)
{
	if(g_bi_index_enable) {
		pthread_mutex_lock(&rbtree_mutex);
		ldus_rbtree_remove(&root, &bi->index->node);
		pthread_mutex_unlock(&rbtree_mutex);
		free(bi->index);
		bi->index = NULL;
	} else {
		pthread_mutex_lock(&rbtree_mutex);
		ldus_rbtree_remove(&root, &bi->node);
		pthread_mutex_unlock(&rbtree_mutex);
	}
	return 0;
}

//插入索引
static int insert_index(struct block_internal *bi)
{
	if(g_bi_index_enable) {
		struct block_internal_index *index = (struct block_internal_index *)malloc(sizeof(struct block_internal_index));
		if(!index) {
			xdag_err("block index malloc failed. [func: add_block_nolock]");
			return -1;
		}
		memset(index, 0, sizeof(struct block_internal_index));
		memcpy(index->hash, bi->hash, sizeof(xdag_hash_t));
		index->bi = bi;
		bi->index = index;

		pthread_mutex_lock(&rbtree_mutex);
		ldus_rbtree_insert(&root, &index->node);
		pthread_mutex_unlock(&rbtree_mutex);
	} else {
		pthread_mutex_lock(&rbtree_mutex);
		ldus_rbtree_insert(&root, &bi->node);
		pthread_mutex_unlock(&rbtree_mutex);
	}
	return 0;
}

//timestamp 加入区块的时间 如果区块的epoch小于把区块加入时的epoch 且区块的难度比pretop_main_chain大的时候 更新pretop_main_chain
#define set_pretop(b) if ((b) && MAIN_TIME((b)->time) < MAIN_TIME(timestamp) && \
		(!pretop_main_chain || xdag_diff_gt((b)->difficulty, pretop_main_chain->difficulty))) { \
		pretop_main_chain = (b); \
		log_block("Pretop", (b)->hash, (b)->time, (b)->storage_pos); \
}

/* checks and adds a new block to the storage
 * returns:
 *		>0 = block was added
 *		0  = block exists
 *		<0 = error
 */

//添加区块

static int add_block_nolock(struct xdag_block *newBlock, xtime_t limit)
{
	fprintf(stdout, "->into add_block_nolock\n");


	const xtime_t timestamp = xdag_get_xtimestamp();
	fprintf(stdout,"timestamp:%llu,main_time(timestamp):%llu start_main_time:%llu",timestamp,MAIN_TIME(timestamp),xdag_start_main_time());
	uint64_t sum_in = 0, sum_out = 0, *psum = NULL;
	const uint64_t transportHeader = newBlock->field[0].transport_header;
	//public_keys保存的是每个字段的
	struct xdag_public_key public_keys[16], *our_keys = 0;
	int i = 0, j = 0;
	int keysCount = 0, ourKeysCount = 0;
	int signInCount = 0, signOutCount = 0;
	int signinmask = 0, signoutmask = 0;
	int inmask = 0, outmask = 0, remark_index = 0;
	int verified_keys_mask = 0, err = 0, type = 0;


	struct block_internal tmpNodeBlock, *blockRef = NULL, *blockRef0 = NULL;


	struct block_internal* blockRefs[XDAG_BLOCK_FIELDS-1]= {0};


	struct block_internal* tmpRefs[XDAG_BLOCK_FIELDS-1]= {0};
	xdag_diff_t diff0, diff;

	//用于缓存hit和miss
	int32_t cache_hit = 0, cache_miss = 0;

	memset(&tmpNodeBlock, 0, sizeof(struct block_internal));
	newBlock->field[0].transport_header = 0;
	xdag_hash(newBlock, sizeof(struct xdag_block), tmpNodeBlock.hash);

//	如果已经存在了
	if(block_by_hash(tmpNodeBlock.hash)){

		struct block_internal *bi = block_by_hash(tmpNodeBlock.hash);

		return 0;
	}
//	看第一个字段类型是不是区块头类型 是的话就是普通区块 如果不是普通区块的话 就说明是传输块
	if(xdag_type(newBlock, 0) != g_block_header_type) {
		i = xdag_type(newBlock, 0);
		err = 1;
		goto end;
	}

	tmpNodeBlock.time = newBlock->field[0].time;

//时间戳不符合要求						16384
//如果有limit 则要在limit内的区块才处理 添加  16s 64s/4
	if(tmpNodeBlock.time > timestamp + MAIN_CHAIN_PERIOD / 4 || tmpNodeBlock.time < XDAG_ERA
		|| (limit && timestamp - tmpNodeBlock.time > limit)) {
		i = 0;
		err = 2;
		goto end;
	}

	//只会获取[1]~[15]的字段
	for(i = 1; i < XDAG_BLOCK_FIELDS; ++i) {
		//查看每个字段的类型
		type = xdag_type(newBlock, i);
		fprintf(stdout,"Fields[%d]:type:%d \n ",i,type);
		switch((type = xdag_type(newBlock, i))) {
			case XDAG_FIELD_NONCE:
				break;
			case XDAG_FIELD_IN:
				inmask |= 1 << i;
				break;
			case XDAG_FIELD_OUT:
				outmask |= 1 << i;
				break;
			case XDAG_FIELD_SIGN_IN:
				//偶数还是奇数判断 如果是奇数的话 因为两个sign_in才组成一个输入签名
				if(++signInCount & 1) {
					signinmask |= 1 << i;
				}
				break;
			case XDAG_FIELD_SIGN_OUT:
				if(++signOutCount & 1) {
					signoutmask |= 1 << i;
				}
				break;
			case XDAG_FIELD_PUBLIC_KEY_0:
			case XDAG_FIELD_PUBLIC_KEY_1:
			//保存公钥 这里的公钥是压缩公钥
				if((public_keys[keysCount].key = xdag_public_to_key(newBlock->field[i].data, type - XDAG_FIELD_PUBLIC_KEY_0))) {
					public_keys[keysCount++].pub = (uint64_t*)((uintptr_t)&newBlock->field[i].data | (type - XDAG_FIELD_PUBLIC_KEY_0));
				}
				break;

			case XDAG_FIELD_REMARK:
				tmpNodeBlock.flags |= BI_REMARK;
				remark_index = i;
				break;
			case XDAG_FIELD_RESERVE1:
			case XDAG_FIELD_RESERVE2:
			case XDAG_FIELD_RESERVE3:
			case XDAG_FIELD_RESERVE4:
			case XDAG_FIELD_RESERVE5:
			case XDAG_FIELD_RESERVE6:
				break;
			default:
				err = 3;
				goto end;
		}
	}

	//如果是轻节点 outmask清零
	if(g_light_mode) {
		outmask = 0;
	}

	//如果输出签名是奇数 end 因为在xdag中输出只能是偶数 输入可以是奇数 奇数时最后一个输入作为随机数
	if(signOutCount & 1) {
		i = signOutCount;
		err = 4;
		goto end;
	}

	/* check remark */
	if(tmpNodeBlock.flags & BI_REMARK) {
		if(!remark_acceptance(newBlock->field[remark_index].remark)) {
			err = 0xC;
			goto end;
		}
	}

	/* if not read from storage and timestamp is ...ffff and last field is nonce then the block is extra */
	//如果不是从持久化中读取出来的话 说明是新建的或者接收到的 且时间是 ...ffff 且最后一个字段是输入签名类型 此时用作nonce 这个块就是附加块 ffff应该只能是主块 从别的矿池接收到的主块先作为EXTRA
	if (!g_light_mode && (transportHeader & (sizeof(struct xdag_block) - 1)) 
			&& (tmpNodeBlock.time & (MAIN_CHAIN_PERIOD - 1)) == (MAIN_CHAIN_PERIOD - 1)
			&& (signinmask & (1 << (XDAG_BLOCK_FIELDS - 1)))) {
		tmpNodeBlock.flags |= BI_EXTRA;
	}


//blockRefs保存所有输入输出的引用区块 最多只能引用（链接）15个区块
	for(i = 1; i < XDAG_BLOCK_FIELDS; ++i) {
		
		if(1 << i & (inmask | outmask)) {
			//将输入和输出的指向区块找到 并保存于blockRefs中
			blockRefs[i-1] = block_by_hash(newBlock->field[i].hash);
			

			if(!blockRefs[i-1]) {
				err = 5;
				goto end;
			}
			//如果引用的区块时间大于当前新区块时间 则end
			if(blockRefs[i-1]->time >= tmpNodeBlock.time) {
				err = 6;
				goto end;
			}
			//如果当前新区块的连接已经超出最大连接数 这部分有什么意义？初始化nlinks不应该一开始就等于0吗？
			if(tmpNodeBlock.nlinks >= MAX_LINKS) {
				err = 7;
				goto end;
			}
		}
	}

	if(!g_light_mode) {
		check_new_main();
	}

//our_keys保存自身的密钥对 如果输出字段存在
	if(signOutCount) {
		our_keys = xdag_wallet_our_keys(&ourKeysCount);
	}

	for(i = 1; i < XDAG_BLOCK_FIELDS; ++i) {
		if(1 << i & (signinmask | signoutmask)) {
			int keyNumber = valid_signature(newBlock, i, keysCount, public_keys);
			if(keyNumber >= 0) {
				//确认的密钥索引的掩码
				verified_keys_mask |= 1 << keyNumber;
			}
			//如果输出 跟 自己的密钥匹配 则这个区块是自己的
			if(1 << i & signoutmask && !(tmpNodeBlock.flags & BI_OURS) && (keyNumber = valid_signature(newBlock, i, ourKeysCount, our_keys)) >= 0) {
				tmpNodeBlock.flags |= BI_OURS;
				tmpNodeBlock.n_our_key = keyNumber;
			}
		}
	}

	for(i = j = 0; i < keysCount; ++i) {
		if(1 << i & verified_keys_mask) {
			if(i != j) {
				xdag_free_key(public_keys[j].key);
			}
			memcpy(public_keys + j++, public_keys + i, sizeof(struct xdag_public_key));
		}
	}

	keysCount = j;
	tmpNodeBlock.difficulty = diff0 = xdag_hash_difficulty(tmpNodeBlock.hash);
	sum_out += newBlock->field[0].amount;
	tmpNodeBlock.fee = newBlock->field[0].amount;
	if (tmpNodeBlock.fee) {
		tmpNodeBlock.flags &= ~BI_EXTRA;
	}

	//计算出哪个链接块使自身难度最大
	for(i = 1; i < XDAG_BLOCK_FIELDS; ++i) {
		if(1 << i & (inmask | outmask)) {
			blockRef = blockRefs[i-1];
			//如果是输入的话
			if(1 << i & inmask) {
				//输入金额
				if(newBlock->field[i].amount) {
					int32_t res = 1;
					if(CACHE) {
						res = check_signature_out_cached(blockRef, public_keys, keysCount, &cache_hit, &cache_miss);
					} else {
						//验证是否可以使用这个输入区块 返回0代表可以使用
						res = check_signature_out(blockRef, public_keys, keysCount);
					}
					if(res) {
						err = res;
						goto end;
					}

				}
				psum = &sum_in;
				tmpNodeBlock.in_mask |= 1 << tmpNodeBlock.nlinks;
			} else {
				psum = &sum_out;
			}

			if (newBlock->field[i].amount) {
				tmpNodeBlock.flags &= ~BI_EXTRA;
			}

			if(*psum + newBlock->field[i].amount < *psum) {
				err = 0xA;
				goto end;
			}

			*psum += newBlock->field[i].amount;
			tmpNodeBlock.link[tmpNodeBlock.nlinks] = blockRef;
			tmpNodeBlock.linkamount[tmpNodeBlock.nlinks] = newBlock->field[i].amount;

			if(MAIN_TIME(blockRef->time) < MAIN_TIME(tmpNodeBlock.time)) {
				//diff0 区块自身计算出的难度
				diff = xdag_diff_add(diff0, blockRef->difficulty);
			} else {
				diff = blockRef->difficulty;

				while(blockRef && MAIN_TIME(blockRef->time) == MAIN_TIME(tmpNodeBlock.time)) {
					blockRef = blockRef->link[blockRef->max_diff_link];
				}
				if(blockRef && xdag_diff_gt(xdag_diff_add(diff0, blockRef->difficulty), diff)) {
					diff = xdag_diff_add(diff0, blockRef->difficulty);
				}
			}
			//如果diff大于当前区块的难度 区块的难度值等于自身的难度值加上链接块中最大难度值的难度 并将max_diff_link设置为那个链接的区块
			if(xdag_diff_gt(diff, tmpNodeBlock.difficulty)) {
				tmpNodeBlock.difficulty = diff;
				tmpNodeBlock.max_diff_link = tmpNodeBlock.nlinks;
			}

			tmpNodeBlock.nlinks++;
		}
	}

	//用来实现lru
	if(CACHE) {
		cache_retarget(cache_hit, cache_miss);
	}

//sum_out应该是等于field[0]的金额的 即是转账金额
	if(tmpNodeBlock.in_mask ? sum_in < sum_out : sum_out != newBlock->field[0].amount) {
		err = 0xB;
		goto end;
	}

	struct block_internal *nodeBlock;
	//extra block太多的话要重利用最早的 把最早的附加块从orphan中拿出来
	if (g_xdag_extstats.nextra > MAX_ALLOWED_EXTRA
			&& (g_xdag_state == XDAG_STATE_SYNC || g_xdag_state == XDAG_STATE_STST)) {
		/* if too many extra blocks then reuse the oldest */
		nodeBlock = g_orphan_first[1]->orphan_bi;
		//将该块重用 不持久化 不过该块不再是附加块
		remove_orphan(nodeBlock, ORPHAN_REMOVE_REUSE);
		remove_index(nodeBlock);
		if (g_xdag_stats.nblocks-- == g_xdag_stats.total_nblocks)
			g_xdag_stats.total_nblocks--;
			//如果是自己的区块 还要从本地区块队列中将区块删除
		if (nodeBlock->flags & BI_OURS) {
			remove_ourblock(nodeBlock);
		}
	} else {
		nodeBlock = xdag_malloc(sizeof(struct block_internal));
	}
	if(!nodeBlock) {
		err = 0xC;
		goto end;
	}

	if(CACHE && signOutCount) {
		cache_add(newBlock, tmpNodeBlock.hash);
	}

	//持久化

	
	//如果已经存储好的 即是说如果就在本地中有的加载进内存的话
	if(!(transportHeader & (sizeof(struct xdag_block) - 1))) {
		tmpNodeBlock.storage_pos = transportHeader;
		//如果不是附加块的话 现在就可以持久化了
	} else if (!(tmpNodeBlock.flags & BI_EXTRA)) {
		tmpNodeBlock.storage_pos = xdag_storage_save(newBlock);
	} else {
		/* do not store extra block right now */
		//先不存储extrablock 因为不一定要把它存进本地持久化
		tmpNodeBlock.storage_pos = -2l;
	}

	memcpy(nodeBlock, &tmpNodeBlock, sizeof(struct block_internal));
	atomic_init_uintptr(&nodeBlock->backrefs, (uintptr_t)NULL);
	if(nodeBlock->flags & BI_REMARK){
		atomic_init_uintptr(&nodeBlock->remark, (uintptr_t)NULL);
	}

//如果索引添加成功的话
	if(!insert_index(nodeBlock)) {
		g_xdag_stats.nblocks++;
	} else {
		err = 0xC;
		goto end;
	}

	if(g_xdag_stats.nblocks > g_xdag_stats.total_nblocks) {
		g_xdag_stats.total_nblocks = g_xdag_stats.nblocks;
	}

//看nodeblock是不是难度够大 大于pretopmain的区块难度
	set_pretop(nodeBlock);
	set_pretop(top_main_chain);

	//如果当前区块难度大于当前状态的难度
	if(xdag_diff_gt(tmpNodeBlock.difficulty, g_xdag_stats.difficulty)) {
		/* Only log this if we are NOT loading state */
		if(g_xdag_state != XDAG_STATE_LOAD)
			xdag_info("Diff  : %llx%016llx (+%llx%016llx)", xdag_diff_args(tmpNodeBlock.difficulty), xdag_diff_args(diff0));
		
		//将nodeblock的链接的最大难度的区块设置为主链上的区块 我们还没标记为主链 把新区块的最大难度链标记为主链直到我们本地也已经标记了为主链的位置
		for(blockRef = nodeBlock, blockRef0 = 0; blockRef && !(blockRef->flags & BI_MAIN_CHAIN); blockRef = blockRef->link[blockRef->max_diff_link]) {
			if((!blockRef->link[blockRef->max_diff_link] || xdag_diff_gt(blockRef->difficulty, blockRef->link[blockRef->max_diff_link]->difficulty))
				&& (!blockRef0 || MAIN_TIME(blockRef0->time) > MAIN_TIME(blockRef->time))) {
				blockRef->flags |= BI_MAIN_CHAIN;
				blockRef0 = blockRef;
			}
		}

		if(blockRef && blockRef0 && blockRef != blockRef0 && MAIN_TIME(blockRef->time) == MAIN_TIME(blockRef0->time)) {
			blockRef = blockRef->link[blockRef->max_diff_link];
		}
		//回到接收到的区块跟我们共同都标记了主链位置的区块
		unwind_main(blockRef);
		top_main_chain = nodeBlock;
		g_xdag_stats.difficulty = tmpNodeBlock.difficulty;

		//修改最大难度
		if(xdag_diff_gt(g_xdag_stats.difficulty, g_xdag_stats.max_difficulty)) {
			g_xdag_stats.max_difficulty = g_xdag_stats.difficulty;
		}

		err = -1; //err是负数才是成功的
	} else if (tmpNodeBlock.flags & BI_EXTRA) {
		err = 0;
	} else {
		err = -1;
	}

	if(tmpNodeBlock.flags & BI_OURS) {
		add_ourblock(nodeBlock);
	}

	//当前区块链接的区块 从orphan中移除 附加块用附加块的方式移除 常规块用常规块的方式移除 声明现在我已经链接了这些区块 这些区块已经是有人指向的了 所以它们要从orphan链中去除了 避免我后续产生新的块又用到它们
	for(i = 0; i < tmpNodeBlock.nlinks; ++i) {
		remove_orphan(tmpNodeBlock.link[i],
				tmpNodeBlock.flags & BI_EXTRA ? ORPHAN_REMOVE_EXTRA : ORPHAN_REMOVE_NORMAL);
				//附加块引用的正常区块暂时不从orphan链中移除 引用的是附加块的话 持久化附加块 移除附加块链接的区块
				//非附加块引用的所有区块都会从orphan链中移除 如果是附加块的话 移除附加块 但不会移除附加块引用的区块

		//如果链接块是有交易的话
		if(tmpNodeBlock.linkamount[i]) {
			blockRef = tmpNodeBlock.link[i];
			//做个back链接 感觉应该是跟交易有关
			add_backref(blockRef, nodeBlock);
		}
	}
	
	//
	add_orphan(nodeBlock, newBlock);

	log_block((tmpNodeBlock.flags & BI_OURS ? "Good +" : "Good  "), tmpNodeBlock.hash, tmpNodeBlock.time, tmpNodeBlock.storage_pos);


	//计算哈希rate
	i = MAIN_TIME(nodeBlock->time) & (HASHRATE_LAST_MAX_TIME - 1);
	if(MAIN_TIME(nodeBlock->time) > MAIN_TIME(g_xdag_extstats.hashrate_last_time)) {
		memset(g_xdag_extstats.hashrate_total + i, 0, sizeof(xdag_diff_t));
		memset(g_xdag_extstats.hashrate_ours + i, 0, sizeof(xdag_diff_t));
		g_xdag_extstats.hashrate_last_time = nodeBlock->time;
	}

	if(xdag_diff_gt(diff0, g_xdag_extstats.hashrate_total[i])) {
		g_xdag_extstats.hashrate_total[i] = diff0;
	}

	if(tmpNodeBlock.flags & BI_OURS && xdag_diff_gt(diff0, g_xdag_extstats.hashrate_ours[i])) {
		g_xdag_extstats.hashrate_ours[i] = diff0;
	}

end:
	for(j = 0; j < keysCount; ++j) {
		xdag_free_key(public_keys[j].key);
	}

	if(err > 0) {
		char buf[32] = {0};
		err |= i << 4;
		sprintf(buf, "Err %2x", err & 0xff);
		log_block(buf, tmpNodeBlock.hash, tmpNodeBlock.time, transportHeader);
	}

	return -err;
}

void *add_block_callback(void *block, void *data)
{
	fprintf(stdout,"add block callback\n");

	struct xdag_block *b = (struct xdag_block *)block;
	xtime_t *t = (xtime_t*)data;
	int res;

	pthread_mutex_lock(&block_mutex);

	if(*t < XDAG_ERA) {
		(res = add_block_nolock(b, *t));
	} else if((res = add_block_nolock(b, 0)) >= 0 && b->field[0].time > *t) {
		*t = b->field[0].time;
	}

	pthread_mutex_unlock(&block_mutex);

	if(res >= 0) {
		xdag_sync_pop_block(b);
	}

	return 0;
}

/* checks and adds block to the storage. Returns non-zero value in case of error. */
int xdag_add_block(struct xdag_block *b)
{
	fprintf(stdout, "->into xdag_add_block\n");
	pthread_mutex_lock(&block_mutex);
	int res = add_block_nolock(b, g_time_limit);
	pthread_mutex_unlock(&block_mutex);

	return res;
}

#define setfld(fldtype, src, hashtype) ( \
		block[0].field[0].type |= (uint64_t)(fldtype) << (i << 2), \
			memcpy(&block[0].field[i++], (void*)(src), sizeof(hashtype)) \
		)

#define pretop_block() (top_main_chain && MAIN_TIME(top_main_chain->time) == MAIN_TIME(send_time) ? pretop_main_chain : top_main_chain)

/* create a new block
 * The first 'ninput' field 'fields' contains the addresses of the inputs and the corresponding quantity of XDAG,
 * in the following 'noutput' fields similarly - outputs, fee; send_time (time of sending the block);
 * if it is greater than the current one, then the mining is performed to generate the most optimal hash
 */
struct xdag_block* xdag_create_block(struct xdag_field *fields, int inputsCount, int outputsCount, int hasRemark,
	xdag_amount_t fee, xtime_t send_time, xdag_hash_t block_hash_result)
{
	pthread_mutex_lock(&g_create_block_mutex);
	struct xdag_block block[2];
	int i, j, res, mining, defkeynum, keysnum[XDAG_BLOCK_FIELDS], nkeys, nkeysnum = 0, outsigkeyind = -1, has_pool_tag = 0;
	//defkey指向默认密钥对 keys指向密钥对组 key指向一个密钥对 
	//defkeynum是默认密钥在密钥组的索引 keys是密钥组 nkeys是密钥组的个数 defkey是默认密钥
	struct xdag_public_key *defkey = xdag_wallet_default_key(&defkeynum), *keys = xdag_wallet_our_keys(&nkeys), *key;
	xdag_hash_t signatureHash;
	xdag_hash_t newBlockHash;
	struct block_internal *ref, *pretop = pretop_block();
	struct orphan_block *oref;

//这里会改变outsigkeyind
//keysnum 保存的是输出的密钥对组的各个索引 nkeysnum是密钥对组的个数
	
	for (i = 0; i < inputsCount; ++i) {
		//找到所有的输入 判断这些输入是不是我们的
		ref = block_by_hash(fields[i].hash);
		if (!ref || !(ref->flags & BI_OURS)) {
			pthread_mutex_unlock(&g_create_block_mutex);
			return NULL;
		}
		//如果当前密钥有重复就不增加keysnum 如果没有重复的话 会去判断是不是等于默认密钥
		for (j = 0; j < nkeysnum && ref->n_our_key != keysnum[j]; ++j);

		if (j == nkeysnum) {
			//找到当前指向默认密钥的输入 outsigkeyind指向keysnum中默认密钥的索引
			if (outsigkeyind < 0 && ref->n_our_key == defkeynum) {
				outsigkeyind = nkeysnum; //第一次循环=0 =1 索引默认密钥
			}
			//keysnum存储当前所有输入的密钥 不重复
			keysnum[nkeysnum++] = ref->n_our_key;
		}
	}
	pthread_mutex_unlock(&g_create_block_mutex);

//1 区块头 输入 输出 掩码 3*密钥对组（签名2 + 公钥1） outsigkeyind指向默认密钥的索引 有默认密钥的话 实质上就是交易块 第一个输出其实是填写自己的第一个地址块 且其中有一个输入也是用的该密钥 
//如果小于0说明密钥组中没有默认密钥

//1. 生成地址块时 res0 = 1 + 2 一个字段头 两个半签名 不用附带公钥 可以留着供别人验证 
//主要是主块 地址块 见证块 用到默认密钥 用来给别人验证 
//主块可以像地址块一样作为输入

	int res0 = 1 + inputsCount + outputsCount + hasRemark + 3 * nkeysnum + (outsigkeyind < 0 ? 2 : 0);

	if (res0 > XDAG_BLOCK_FIELDS) {
		xdag_err("create block failed, exceed max number of fields.");
		return NULL;
	}

	if (!send_time) {
		send_time = xdag_get_xtimestamp();
		mining = 0;
	} else {
		//挖主块的时候
		mining = (send_time > xdag_get_xtimestamp() && res0 + 1 <= XDAG_BLOCK_FIELDS);
	}

//挖矿的话还要再留一个字段 输入签名
	res0 += mining;

#if REMARK_ENABLED
	/* reserve field for pool tag in generated main block */
	has_pool_tag = g_pool_has_tag;
	res0 += has_pool_tag * mining;
#endif

 begin:
	res = res0;
	memset(block, 0, sizeof(struct xdag_block));
	i = 1;
	// mining=1时 type（64bits） ： 0100...1 否则 type ：00...1 如果mining最后一个字段是输入签名
	block[0].field[0].type = g_block_header_type | (mining ? (uint64_t)XDAG_FIELD_SIGN_IN << ((XDAG_BLOCK_FIELDS - 1) * 4) : 0); 
	block[0].field[0].time = send_time;//如果主块 ..ffff
	block[0].field[0].amount = fee;

	if (g_light_mode) {
		pthread_mutex_lock(&g_create_block_mutex);
		if (res < XDAG_BLOCK_FIELDS && ourfirst) {
			//设置自己的第一个地址块地址作为第一个输出
			fprintf(stdout,"-> set fields[0] self address as first output");
			setfld(XDAG_FIELD_OUT, ourfirst->hash, xdag_hashlow_t);
			res++;
		}
		pthread_mutex_unlock(&g_create_block_mutex);
	} else {
		pthread_mutex_lock(&block_mutex);
		if (res < XDAG_BLOCK_FIELDS && mining && pretop && pretop->time < send_time) {
			log_block("Mintop", pretop->hash, pretop->time, pretop->storage_pos);
			//设置当前最新块作为第一个输出
			setfld(XDAG_FIELD_OUT, pretop->hash, xdag_hashlow_t);
			res++;
		}

		//从orphan中取出还未被连接的区块
		for (oref = g_orphan_first[0]; oref && res < XDAG_BLOCK_FIELDS; oref = oref->next) {
			ref = oref->orphan_bi;
			if (ref->time < send_time) {
				setfld(XDAG_FIELD_OUT, ref->hash, xdag_hashlow_t);
				res++;
			}
		}
		pthread_mutex_unlock(&block_mutex);
	}
	//设置输入
	for (j = 0; j < inputsCount; ++j) {
		setfld(XDAG_FIELD_IN, fields + j, xdag_hash_t);
	}
	//设置输出
	for (j = 0; j < outputsCount; ++j) {
		setfld(XDAG_FIELD_OUT, fields + inputsCount + j, xdag_hash_t);
	}
	//设置掩码
	if(hasRemark) {
		setfld(XDAG_FIELD_REMARK, fields + inputsCount + outputsCount, xdag_remark_t);
	}
	//设置
	if(mining && has_pool_tag) {
		setfld(XDAG_FIELD_REMARK, g_pool_tag, xdag_remark_t);
	}

	//nkeysnum是当前输入的密钥数量
	for (j = 0; j < nkeysnum; ++j) {
		key = keys + keysnum[j]; //对应每个输入的密钥 最后一个密钥对对应输出签名
		fprintf(stdout,"is j == outsigkeyind :%d",j == outsigkeyind);
		//如果是默认密钥则设置为输出签名 否则是输入签名 填入type中
		block[0].field[0].type |= (uint64_t)((j == outsigkeyind ? XDAG_FIELD_SIGN_OUT : XDAG_FIELD_SIGN_IN) * 0x11) << ((i + j + nkeysnum) * 4);
		//未压缩公钥 520位 65字节 1个字节前缀 04 + 32个字节是x + 32个字节是y 
		//根据未压缩公钥最后一位是偶数还是奇数
		//分为两种 前缀03+x(如果y是奇数)，前缀02+x(如果y是偶数)
		//key->pub & ~1l：key->pub 最低位置零 key->pub & 1：取最低位 区分偶数公钥还是奇数公钥 xdag中在 x后加了一位以辨别是偶数公钥还是奇数公钥 pub的最后一位是奇偶校验位
		setfld(XDAG_FIELD_PUBLIC_KEY_0 + ((uintptr_t)key->pub & 1), (uintptr_t)key->pub & ~1l, xdag_hash_t);
	}

//给地址块用 见证块也是用这个 主块也是用这个 即是说没有输入中有默认密钥 即是没有输入 设为输出签名
	if(outsigkeyind < 0) {
		//两个字段5 *0x11
		block[0].field[0].type |= (uint64_t)(XDAG_FIELD_SIGN_OUT * 0x11) << ((i + j + nkeysnum) * 4);
	}


//填入签名 多少个密钥 多少个签名
	for (j = 0; j < nkeysnum; ++j, i += 2) {
		key = keys + keysnum[j];
		hash_for_signature(block, key, signatureHash);
		xdag_sign(key->key, signatureHash, block[0].field[i].data, block[0].field[i + 1].data);

	}

//给地址块用 见证块也是用这个 主块也是用这个
	if (outsigkeyind < 0) {
		//计算待签名数据摘要
		hash_for_signature(block, defkey, signatureHash);
		//signatureHash是待签名的数据
		xdag_sign(defkey->key, signatureHash, block[0].field[i].data, block[0].field[i + 1].data);
	}

	//如果是挖主块
	if (mining) {
		if(!do_mining(block, &pretop, send_time)) {
			goto begin;
		}
	}

	//计算出hash
	xdag_hash(block, sizeof(struct xdag_block), newBlockHash);


//如果是在挖矿 记录hash和nonce
	if(mining) {
		memcpy(g_xdag_mined_hashes[MAIN_TIME(send_time) & (CONFIRMATIONS_COUNT - 1)],
			newBlockHash, sizeof(xdag_hash_t));
		memcpy(g_xdag_mined_nonce[MAIN_TIME(send_time) & (CONFIRMATIONS_COUNT - 1)],
			block[0].field[XDAG_BLOCK_FIELDS - 1].data, sizeof(xdag_hash_t));
	}

	log_block("Create", newBlockHash, block[0].field[0].time, 1);
	
	if(block_hash_result != NULL) {
		memcpy(block_hash_result, newBlockHash, sizeof(xdag_hash_t));
	}

	struct xdag_block *new_block = (struct xdag_block *)malloc(sizeof(struct xdag_block));
	if(new_block) {
		memcpy(new_block, block, sizeof(struct xdag_block));
	}	
	fprintf(stdout,"block hash is hash: %016llx%016llx%016llx%016llx\n",(unsigned long long)newBlockHash[3], (unsigned long long)newBlockHash[2], (unsigned long long)newBlockHash[1], (unsigned long long)newBlockHash[0]);
	return new_block;
}

/* create and publish a block
* The first 'ninput' field 'fields' contains the addresses of the inputs and the corresponding quantity of XDAG,
* in the following 'noutput' fields similarly - outputs, fee; send_time (time of sending the block);
* if it is greater than the current one, then the mining is performed to generate the most optimal hash
*/
int xdag_create_and_send_block(struct xdag_field *fields, int inputsCount, int outputsCount, int hasRemark,
	xdag_amount_t fee, xtime_t send_time, xdag_hash_t block_hash_result)
{
	fprintf(stdout, "->into xdag_create_and_send_block,nmain is \n");
	fprintf(stdout,"nmain is %llu ,total main is %llu ,nblocks is %llu, total nblocks is %llu \n",g_xdag_stats.nmain,g_xdag_stats.total_nmain,g_xdag_stats.nblocks,g_xdag_stats.total_nblocks);

	//1. 做好地址块
	//2. 生成交易块
	struct xdag_block *block = xdag_create_block(fields, inputsCount, outputsCount, hasRemark, fee, send_time, block_hash_result);
	if(!block) {
		return 0;
	}

	//1. 传输头设置为1
	//2. 传输头设置为1
	block->field[0].transport_header = 1;
	int res = xdag_add_block(block);
	if(res > 0) {
		xdag_send_new_block(block);
		res = 1;
	} else {
		res = 0;
	}
	free(block);	

	return res;
}

//用于挖主块 生成任务 供矿工计算nonce
int do_mining(struct xdag_block *block, struct block_internal **pretop, xtime_t send_time)
{
	uint64_t taskIndex = g_xdag_pool_task_index + 1;
	//看taskIndex是奇数还是偶数
	struct xdag_pool_task *task = &g_xdag_pool_task[taskIndex & 1];

	//最后一个字段填入随机值
	xdag_generate_random_array(block[0].field[XDAG_BLOCK_FIELDS - 1].data, sizeof(xdag_hash_t));

	//任务对应的epoch
	task->task_time = MAIN_TIME(send_time);

	xdag_hash_init(task->ctx0);
	//最后两个字段不处理 把区块除去最后的两个字段用来计算hash
	xdag_hash_update(task->ctx0, block, sizeof(struct xdag_block) - 2 * sizeof(struct xdag_field));
	//把ctx0的state放入task->task[0].data  task->task[0].data存放的是去掉倒数两个字段的状态 是用来发送任务用的 两个任务字段的第一个
	xdag_hash_get_state(task->ctx0, task->task[0].data);
	
	//又把倒数第二个放回来了
	xdag_hash_update(task->ctx0, block[0].field[XDAG_BLOCK_FIELDS - 2].data, sizeof(struct xdag_field));
	//task->ctx现在存放的是去除了最后一个的ctx
	memcpy(task->ctx, task->ctx0, xdag_hash_ctx_size());

	//task->ctx现在又把最后一个放进来了 不过留了nonce的位置
	xdag_hash_update(task->ctx, block[0].field[XDAG_BLOCK_FIELDS - 1].data, sizeof(struct xdag_field) - sizeof(uint64_t));
	//task->task[1].data存放倒数第二个字段的数据
	memcpy(task->task[1].data, block[0].field[XDAG_BLOCK_FIELDS - 2].data, sizeof(struct xdag_field));

	//task->nonce.data存放倒数第一个字段的数据 即是最后放nonce的数据
	memcpy(task->nonce.data, block[0].field[XDAG_BLOCK_FIELDS - 1].data, sizeof(struct xdag_field));
	//task->lastfield.data存放倒数第一个字段的数据 即是最后放nonce的数据
	memcpy(task->lastfield.data, block[0].field[XDAG_BLOCK_FIELDS - 1].data, sizeof(struct xdag_field));

	//计算双hash 用一开始的amount 然后结果hash放在task->minhash.data
	xdag_hash_final(task->ctx, &task->nonce.amount, sizeof(uint64_t), task->minhash.data);
	g_xdag_pool_task_index = taskIndex;

	//等待矿工发送给自己的nonce用来更新区块的难度值
	while(xdag_get_xtimestamp() <= send_time) {
		sleep(1);
		pthread_mutex_lock(&g_create_block_mutex);
		struct block_internal *pretop_new = pretop_block();
		pthread_mutex_unlock(&g_create_block_mutex);
		if(*pretop != pretop_new && xdag_get_xtimestamp() < send_time) {
			*pretop = pretop_new;
			xdag_info("Mining: start from beginning because of pre-top block changed");
			return 0;
		}
	}

	//时间到了可以计算最后的值了 把包含nonce和挖出的矿工地址的值放入最后一个字段
	pthread_mutex_lock((pthread_mutex_t*)g_ptr_share_mutex);
	memcpy(block[0].field[XDAG_BLOCK_FIELDS - 1].data, task->lastfield.data, sizeof(struct xdag_field));
	pthread_mutex_unlock((pthread_mutex_t*)g_ptr_share_mutex);

	return 1;
}

static void reset_callback(struct ldus_rbtree *node)
{
	struct block_internal *bi = 0;

	if(g_bi_index_enable) {
		struct block_internal_index *index = (struct block_internal_index *)node;
		bi = index->bi;
	} else {
		bi = (struct block_internal *)node;
	}

	struct block_backrefs *tmp;
	for(struct block_backrefs *to_free = (struct block_backrefs*)atomic_load_explicit_uintptr(&bi->backrefs, memory_order_acquire); to_free != NULL;){
		tmp = to_free->next;
		xdag_free(to_free);
		to_free = tmp;
	}
	if((bi->flags & BI_REMARK) && bi->remark != (uintptr_t)NULL) {
		xdag_free((char*)bi->remark);
	}
	xdag_free(bi);

	if(g_bi_index_enable) {
		free(node);
	}
}

// main thread which works with block
static void *work_thread(void *arg)
{
	fprintf(stdout,"->work thread \n");

	xtime_t t = XDAG_ERA, conn_time = 0, sync_time = 0, t0;
	int n_mining_threads = (int)(unsigned)(uintptr_t)arg, sync_thread_running = 0;
	uint64_t nhashes0 = 0, nhashes = 0;
	pthread_t th;
	uint64_t last_nmain = 0, nmain;
	time_t last_time_nmain_unequal = time(NULL);

begin:
	// loading block from the local storage
	g_xdag_state = XDAG_STATE_LOAD;
	xdag_mess("Loading blocks from local storage...");
	fprintf(stdout,"->Loading blocks from local storage...\n");

	xtime_t start = xdag_get_xtimestamp();
	xdag_show_state(0);

//加载地址块（如果是钱包用户 或者miner的话）
	xdag_load_blocks(t, xdag_get_xtimestamp(), &t, &add_block_callback);

	xdag_mess("Finish loading blocks, time cost %ldms", xdag_get_xtimestamp() - start);

	// waiting for command "run"
	while (!g_xdag_run) {
		g_xdag_state = XDAG_STATE_STOP;
		fprintf(stdout,"waiting for command run\n");

		sleep(1);
	}

	// launching of synchronization thread
	g_xdag_sync_on = 1;
	if (!g_light_mode && !sync_thread_running) {
		xdag_mess("Starting sync thread...");
		int err = pthread_create(&th, 0, sync_thread, 0);
		if(err != 0) {
			printf("create sync_thread failed, error : %s\n", strerror(err));
			return 0;
		}

		sync_thread_running = 1;

		err = pthread_detach(th);
		if(err != 0) {
			printf("detach sync_thread failed, error : %s\n", strerror(err));
			return 0;
		}
	}

	if (g_light_mode) {
		// start mining threads
		xdag_mess("Starting mining threads...");
		xdag_mining_start(n_mining_threads);
	}

	// periodic generation of blocks and determination of the main block
	xdag_mess("Entering main cycle...");

	for (;;) {
		unsigned nblk;

		t0 = t;
		t = xdag_get_xtimestamp();
		nhashes0 = nhashes;
		nhashes = g_xdag_extstats.nhashes;
		nmain = g_xdag_stats.nmain;

		if (t > t0) {
			g_xdag_extstats.hashrate_s = ((double)(nhashes - nhashes0) * 1024) / (t - t0);
		}

		if (!g_block_production_on && !g_light_mode &&
				(g_xdag_state == XDAG_STATE_WAIT || g_xdag_state == XDAG_STATE_WTST ||
				g_xdag_state == XDAG_STATE_SYNC || g_xdag_state == XDAG_STATE_STST || 
				g_xdag_state == XDAG_STATE_CONN || g_xdag_state == XDAG_STATE_CTST)) {
			if (g_xdag_state == XDAG_STATE_SYNC || g_xdag_state == XDAG_STATE_STST || 
					g_xdag_stats.nmain >= (MAIN_TIME(t) - xdag_start_main_time())) {
				g_block_production_on = 1;
			} else if (last_nmain != nmain) {
				last_nmain = nmain;
				last_time_nmain_unequal = time(NULL);
			} else if (time(NULL) - last_time_nmain_unequal > MAX_TIME_NMAIN_STALLED) {
				g_block_production_on = 1;
			}

			if (g_block_production_on) {
				xdag_mess("Starting refer blocks creation...");

				// start mining threads
				xdag_mess("Starting mining threads...");
				xdag_mining_start(n_mining_threads);
			}

		}

		if (g_block_production_on && 
				(nblk = (unsigned)g_xdag_extstats.nnoref / (XDAG_BLOCK_FIELDS - 5))) {
			nblk = nblk / 61 + (nblk % 61 > (unsigned)rand() % 61);

//	生成见证块 矿池做的
			while (nblk--) {
				xdag_create_and_send_block(0, 0, 0, 0, 0, 0, NULL);
			}
		}

		pthread_mutex_lock(&block_mutex);

		if (g_xdag_state == XDAG_STATE_REST) {
			g_xdag_sync_on = 0;
			pthread_mutex_unlock(&block_mutex);
			xdag_mining_start(0);

			while (xdag_get_xtimestamp() - t < MAIN_CHAIN_PERIOD + (3 << 10)) {
				sleep(1);
			}

			pthread_mutex_lock(&block_mutex);

			if (xdag_free_all()) {
				pthread_mutex_lock(&rbtree_mutex);
				ldus_rbtree_walk_up(root, reset_callback);
				pthread_mutex_unlock(&rbtree_mutex);
			}
			
			root = 0;
			g_balance = 0;
			top_main_chain = pretop_main_chain = 0;
			ourfirst = ourlast = 0;
			g_orphan_first[0] = g_orphan_last[0] = 0;
			g_orphan_first[1] = g_orphan_last[1] = 0;
			memset(&g_xdag_stats, 0, sizeof(g_xdag_stats));
			memset(&g_xdag_extstats, 0, sizeof(g_xdag_extstats));
			pthread_mutex_unlock(&block_mutex);
			conn_time = sync_time = 0;

			goto begin;
		} else {
			pthread_mutex_lock(&g_transport_mutex);
			if (t > (g_xdag_last_received << 10) && t - (g_xdag_last_received << 10) > 3 * MAIN_CHAIN_PERIOD) {
				g_xdag_state = (g_light_mode ? (g_xdag_testnet ? XDAG_STATE_TTST : XDAG_STATE_TRYP)
					: (g_xdag_testnet ? XDAG_STATE_WTST : XDAG_STATE_WAIT));
				conn_time = sync_time = 0;
			} else {
				if (!conn_time) {
					conn_time = t;
				}

				if (!g_light_mode && t - conn_time >= 2 * MAIN_CHAIN_PERIOD
					&& !memcmp(&g_xdag_stats.difficulty, &g_xdag_stats.max_difficulty, sizeof(xdag_diff_t))) {
					sync_time = t;
				}

				if (t - (g_xdag_xfer_last << 10) <= 2 * MAIN_CHAIN_PERIOD + 4) {
					g_xdag_state = XDAG_STATE_XFER;
				} else if (g_light_mode) {
					g_xdag_state = (g_xdag_mining_threads > 0 ?
						(g_xdag_testnet ? XDAG_STATE_MTST : XDAG_STATE_MINE)
						: (g_xdag_testnet ? XDAG_STATE_PTST : XDAG_STATE_POOL));
				} else if (t - sync_time > 8 * MAIN_CHAIN_PERIOD) {
					g_xdag_state = (g_xdag_testnet ? XDAG_STATE_CTST : XDAG_STATE_CONN);
				} else {
					g_xdag_state = (g_xdag_testnet ? XDAG_STATE_STST : XDAG_STATE_SYNC);
				}
			}
			pthread_mutex_unlock(&g_transport_mutex);
		}

		if (!g_light_mode) {
			check_new_main();
		}

		struct block_internal *ours = ourfirst;
		pthread_mutex_unlock(&block_mutex);
		xdag_show_state(ours ? ours->hash : 0);

		while (xdag_get_xtimestamp() - t < 1024) {
			sleep(1);
		}
	}

	return 0;
}

/* start of regular block processing
 * n_mining_threads - the number of threads for mining on the CPU;
 *   for the light node is_pool == 0;
 * miner_address = 1 - the address of the miner is explicitly set
 */
int xdag_blocks_start(int is_pool, int mining_threads_count, int miner_address)
{
	fprintf(stdout,"->xdag blocks start\n");

	pthread_mutexattr_t attr;
	pthread_t th;

//如果不是矿池的话就是轻节点
	if (!is_pool) {
		g_light_mode = 1;
	}

	fprintf(stdout,"is pool:%d g_light_mode:%d \n",is_pool,g_light_mode);

	if (xdag_mem_init(g_light_mode && !miner_address ? 0 : (((xdag_get_xtimestamp() - XDAG_ERA) >> 10) + (uint64_t)365 * 24 * 60 * 60) * 2 * sizeof(struct block_internal))) {
		return -1;
	}

	g_bi_index_enable = g_use_tmpfile;
	fprintf(stdout,"g_bi_inde_enable:%d \n",g_bi_index_enable);

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&block_mutex, &attr);
	pthread_mutex_init(&rbtree_mutex, 0);
	int err = pthread_create(&th, 0, work_thread, (void*)(uintptr_t)(unsigned)mining_threads_count);
	if(err != 0) {
		printf("create work_thread failed, error : %s\n", strerror(err));
		return -1;
	}
	err = pthread_detach(th);
	if(err != 0) {
		printf("create 	pool_main_thread failed, error : %s\n", strerror(err));
		return -1;
	}

	return 0;
}

/* returns our first block. If there is no blocks yet - the first block is created. */
int xdag_get_our_block(xdag_hash_t hash)
{
	pthread_mutex_lock(&block_mutex);
	struct block_internal *bi = ourfirst;
	pthread_mutex_unlock(&block_mutex);

	if (!bi) {
		//生成地址块
		xdag_create_and_send_block(0, 0, 0, 0, 0, 0, NULL);
		pthread_mutex_lock(&block_mutex);
		bi = ourfirst;
		pthread_mutex_unlock(&block_mutex);
		if (!bi) {
			return -1;
		}
	}

	memcpy(hash, bi->hash, sizeof(xdag_hash_t));
	fprintf(stdout, "->xdag_get_our_block  hash: %016llx%016llx%016llx%016llx\n",
			(unsigned long long)hash[3], (unsigned long long)hash[2], (unsigned long long)hash[1], (unsigned long long)hash[0]);

	return 0;
}

/* calls callback for each own block */
int xdag_traverse_our_blocks(void *data,
    int (*callback)(void*, xdag_hash_t, xdag_amount_t, xtime_t, int))
{
	int res = 0;

	pthread_mutex_lock(&block_mutex);
	//在用户中只会便利一个区块 就是自己的地址块
	for (struct block_internal *bi = ourfirst; !res && bi; bi = bi->ournext) {
		uint64_t *h = bi->hash;
		fprintf(stdout, "\n->in traverse -> hash: %016llx%016llx%016llx%016llx\n",
		(unsigned long long)h[3], (unsigned long long)h[2], (unsigned long long)h[1], (unsigned long long)h[0]);
		fprintf(stdout,"n_our_key:%d\n",bi->n_our_key);
		res = (*callback)(data, bi->hash, bi->amount, bi->time, bi->n_our_key);
	}

	pthread_mutex_unlock(&block_mutex);

	return res;
}

static int (*g_traverse_callback)(void *data, xdag_hash_t hash, xdag_amount_t amount, xtime_t time);
static void *g_traverse_data;

static void traverse_all_callback(struct ldus_rbtree *node)
{
	struct block_internal *bi = 0;
	if(g_bi_index_enable) {
		struct block_internal_index *index = (struct block_internal_index *)node;
		bi = index->bi;
	} else {
		bi = (struct block_internal *)node;
	}

	(*g_traverse_callback)(g_traverse_data, bi->hash, bi->amount, bi->time);
}

/* calls callback for each block */
int xdag_traverse_all_blocks(void *data, int (*callback)(void *data, xdag_hash_t hash,
	xdag_amount_t amount, xtime_t time))
{
	pthread_mutex_lock(&block_mutex);
	g_traverse_callback = callback;
	g_traverse_data = data;
	pthread_mutex_lock(&rbtree_mutex);
	ldus_rbtree_walk_right(root, traverse_all_callback);
	pthread_mutex_unlock(&rbtree_mutex);
	pthread_mutex_unlock(&block_mutex);
	return 0;
}

/* returns current balance for specified address or balance for all addresses if hash == 0 */
xdag_amount_t xdag_get_balance(xdag_hash_t hash)
{
	if (!hash) {
		return g_balance;
	}

	struct block_internal *bi = block_by_hash(hash);

	if (!bi) {
		return 0;
	}

	return bi->amount;
}

/* sets current balance for the specified address */
//不断的在更新余额 且更新后对应的地址块就成了ourfirst
int xdag_set_balance(xdag_hash_t hash, xdag_amount_t balance)
{
	long double tmpbalance = amount2xdags(balance);
	fprintf(stdout,"\n->into xdag_set_balance:%Lf\n",(long double)tmpbalance);


	if (!hash) return -1;

	pthread_mutex_lock(&block_mutex);
	struct block_internal *bi = block_by_hash(hash);
	if (bi->flags & BI_OURS && bi != ourfirst) {
		if (bi->ourprev) { //bi->ourprev == bi->link[13] bi->ournext == bi->link[14]
			bi->ourprev->ournext = bi->ournext;
		} else {
			ourfirst = bi->ournext;
		}

		if (bi->ournext) {
			bi->ournext->ourprev = bi->ourprev;
		} else {
			ourlast = bi->ourprev;
		}

		bi->ourprev = 0;
		bi->ournext = ourfirst;

		if (ourfirst) {
			ourfirst->ourprev = bi;
		} else {
			ourlast = bi;
		}

		ourfirst = bi;
	}

	pthread_mutex_unlock(&block_mutex);

	if (!bi) return -1;

	if (bi->amount != balance) {
		xdag_hash_t hash0;
		xdag_amount_t diff;

		memset(hash0, 0, sizeof(xdag_hash_t));

		if (balance > bi->amount) {
			diff = balance - bi->amount;
			xdag_log_xfer(hash0, hash, diff);
			if (bi->flags & BI_OURS) {
				//总资产 多个地址块的所有余额相加
				g_balance += diff;
			}
		} else {
			diff = bi->amount - balance;
			xdag_log_xfer(hash, hash0, diff);
			if (bi->flags & BI_OURS) {
				g_balance -= diff;
			}
		}

		bi->amount = balance;
	}

	return 0;
}

// returns position and time of block by hash; if block is extra and block != 0 also returns the whole block
//先从内存中找到对应hash的bi 判断bi的类型 如果是extra则将bi的orphan对应的xdag赋值给block 否则后续通过xdag_storage_load在持久化存储中获取block
// 如果区块是extra标志 赋值orphan指向的xdag块 否则先不给block赋值 后续可以通过调用xdag_storage_load获取block
int64_t xdag_get_block_pos(const xdag_hash_t hash, xtime_t *t, struct xdag_block *block)
{
	if (block) pthread_mutex_lock(&block_mutex);
	struct block_internal *bi = block_by_hash(hash);

	if (!bi) {
		if (block) pthread_mutex_unlock(&block_mutex);
		return -1;
	}

	if (block && bi->flags & BI_EXTRA) {
		memcpy(block, bi->oref->block, sizeof(struct xdag_block));
	}

	if (block) pthread_mutex_unlock(&block_mutex);

	*t = bi->time;

	return bi->storage_pos;
}

//returns a number of key by hash of block, or -1 if block is not ours
int xdag_get_key(xdag_hash_t hash)
{
	struct block_internal *bi = block_by_hash(hash);

	if (!bi || !(bi->flags & BI_OURS)) {
		return -1;
	}

	return bi->n_our_key;
}

/* reinitialization of block processing */
int xdag_blocks_reset(void)
{
	pthread_mutex_lock(&block_mutex);
	if (g_xdag_state != XDAG_STATE_REST) {
		xdag_crit("The local storage is corrupted. Resetting blocks engine.");
		g_xdag_state = XDAG_STATE_REST;
		xdag_show_state(0);
	}
	pthread_mutex_unlock(&block_mutex);

	return 0;
}

#define pramount(amount) xdag_amount2xdag(amount), xdag_amount2cheato(amount)

static int bi_compar(const void *l, const void *r)
{
	xtime_t tl = (*(struct block_internal **)l)->time, tr = (*(struct block_internal **)r)->time;

	return (tl < tr) - (tl > tr);
}

// returns string representation for the block state. Ignores BI_OURS flag
const char* xdag_get_block_state_info(uint8_t flags)
{
	const uint8_t flag = flags & ~(BI_OURS | BI_REMARK);

	if(flag == (BI_REF | BI_MAIN_REF | BI_APPLIED | BI_MAIN | BI_MAIN_CHAIN)) { //1F
		return "Main";
	}
	if(flag == (BI_REF | BI_MAIN_REF | BI_APPLIED)) { //1C
		return "Accepted";
	}
	if(flag == (BI_REF | BI_MAIN_REF)) { //18
		return "Rejected";
	}
	return "Pending";
}

/* prints detailed information about block */
int xdag_print_block_info(xdag_hash_t hash, FILE *out)
{
	char time_buf[64] = {0};
	char address[33] = {0};
	int i;

	struct block_internal *bi = block_by_hash(hash);

	if (!bi) {
		return -1;
	}

	uint64_t *h = bi->hash;
	xdag_xtime_to_string(bi->time, time_buf);
	fprintf(out, "      time: %s\n", time_buf);
	fprintf(out, " timestamp: %llx\n", (unsigned long long)bi->time);
	fprintf(out, "     flags: %x\n", bi->flags & ~BI_OURS);
	fprintf(out, "     state: %s\n", xdag_get_block_state_info(bi->flags));
	fprintf(out, "  file pos: %llx\n", (unsigned long long)bi->storage_pos);
	fprintf(out, "      hash: %016llx%016llx%016llx%016llx\n",
		(unsigned long long)h[3], (unsigned long long)h[2], (unsigned long long)h[1], (unsigned long long)h[0]);
	fprintf(out, "    remark: %s\n", get_remark(bi));
	fprintf(out, "difficulty: %llx%016llx\n", xdag_diff_args(bi->difficulty));
	xdag_hash2address(h, address);
	fprintf(out, "   balance: %s  %10u.%09u\n", address, pramount(bi->amount));
	fprintf(out, "-----------------------------------------------------------------------------------------------------------------------------\n");
	fprintf(out, "                               block as transaction: details\n");
	fprintf(out, " direction  address                                    amount\n");
	fprintf(out, "-----------------------------------------------------------------------------------------------------------------------------\n");
	int flags;
	struct block_internal *ref;
	pthread_mutex_lock(&block_mutex);
	ref = bi->ref;
	flags = bi->flags;
	pthread_mutex_unlock(&block_mutex);
	if((flags & BI_REF) && ref != NULL) {
		xdag_hash2address(ref->hash, address);
	} else {
		strcpy(address, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
	}
	fprintf(out, "       fee: %s  %10u.%09u\n", address, pramount(bi->fee));

 	if(flags & BI_EXTRA) pthread_mutex_lock(&block_mutex);
 	int nlinks = bi->nlinks;
	struct block_internal *link[MAX_LINKS];
	memcpy(link, bi->link, nlinks * sizeof(struct block_internal*));
	if(flags & BI_EXTRA) pthread_mutex_unlock(&block_mutex);

 	for (i = 0; i < nlinks; ++i) {
		xdag_hash2address(link[i]->hash, address);
		fprintf(out, "    %6s: %s  %10u.%09u\n", (1 << i & bi->in_mask ? " input" : "output"),
			address, pramount(bi->linkamount[i]));
	}

	fprintf(out, "-----------------------------------------------------------------------------------------------------------------------------\n");
	fprintf(out, "                                 block as address: details\n");
	fprintf(out, " direction  transaction                                amount       time                     remark                          \n");
	fprintf(out, "-----------------------------------------------------------------------------------------------------------------------------\n");

	int N = 0x10000;
	int n = 0;
	struct block_internal **ba = malloc(N * sizeof(struct block_internal *));

	if (!ba) return -1;

	for (struct block_backrefs *br = (struct block_backrefs*)atomic_load_explicit_uintptr(&bi->backrefs, memory_order_acquire); br; br = br->next) {
		for (i = N_BACKREFS; i && !br->backrefs[i - 1]; i--);

		if (!i) {
			continue;
		}

		if (n + i > N) {
			N *= 2;
			struct block_internal **ba1 = realloc(ba, N * sizeof(struct block_internal *));
			if (!ba1) {
				free(ba);
				return -1;
			}

			ba = ba1;
		}

		memcpy(ba + n, br->backrefs, i * sizeof(struct block_internal *));
		n += i;
	}

	if (n) {
		qsort(ba, n, sizeof(struct block_internal *), bi_compar);

		for (i = 0; i < n; ++i) {
			if (!i || ba[i] != ba[i - 1]) {
				struct block_internal *ri = ba[i];
				if (ri->flags & BI_APPLIED) {
					for (int j = 0; j < ri->nlinks; j++) {
						if(ri->link[j] == bi && ri->linkamount[j]) {
							xdag_xtime_to_string(ri->time, time_buf);
							xdag_hash2address(ri->hash, address);
							fprintf(out, "    %6s: %s  %10u.%09u  %s  %s\n",
								(1 << j & ri->in_mask ? "output" : " input"), address,
								pramount(ri->linkamount[j]), time_buf, get_remark(ri));
						}
					}
				}
			}
		}
	}

	free(ba);
	
	if (bi->flags & BI_MAIN) {
		xdag_hash2address(h, address);
		fprintf(out, "   earning: %s  %10u.%09u  %s\n", address,
			pramount(MAIN_START_AMOUNT >> ((MAIN_TIME(bi->time) - MAIN_TIME(XDAG_ERA)) >> MAIN_BIG_PERIOD_LOG)),
			time_buf);
	}
	
	return 0;
}

static inline void print_block(struct block_internal *block, int print_only_addresses, FILE *out)
{
	char address[33] = {0};
	char time_buf[64] = {0};

	xdag_hash2address(block->hash, address);

	if(print_only_addresses) {
		fprintf(out, "%s\n", address);
	} else {
		xdag_xtime_to_string(block->time, time_buf);
		fprintf(out, "%s   %s   %-8s  %-32s\n", address, time_buf, xdag_get_block_state_info(block->flags), get_remark(block));
	}
}

static inline void print_header_block_list(FILE *out)
{
	fprintf(out, "---------------------------------------------------------------------------------------------------------\n");
	fprintf(out, "address                            time                      state     mined by                          \n");
	fprintf(out, "---------------------------------------------------------------------------------------------------------\n");
}

// prints list of N last main blocks
void xdag_list_main_blocks(int count, int print_only_addresses, FILE *out)
{
	int i = 0;
	if(!print_only_addresses) {
		print_header_block_list(out);
	}

	pthread_mutex_lock(&block_mutex);

	for (struct block_internal *b = top_main_chain; b && i < count; b = b->link[b->max_diff_link]) {
		if (b->flags & BI_MAIN) {
			print_block(b, print_only_addresses, out);
			++i;
		}
	}

	pthread_mutex_unlock(&block_mutex);
}

// prints list of N last blocks mined by current pool
// TODO: find a way to find non-payed mined blocks or remove 'include_non_payed' parameter
void xdag_list_mined_blocks(int count, int include_non_payed, FILE *out)
{
	int i = 0;
	print_header_block_list(out);

	pthread_mutex_lock(&block_mutex);

	for(struct block_internal *b = top_main_chain; b && i < count; b = b->link[b->max_diff_link]) {
		if(b->flags & BI_MAIN && b->flags & BI_OURS) {
			print_block(b, 0, out);
			++i;
		}
	}

	pthread_mutex_unlock(&block_mutex);
}

void cache_retarget(int32_t cache_hit, int32_t cache_miss)
{
	if(g_xdag_extstats.cache_usage >= g_xdag_extstats.cache_size) {
		if(g_xdag_extstats.cache_hitrate < 0.94 && g_xdag_extstats.cache_size < CACHE_MAX_SIZE) {
			g_xdag_extstats.cache_size++;
		} else if(g_xdag_extstats.cache_hitrate > 0.98 && !cache_miss && g_xdag_extstats.cache_size && (rand() & 0xF) < 0x5) {
			g_xdag_extstats.cache_size--;
		}
		for(int l = g_xdag_extstats.cache_usage; l > g_xdag_extstats.cache_size; l--) {
			if(cache_first != NULL) {
				struct cache_block* to_free = cache_first;
				cache_first = cache_first->next;
				if(cache_first == NULL) {
					cache_last = NULL;
				}
				ldus_rbtree_remove(&cache_root, &to_free->node);
				free(to_free);
				g_xdag_extstats.cache_usage--;
			} else {
				break;
				xdag_warn("Non critical error, break in for [function: cache_retarget]");
			}
		}

	} else if(g_xdag_extstats.cache_hitrate > 0.98 && !cache_miss && g_xdag_extstats.cache_size && (rand() & 0xF) < 0x5) {
		g_xdag_extstats.cache_size--;
	}
	if((uint32_t)(g_xdag_extstats.cache_size / 0.9) > CACHE_MAX_SIZE) {
		g_xdag_extstats.cache_size = (uint32_t)(g_xdag_extstats.cache_size*0.9);
	}
	if(cache_hit + cache_miss > 0) {
		if(cache_bounded_counter < CACHE_MAX_SAMPLES)
			cache_bounded_counter++;
		g_xdag_extstats.cache_hitrate = moving_average_double(g_xdag_extstats.cache_hitrate, (double)((cache_hit) / (cache_hit + cache_miss)), cache_bounded_counter);

	}
}

void cache_add(struct xdag_block* block, xdag_hash_t hash)
{
	if(g_xdag_extstats.cache_usage <= CACHE_MAX_SIZE) {
		struct cache_block *cacheBlock = malloc(sizeof(struct cache_block));
		if(cacheBlock != NULL) {
			memset(cacheBlock, 0, sizeof(struct cache_block));
			memcpy(&(cacheBlock->block), block, sizeof(struct xdag_block));
			memcpy(&(cacheBlock->hash), hash, sizeof(xdag_hash_t));

			if(cache_first == NULL)
				cache_first = cacheBlock;
			if(cache_last != NULL)
				cache_last->next = cacheBlock;
			cache_last = cacheBlock;
			ldus_rbtree_insert(&cache_root, &cacheBlock->node);
			g_xdag_extstats.cache_usage++;
		} else {
			xdag_warn("cache malloc failed [function: cache_add]");
		}
	} else {
		xdag_warn("maximum cache reached [function: cache_add]");
	}

}

int32_t check_signature_out_cached(struct block_internal* blockRef, struct xdag_public_key *public_keys, const int keysCount, int32_t *cache_hit, int32_t *cache_miss)
{
	struct cache_block *bref = cache_block_by_hash(blockRef->hash);
	if(bref != NULL) {
		++(*cache_hit); //缓存击中
		return  find_and_verify_signature_out(&(bref->block), public_keys, keysCount);
	} else {
		++(*cache_miss); //缓存miss
		return check_signature_out(blockRef, public_keys, keysCount);
	}
}

int32_t check_signature_out(struct block_internal* blockRef, struct xdag_public_key *public_keys, const int keysCount)
{
	struct xdag_block buf;
	struct xdag_block *bref = xdag_storage_load(blockRef->hash, blockRef->time, blockRef->storage_pos, &buf);
	if(!bref) {
		return 8;
	}
	return find_and_verify_signature_out(bref, public_keys, keysCount);
}

static int32_t find_and_verify_signature_out(struct xdag_block* bref, struct xdag_public_key *public_keys, const int keysCount)
{
	int j = 0;
	for(int k = 0; j < XDAG_BLOCK_FIELDS; ++j) {
		if(xdag_type(bref, j) == XDAG_FIELD_SIGN_OUT && (++k & 1)
			&& valid_signature(bref, j, keysCount, public_keys) >= 0) {
			break;
		}
	}
	if(j == XDAG_BLOCK_FIELDS) {
		return 9;
	}
	return 0;
}

int xdag_get_transactions(xdag_hash_t hash, void *data, int (*callback)(void*, int, int, xdag_hash_t, xdag_amount_t, xtime_t, const char *))
{
	struct block_internal *bi = block_by_hash(hash);
	
	if (!bi) {
		return -1;
	}
	
	int size = 0x10000; 
	int n = 0;
	struct block_internal **block_array = malloc(size * sizeof(struct block_internal *));
	
	if (!block_array) return -1;
	
	int i;
	for (struct block_backrefs *br = (struct block_backrefs*)atomic_load_explicit_uintptr(&bi->backrefs, memory_order_acquire); br; br = br->next) {
		for (i = N_BACKREFS; i && !br->backrefs[i - 1]; i--);
		
		if (!i) {
			continue;
		}
		
		if (n + i > size) {
			size *= 2;
			struct block_internal **tmp_array = realloc(block_array, size * sizeof(struct block_internal *));
			if (!tmp_array) {
				free(block_array);
				return -1;
			}
			
			block_array = tmp_array;
		}
		
		memcpy(block_array + n, br->backrefs, i * sizeof(struct block_internal *));
		n += i;
	}
	
	if (!n) {
		free(block_array);
		return 0;
	}
	
	qsort(block_array, n, sizeof(struct block_internal *), bi_compar);
	
	for (i = 0; i < n; ++i) {
		if (!i || block_array[i] != block_array[i - 1]) {
			struct block_internal *ri = block_array[i];
			for (int j = 0; j < ri->nlinks; j++) {
				if(ri->link[j] == bi && ri->linkamount[j]) {
					if(callback(data, 1 << j & ri->in_mask, ri->flags, ri->hash, ri->linkamount[j], ri->time, get_remark(ri))) {
						free(block_array);
						return n;
					}
				}
			}
		}
	}
	
	free(block_array);
	
	return n;
}

//移除孤块 孤块有人链接了 标记为REF 不过不会又ref这个属性 因为还未被加入主链中 所以还不确定哪个先
void remove_orphan(struct block_internal* bi, int remove_action)
{
	if(!(bi->flags & BI_REF) && (remove_action != ORPHAN_REMOVE_EXTRA || (bi->flags & BI_EXTRA))) {
		struct orphan_block *obt = bi->oref;
		if (obt == NULL) {
			xdag_crit("Critical error. obt=0");
		} else if (obt->orphan_bi != bi) {
			xdag_crit("Critical error. bi=%p, flags=%x, action=%d, obt=%p, prev=%p, next=%p, obi=%p",
				  bi, bi->flags, remove_action, obt, obt->prev, obt->next, obt->orphan_bi);
		} else {
			//判断是不是附加块
			int index = get_orphan_index(bi), i;
			struct orphan_block *prev = obt->prev, *next = obt->next;

			//将obt从链表中去除 
			*(prev ? &(prev->next) : &g_orphan_first[index]) = next;
			*(next ? &(next->prev) : &g_orphan_last[index]) = prev;

			if (index) {
				//如果是附加块 不是重用的话就持久化 重用的话 不持久化
				if (remove_action != ORPHAN_REMOVE_REUSE) {
					//将该块持久化并获取存储地址
					bi->storage_pos = xdag_storage_save(obt->block);
					//由于该块持久化了 所以对应的连接的区块也要从orphan中移除
					for (i = 0; i < bi->nlinks; ++i) {
						remove_orphan(bi->link[i], ORPHAN_REMOVE_NORMAL);
					}
				}
				//将bi设置为非附加块 重用后就不是附加块了
				bi->flags &= ~BI_EXTRA;
				g_xdag_extstats.nextra--;
			} else {
				//如果本身就不是额外块
				//直接未被指向的区块数量减一
				g_xdag_extstats.nnoref--;
			}


			//bi不是孤块了 已经被指向了
			bi->oref = 0;
			bi->flags |= BI_REF;
			free(obt);
		}
	}
}

void add_orphan(struct block_internal* bi, struct xdag_block *block)
{
	//获取索引 要么0 要么1 如果bi是extra块的话返回1 否则返回0
	int index = get_orphan_index(bi);
	struct orphan_block *obt = malloc(sizeof(struct orphan_block) + index * sizeof(struct xdag_block));
	if(obt == NULL){
		xdag_crit("Error. Malloc failed. [function: add_orphan]");
	} else {
		obt->orphan_bi = bi;
		obt->prev = g_orphan_last[index];
		obt->next = 0;
		bi->oref = obt;
		*(g_orphan_last[index] ? &g_orphan_last[index]->next : &g_orphan_first[index]) = obt;
		g_orphan_last[index] = obt;
		if (index) {
			memcpy(obt->block, block, sizeof(struct xdag_block));
			g_xdag_extstats.nextra++;
		} else {
			g_xdag_extstats.nnoref++;
		}
	}
}

void xdag_list_orphan_blocks(int count, FILE *out)
{
	int i = 0;
	print_header_block_list(out);

	pthread_mutex_lock(&block_mutex);

	for(struct orphan_block *b = g_orphan_first[0]; b && i < count; b = b->next, i++) {
		print_block(b->orphan_bi, 0, out);
	}

	pthread_mutex_unlock(&block_mutex);
}

// completes work with the blocks
void xdag_block_finish()
{
	pthread_mutex_lock(&g_create_block_mutex);
	pthread_mutex_lock(&block_mutex);
}

int xdag_get_block_info(xdag_hash_t hash, void *info, int (*info_callback)(void*, int, xdag_hash_t, xdag_amount_t, xtime_t, const char *),
						void *links, int (*links_callback)(void*, const char *, xdag_hash_t, xdag_amount_t))
{
	pthread_mutex_lock(&block_mutex);
	struct block_internal *bi = block_by_hash(hash);
	pthread_mutex_unlock(&block_mutex);

	if(info_callback && bi) {
		info_callback(info, bi->flags & ~BI_OURS,  bi->hash, bi->amount, bi->time, get_remark(bi));
	}

	if(links_callback && bi) {
		int flags;
		struct block_internal *ref;
		pthread_mutex_lock(&block_mutex);
		ref = bi->ref;
		flags = bi->flags;
		pthread_mutex_unlock(&block_mutex);

		xdag_hash_t link_hash;
		memset(link_hash, 0, sizeof(xdag_hash_t));
		if((flags & BI_REF) && ref != NULL) {
			memcpy(link_hash, ref->hash, sizeof(xdag_hash_t));
		}
		links_callback(links, "fee", link_hash, bi->fee);

		struct block_internal *bi_links[MAX_LINKS] = {0};
		int bi_nlinks = 0;

		if(flags & BI_EXTRA) {
			pthread_mutex_lock(&block_mutex);
		}

		bi_nlinks = bi->nlinks;
		memcpy(bi_links, bi->link, bi_nlinks * sizeof(struct block_internal *));

		if(flags & BI_EXTRA) {
			pthread_mutex_unlock(&block_mutex);
		}

		for (int i = 0; i < bi_nlinks; ++i) {
			links_callback(links, (1 << i & bi->in_mask ? " input" : "output"), bi_links[i]->hash, bi->linkamount[i]);
		}
	}
	return 0;
}

static inline size_t remark_acceptance(xdag_remark_t origin)
{
	char remark_buf[33] = {0};
	memcpy(remark_buf, origin, sizeof(xdag_remark_t));
	size_t size = validate_remark(remark_buf);
	if(size){
		return size;
	}
	return 0;
}

static int add_remark_bi(struct block_internal* bi, xdag_remark_t strbuf)
{
	size_t size = remark_acceptance(strbuf);
	char *remark_tmp = xdag_malloc(size + 1);
	if(remark_tmp == NULL) {
		xdag_err("xdag_malloc failed, [function add_remark_bi]");
		return 0;
	}
	memset(remark_tmp, 0, size + 1);
	memcpy(remark_tmp, strbuf, size);
	uintptr_t expected_value = 0 ;
	if(!atomic_compare_exchange_strong_explicit_uintptr(&bi->remark, &expected_value, (uintptr_t)remark_tmp, memory_order_acq_rel, memory_order_relaxed)){
		free(remark_tmp);
	}
	return 1;
}

//nodeBlock链接了blockRef
static void add_backref(struct block_internal* blockRef, struct block_internal* nodeBlock)
{
	int i = 0;

	struct block_backrefs *tmp = (struct block_backrefs*)atomic_load_explicit_uintptr(&blockRef->backrefs, memory_order_acquire);
	// LIFO list: if the first element doesn't exist or it is full, a new element of the backrefs list will be created
	// and added as first element of backrefs block list
	if( tmp == NULL || tmp->backrefs[N_BACKREFS - 1]) {
		struct block_backrefs *blockRefs_to_insert = xdag_malloc(sizeof(struct block_backrefs));
		if(blockRefs_to_insert == NULL) {
			xdag_err("xdag_malloc failed. [function add_backref]");
			return;
		}
		memset(blockRefs_to_insert, 0, sizeof(struct block_backrefs));
		blockRefs_to_insert->next = tmp;
		atomic_store_explicit_uintptr(&blockRef->backrefs, (uintptr_t)blockRefs_to_insert, memory_order_release);
		tmp = blockRefs_to_insert;
	}

	// searching the first free array element
	for(; tmp->backrefs[i]; ++i);
	// adding the actual block memory address to the backrefs array
	tmp->backrefs[i] = nodeBlock;
}

static inline int get_nfield(struct xdag_block *bref, int field_type)
{
	for(int i = 0; i < XDAG_BLOCK_FIELDS; ++i) {
		if(xdag_type(bref, i) == field_type){
			return i;
		}
	}
	return -1;
}

static inline const char* get_remark(struct block_internal *bi){
	if((bi->flags & BI_REMARK) & ~BI_EXTRA){
		const char* tmp = (const char*)atomic_load_explicit_uintptr(&bi->remark, memory_order_acquire);
		if(tmp != NULL){
			return tmp;
		} else if(load_remark(bi)){
			return (const char*)atomic_load_explicit_uintptr(&bi->remark, memory_order_relaxed);
		}
	}
	return "";
}

static int load_remark(struct block_internal* bi) {
	struct xdag_block buf;
	struct xdag_block *bref = xdag_storage_load(bi->hash, bi->time, bi->storage_pos, &buf);
	if(bref == NULL) {
		return 0;
	}

	int remark_field = get_nfield(bref, XDAG_FIELD_REMARK);
	if (remark_field < 0) {
		xdag_err("Remark field not found [function: load_remark]");
		pthread_mutex_lock(&block_mutex);
		bi->flags &= ~BI_REMARK;
		pthread_mutex_unlock(&block_mutex);
		return 0;
	}
	return add_remark_bi(bi, bref->field[remark_field].remark);
}

//将自己的区块进行排序
void order_ourblocks_by_amount(struct block_internal *bi)
{
	struct block_internal *ti;
	while ((ti = bi->ourprev) && bi->amount > ti->amount) {
		bi->ourprev = ti->ourprev;
		ti->ournext = bi->ournext;
		bi->ournext = ti;
		ti->ourprev = bi;
		*(bi->ourprev ? &bi->ourprev->ournext : &ourfirst) = bi;
		*(ti->ournext ? &ti->ournext->ourprev : &ourlast) = ti;
	}
 	while ((ti = bi->ournext) && bi->amount < ti->amount) {
		bi->ournext = ti->ournext;
		ti->ourprev = bi->ourprev;
		bi->ourprev = ti;
		ti->ournext = bi;
		*(bi->ournext ? &bi->ournext->ourprev : &ourlast) = bi;
		*(ti->ourprev ? &ti->ourprev->ournext : &ourfirst) = ti;
	}
 }



//添加我们的区块
static inline void add_ourblock(struct block_internal *nodeBlock)
{
	nodeBlock->ourprev = ourlast;
	*(ourlast ? &ourlast->ournext : &ourfirst) = nodeBlock;
	ourlast = nodeBlock;
}

//移除我们的区块
static inline void remove_ourblock(struct block_internal *nodeBlock){
	struct block_internal *prev = nodeBlock->ourprev, *next = nodeBlock->ournext;
	*(prev ? &prev->ournext : &ourfirst) = next;
	*(next ? &next->ourprev : &ourlast) = prev;
}
