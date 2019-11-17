/* пул и майнер, T13.744-T14.390 $DVS:time$ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "system.h"
#include "../dus/programs/dfstools/source/dfslib/dfslib_crypt.h"
#include "../dus/programs/dar/source/include/crc.h"
#include "address.h"
#include "block.h"
#include "init.h"
#include "miner.h"
#include "storage.h"
#include "sync.h"
#include "transport.h"
#include "mining_common.h"
#include "network.h"
#include "utils/log.h"
#include "utils/utils.h"

#define MINERS_PWD             "minersgonnamine"
#define SECTOR0_BASE           0x1947f3acu
#define SECTOR0_OFFSET         0x82e9d1b5u
#define SEND_PERIOD            10                                  /* share period of sending shares */
#define POOL_LIST_FILE         (g_xdag_testnet ? "pools-testnet.txt" : "pools.txt")

struct miner {
	struct xdag_field id;
	uint64_t nfield_in;//入 
	uint64_t nfield_out;//出
};

static struct miner g_local_miner;//本地全局矿工
static pthread_mutex_t g_miner_mutex = PTHREAD_MUTEX_INITIALIZER;

/* a number of mining threads */
int g_xdag_mining_threads = 0;

static int g_socket = -1, g_stop_mining = 1;


//判断什么时候可以发送share share_time记录上次发送的时间
static int can_send_share(time_t current_time, time_t task_time, time_t share_time)
{
	//两次发送间隔 10 当前时间没有超过任务时间64s 即是说还在这一轮的主块竞选中
	int can_send = current_time - share_time >= SEND_PERIOD && current_time - task_time <= 64;

	//只有第一次发送share可以成功 如果mining_threads为0的话 因为发送后share_time就会大于task_time了
	if(g_xdag_mining_threads == 0 && share_time >= task_time) {
		can_send = 0;  //we send only one share per task if mining is turned off
	}
	return can_send;
}

/* initialization of connection the miner to pool */
//链接矿池
extern int xdag_initialize_miner(const char *pool_address)
{
	pthread_t th;

	memset(&g_local_miner, 0, sizeof(struct miner));
	//将自己的第一个地址块hash赋值到miner.id.data
	xdag_get_our_block(g_local_miner.id.data);

	int err = pthread_create(&th, 0, miner_net_thread, (void*)pool_address);
	if(err != 0) {
		printf("create miner_net_thread failed, error : %s\n", strerror(err));
		return -1;
	}

	err = pthread_detach(th);
	if(err != 0) {
		printf("detach miner_net_thread failed, error : %s\n", strerror(err));
		//return -1; //fixme: not sure why pthread_detach return 3
	}

	return 0;
}


//发送给矿池 参数 字段和字段数量
static int send_to_pool(struct xdag_field *fld, int nfld)
{
	fprintf(stdout,"->into send_to_pool\n");

	//先定义一个长度为xdag区块（16）的字段数组 因为crc要用区块大小的字段才能生成
	struct xdag_field f[XDAG_BLOCK_FIELDS];
	xdag_hash_t h;
	struct miner *m = &g_local_miner;
	//需要发送的字段只有todo这么大
	int todo = nfld * sizeof(struct xdag_field), done = 0;

	if(g_socket < 0) {
		return -1;
	}

	//把需要发送的字段复制到f中
	memcpy(f, fld, todo);

	//普通区块 如果不等于就是发送share
	//如果是nfld是16的话 说明是发送一个区块 区块头的transport_header进行处理
	if(nfld == XDAG_BLOCK_FIELDS) {
		f[0].transport_header = 0;

		xdag_hash(f, sizeof(struct xdag_block), h);
		
		f[0].transport_header = BLOCK_HEADER_WORD; //transport_header 8个字节


		uint32_t crc = crc_of_array((uint8_t*)f, sizeof(struct xdag_block));

		//前四个字节填校验码
		f[0].transport_header |= (uint64_t)crc << 32;
	}


	//进行加密处理
	for(int i = 0; i < nfld; ++i) {
		dfslib_encrypt_array(g_crypt, (uint32_t*)(f + i), DATA_SIZE, m->nfield_out++);
	}

	//当还有需要发送的时候循环 知道全都发送完成
	while(todo) {
		struct pollfd p;

		p.fd = g_socket;
		p.events = POLLOUT;

		if(!poll(&p, 1, 1000)) continue;

		if(p.revents & (POLLHUP | POLLERR)) {
			return -1;
		}

		if(!(p.revents & POLLOUT)) continue;

		//判断写了多少 然后继续传输剩下的内容 传输不一定全部传完 所以通过res来判断
		int res = write(g_socket, (uint8_t*)f + done, todo);
		if(res <= 0) {
			return -1;
		}

		done += res;
		todo -= res;
	}

	if(nfld == XDAG_BLOCK_FIELDS) {
		xdag_info("Sent  : %016llx%016llx%016llx%016llx t=%llx res=%d",
			h[3], h[2], h[1], h[0], fld[0].time, 0);
		fprintf(stdout,"Sent  : %016llx%016llx%016llx%016llx t=%llx res=%d",
			h[3], h[2], h[1], h[0], fld[0].time, 0);
	}

	return 0;
}

//矿工的网络线程 矿工的网络只有跟矿池有连接
void *miner_net_thread(void *arg)
{
	struct xdag_block b;
	struct xdag_field data[2];
	xdag_hash_t hash;
	const char *pool_address = (const char*)arg;
	const char *mess = NULL;
	int res = 0;
	xtime_t t;
	struct miner *m = &g_local_miner;

	while(!g_xdag_sync_on) {
		sleep(1);
	}

begin:
	m->nfield_in = m->nfield_out = 0;

	int ndata = 0;
	int maxndata = sizeof(struct xdag_field);
	time_t share_time = 0;
	time_t task_time = 0;

	if(g_miner_address) {
		if(xdag_address2hash(g_miner_address, hash)) {
			mess = "incorrect miner address";
			goto err;
		}
	} else if(xdag_get_our_block(hash)) {
		mess = "can't create a block";
		goto err;
	}

	const int64_t pos = xdag_get_block_pos(hash, &t, &b);
	//如果pos==-2l说明是附加块
	if (pos == -2l) {
		;
	} else if (pos < 0) {
		mess = "can't find the block";
		goto err;
	} else {
		struct xdag_block *blk = xdag_storage_load(hash, t, pos, &b);
		if(!blk) {
			mess = "can't load the block";
			goto err;
		}
		if(blk != &b) memcpy(&b, blk, sizeof(struct xdag_block));
	}
	//将矿工地址块赋值给b


	pthread_mutex_lock(&g_miner_mutex);
	g_socket = xdag_connect_pool(pool_address, &mess);
	if(g_socket == INVALID_SOCKET) {
		pthread_mutex_unlock(&g_miner_mutex);
		goto err;
	}
	uint64_t *tmph = b.field[1].hash;
	fprintf(stdout, "->send to pool my block   hash: %016llx%016llx%016llx%016llx\n",
			(unsigned long long)tmph[3], (unsigned long long)tmph[2], (unsigned long long)tmph[1], (unsigned long long)tmph[0]);

	//会发送b到矿池 小于0代表发送失败
	if(send_to_pool(b.field, XDAG_BLOCK_FIELDS) < 0) {
		mess = "socket is closed";
		pthread_mutex_unlock(&g_miner_mutex);
		goto err;
	}
	pthread_mutex_unlock(&g_miner_mutex);

	for(;;) {
		struct pollfd p;

		pthread_mutex_lock(&g_miner_mutex);

		if(g_socket < 0) {
			pthread_mutex_unlock(&g_miner_mutex);
			mess = "socket is closed";
			goto err;
		}

		p.fd = g_socket;
		time_t current_time = time(0);
		p.events = POLLIN | (can_send_share(current_time, task_time, share_time) ? POLLOUT : 0);

		if(!poll(&p, 1, 0)) {
			pthread_mutex_unlock(&g_miner_mutex);
			sleep(1);
			continue;
		}

		if(p.revents & POLLHUP) {
			pthread_mutex_unlock(&g_miner_mutex);
			mess = "socket hangup";
			goto err;
		}

		if(p.revents & POLLERR) {
			pthread_mutex_unlock(&g_miner_mutex);
			mess = "socket error";
			goto err;
		}

		if(p.revents & POLLIN) {
			//maxndata是32字节 一个字节一个字节的读 要读32字节一个字段的数据
			res = read(g_socket, (uint8_t*)data + ndata, maxndata - ndata);
			if(res < 0) {
				pthread_mutex_unlock(&g_miner_mutex); mess = "read error on socket"; goto err;
			}
			ndata += res;
			//如果已经读了第一个32字节
			if(ndata == maxndata) {
				//最终结果
				struct xdag_field *last = data + (ndata / sizeof(struct xdag_field) - 1);

				//将该字段解码  矿工的接收字段 nfield_in加一
				dfslib_uncrypt_array(g_crypt, (uint32_t*)last->data, DATA_SIZE, m->nfield_in++);

				//一种 余额 一种 就是任务
				//比较是不是跟自身地址匹配 如果是的话就是给你更新余额了 如果不是的话且maxndata也不是64字节 即两个字段的话 设置为两个字段 然后继续接收
				if(!memcmp(last->data, hash, sizeof(xdag_hashlow_t))) {
					xdag_set_balance(hash, last->amount); // 此时的last 就是 金额 + 192bit地址 

					pthread_mutex_lock(&g_transport_mutex);


					//最新收到余额的时间更新为当前
					g_xdag_last_received = current_time;
					pthread_mutex_unlock(&g_transport_mutex);

					//清零
					ndata = 0;
					//归位
					maxndata = sizeof(struct xdag_field);

				} else if(maxndata == 2 * sizeof(struct xdag_field)) {
					//接收到新任务 记录当前任务索引
					const uint64_t task_index = g_xdag_pool_task_index + 1;
					//判断当前任务奇偶 奇数偶数不同处理 接下来的这个task就是矿工的任务 
					struct xdag_pool_task *task = &g_xdag_pool_task[task_index & 1];

					//任务时间设置为当前epoch 接收任务数据
					task->task_time = xdag_main_time();
					xdag_hash_set_state(task->ctx, data[0].data,
						sizeof(struct xdag_block) - 2 * sizeof(struct xdag_field));
					//只剩下最后一个字段没放进
					xdag_hash_update(task->ctx, data[1].data, sizeof(struct xdag_field));
					//放进自己的地址hash低192bit进入最后一个字段
					xdag_hash_update(task->ctx, hash, sizeof(xdag_hashlow_t));

					//找随机数
					xdag_generate_random_array(task->nonce.data, sizeof(xdag_hash_t));

				
					memcpy(task->nonce.data, hash, sizeof(xdag_hashlow_t));
					memcpy(task->lastfield.data, task->nonce.data, sizeof(xdag_hash_t));

					xdag_hash_final(task->ctx, &task->nonce.amount, sizeof(uint64_t), task->minhash.data);


					//更新当前的最新任务
					g_xdag_pool_task_index = task_index;
					task_time = time(0);

					xdag_info("Task  : t=%llx N=%llu", task->task_time << 16 | 0xffff, task_index);
					fprintf(stdout,"Task  : t=%llx N=%llu", task->task_time << 16 | 0xffff, task_index);
					
					//清零 归位
					ndata = 0;
					maxndata = sizeof(struct xdag_field);
				} else {
					maxndata = 2 * sizeof(struct xdag_field);
				}
			}
		}
		//将share发送出去后就更新share_time
		if(p.revents & POLLOUT) {
			const uint64_t task_index = g_xdag_pool_task_index;
			struct xdag_pool_task *task = &g_xdag_pool_task[task_index & 1];
			//计算出来的最小hash
			uint64_t *h = task->minhash.data;

			//更新share_time
			share_time = time(0);
			//将计算出来的最小hash对应的nonce发送给矿池
			res = send_to_pool(&task->lastfield, 1);
			pthread_mutex_unlock(&g_miner_mutex);
			fprintf(stdout,"this for send share\n");
			xdag_info("Share : %016llx%016llx%016llx%016llx t=%llx res=%d",
				h[3], h[2], h[1], h[0], task->task_time << 16 | 0xffff, res);
			fprintf(stdout,"Share : %016llx%016llx%016llx%016llx t=%llx res=%d",
				h[3], h[2], h[1], h[0], task->task_time << 16 | 0xffff, res);

			if(res) {
				mess = "write error on socket"; goto err;
			}
		} else {
			pthread_mutex_unlock(&g_miner_mutex);
		}
	}

	return 0;

err:
	xdag_err("Miner: %s (error %d)", mess, res);

	pthread_mutex_lock(&g_miner_mutex);

	if(g_socket != INVALID_SOCKET) {
		close(g_socket);
		g_socket = INVALID_SOCKET;
	}

	pthread_mutex_unlock(&g_miner_mutex);

	sleep(5);

	goto begin;
}

//矿工 真正做计算的线程
static void *mining_thread(void *arg)
{
	xdag_hash_t hash;
	struct xdag_field last;
	const int nthread = (int)(uintptr_t)arg;
	uint64_t oldntask = 0;
	uint64_t nonce;

	while(!g_xdag_sync_on && !g_stop_mining) {
		sleep(1);
	}

	while(!g_stop_mining) {
		//当前第几个任务
		const uint64_t ntask = g_xdag_pool_task_index;
		struct xdag_pool_task *task = &g_xdag_pool_task[ntask & 1];
		//如果没有任务
		if(!ntask) {
			sleep(1);
			continue;
		}
		//如果最新任务不等于老任务（即是说当前新任务来了） 也即是说现在在工作的任务也成了老任务了 我们要开始做新的任务了
		if(ntask != oldntask) {
			oldntask = ntask;
			//nonce.data 包含了新任务给的数据信息
			// task->nonce.data存放倒数第一个字段的数据
			memcpy(last.data, task->nonce.data, sizeof(xdag_hash_t));
			//修改初始nonce (任务中会给一个随机的nonce)
			nonce = last.amount + nthread;
		}
		//last.amount保存最小hash时的nonce hash是最小hash
		//	xdag_hash_final_multi ：hash0是双sha256后的哈希值 nonce以step(threads)的步数改变 计算出最小的hash 最小hash时的min_nonce 尝试4096次(即4096次后返回最小nonce) 并将最小hash时的nonce返回 
		last.amount = xdag_hash_final_multi(task->ctx, &nonce, 4096, g_xdag_mining_threads, hash);
		g_xdag_extstats.nhashes += 4096;//已经做了4096次sha256d 加4096

		//设置最小的hash对应的nonce last.data已经包含了amount即min_nonce的值了 hash已经是最小hash了 然后更新这个task
		xdag_set_min_share(task, last.data, hash);
	}

	return 0;
}

/* changes the number of mining threads */
int xdag_mining_start(int n_mining_threads)
{
	pthread_t th;

	if(n_mining_threads == g_xdag_mining_threads) {

	} else if(!n_mining_threads) {
		g_stop_mining = 1;
		g_xdag_mining_threads = 0;
	} else if(!g_xdag_mining_threads) {
		g_stop_mining = 0;
	} else if(g_xdag_mining_threads > n_mining_threads) {
		g_stop_mining = 1;
		sleep(5);
		g_stop_mining = 0;
		g_xdag_mining_threads = 0;
	}
	//启动多个线程
	while(g_xdag_mining_threads < n_mining_threads) {
		g_xdag_mining_threads++;
		int err = pthread_create(&th, 0, mining_thread, (void*)(uintptr_t)g_xdag_mining_threads);
		if(err != 0) {
			printf("create mining_thread failed, error : %s\n", strerror(err));
			continue;
		}

		err = pthread_detach(th);
		if(err != 0) {
			printf("detach mining_thread failed, error : %s\n", strerror(err));
			continue;
		}
	}

	return 0;
}

/* send block to network via pool */
//发送给矿池区块
int xdag_send_block_via_pool(struct xdag_block *b)
{
	if(g_socket < 0) return -1;
	fprintf(stdout,"this for send transaction\n");

	pthread_mutex_lock(&g_miner_mutex);
	int ret = send_to_pool(b->field, XDAG_BLOCK_FIELDS);
	pthread_mutex_unlock(&g_miner_mutex);
	return ret;
}

//从矿池列表里随机选取矿池
/* picks random pool from the list of pools */
int xdag_pick_pool(char *pool_address)
{
	char addresses[30][50] = {0};
	const char *error_message;
	srand(time(NULL));
	
	int count = 0;
	FILE *fp = xdag_open_file(POOL_LIST_FILE, "r");
	if(!fp) {
		printf("List of pools is not found\n");
		return 0;
	}
	while(fgets(addresses[count], 50, fp)) {
		// remove trailing newline character
		addresses[count][strcspn(addresses[count], "\n")] = 0;
		++count;
	}
	fclose(fp);

	int start_index = count ? rand() % count : 0;
	int index = start_index;
	do {
		int socket = xdag_connect_pool(addresses[index], &error_message);
		if(socket != INVALID_SOCKET) {
			xdag_connection_close(socket);
			strncpy(pool_address, addresses[index], 49);
			return 1;
		} else {
			++index;
			if(index >= count) {
				index = 0;
			}
		}
	} while(index != start_index);

	printf("Wallet is unable to connect to network. Check your network connection\n");
	return 0;
}
