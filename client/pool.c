/* pool logic, T14.191-T14.618 $DVS:time$ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <float.h>
#if defined(_WIN32) || defined(_WIN64)
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <errno.h>
#endif
#include "block.h"
#include "sync.h"
#include "mining_common.h"
#include "pool.h"
#include "address.h"
#include "utils/moving_statistics/moving_average.h"
#include "commands.h"
#include "storage.h"
#include "transport.h"
#include "wallet.h"
#include "system.h"
#include "math.h"
#include "utils/log.h"
#include "utils/utils.h"
#include "../dus/programs/dfstools/source/dfslib/dfslib_crypt.h"
#include "../dus/programs/dar/source/include/crc.h"
#include "uthash/utlist.h"
#include "uthash/uthash.h"
#include "utils/atomic.h"
#include "time.h"

//TODO: why do we need these two definitions?
#define START_MINERS_COUNT     256
#define START_MINERS_IP_COUNT  8

#define FUND_ADDRESS                       "FQglVQtb60vQv2DOWEUL7yh3smtj7g1s" /* community fund */
#define SHARES_PER_TASK_LIMIT              20                                 /* maximum count of shares per task */
#define DEFAUL_CONNECTIONS_PER_MINER_LIMIT 100
#define WORKERNAME_HEADER_WORD             0xf46b9853u

struct nonce_hash {
	uint64_t key;
	UT_hash_handle hh;
};

//记录矿工的状态
enum miner_state {
	MINER_UNKNOWN = 0,
	MINER_ACTIVE = 1,
	MINER_ARCHIVE = 2,
	MINER_SERVICE = 3
};

//矿工在矿池中的记录
struct miner_pool_data {
	struct xdag_field id;
	xtime_t task_time;
	double prev_diff;
	uint32_t prev_diff_count;
	double maxdiff[CONFIRMATIONS_COUNT];
	enum miner_state state;
	uint32_t connections_count;
	uint64_t task_index;
	struct nonce_hash *nonces;
	xdag_hash_t last_min_hash;
	long double mean_log_difficulty;
	uint32_t bounded_task_counter;
	time_t registered_time;
};

//管理miner的链表
typedef struct miner_list_element {
	struct miner_pool_data miner_data;
	struct miner_list_element *next;
} miner_list_element;

//连接状态
enum connection_state {
	UNKNOWN_ADDRESS = 0,
	ACTIVE_CONNECTION = 1
};

//连接记录
struct connection_pool_data {
	xtime_t task_time;
	double prev_diff;
	uint32_t prev_diff_count;
	double maxdiff[CONFIRMATIONS_COUNT];
	uint32_t data[DATA_SIZE]; //会放数据 地址
	uint64_t nfield_in;
	uint64_t nfield_out;
	uint64_t task_index;
	struct xdag_block *block;
	uint32_t ip;
	uint16_t port;
	enum connection_state state;
	uint8_t data_size;
	uint8_t block_size;
	struct pollfd connection_descriptor;
	struct miner_pool_data *miner;
	time_t balance_refreshed_time;
	uint32_t shares_count;
	time_t last_share_time;
	atomic_int deleted;
	const char* disconnection_reason;
	xdag_hash_t last_min_hash;
	long double mean_log_difficulty;
	uint32_t bounded_task_counter;
	char* worker_name;
	time_t connected_time;
};

//连接记录链表
typedef struct connection_list_element {
	struct connection_pool_data connection_data;
	struct connection_list_element *next;
} connection_list_element;


//支付数据
struct payment_data {
	xdag_amount_t balance;
	xdag_amount_t pay;
	xdag_amount_t reward;
	xdag_amount_t direct;
	xdag_amount_t fund;
	double sum;
	double prev_sum;
	int reward_index;
};

xdag_hash_t g_xdag_mined_hashes[CONFIRMATIONS_COUNT];
xdag_hash_t g_xdag_mined_nonce[CONFIRMATIONS_COUNT];
xdag_remark_t g_pool_tag = {0};
int g_pool_has_tag = 0;

static uint32_t g_max_connections_count = START_MINERS_COUNT, g_max_miner_ip_count = START_MINERS_IP_COUNT;
static uint32_t g_connections_per_miner_limit = DEFAUL_CONNECTIONS_PER_MINER_LIMIT;
static uint32_t g_connections_count = 0;
static double g_pool_fee = 0, g_pool_reward = 0, g_pool_direct = 0, g_pool_fund = 0;
static struct xdag_block *g_firstb = 0, *g_lastb = 0;

static int g_stop_general_mining = 1;
extern int g_block_production_on;

static struct miner_pool_data g_pool_miner;
static struct miner_pool_data g_fund_miner;
static struct pollfd *g_fds;

static connection_list_element *g_connection_list_head = NULL;
static connection_list_element *g_accept_connection_list_head = NULL;
static miner_list_element *g_miner_list_head = NULL;
static uint32_t g_connection_changed = 0;
static pthread_mutex_t g_connections_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_pool_mutex = PTHREAD_MUTEX_INITIALIZER;

int pay_miners(xtime_t time);
void remove_inactive_miners(void);
void block_queue_append_new(struct xdag_block *b);
struct xdag_block *block_queue_first(void);

void *general_mining_thread(void *arg);
void *pool_net_thread(void *arg);
void *pool_main_thread(void *arg);
void *pool_block_thread(void *arg);
void *pool_remove_inactive_connections(void *arg);
void *pool_payment_thread(void *arg);

void update_mean_log_diff(struct connection_pool_data *, struct xdag_pool_task *, xdag_hash_t);

/* initialization of the pool */
int xdag_initialize_pool(const char *pool_arg)
{
	pthread_t th;

	memset(&g_pool_miner, 0, sizeof(struct miner_pool_data));
	memset(&g_fund_miner, 0, sizeof(struct miner_pool_data));

	//设置矿池的g_pool_miner 用第一个地址块设置
	xdag_get_our_block(g_pool_miner.id.data);
	//设置状态 服务状态
	g_pool_miner.state = MINER_SERVICE;

	//分配最大连接数的连接描述符数组
	g_fds = malloc(MAX_CONNECTIONS_COUNT * sizeof(struct pollfd));
	if(!g_fds) return -1;

	//矿池网络线程
	int err = pthread_create(&th, 0, pool_net_thread, (void*)pool_arg);
	if(err != 0) {
		printf("create pool_net_thread failed, error : %s\n", strerror(err));
		return -1;
	}

	err = pthread_detach(th);
	if(err != 0) {
		printf("detach pool_net_thread failed, error : %s\n", strerror(err));
		return -1;
	}

	//矿池的主线程
	err = pthread_create(&th, 0, pool_main_thread, 0);
	if(err != 0) {
		printf("create pool_main_thread failed, error : %s\n", strerror(err));
		return -1;
	}

	err = pthread_detach(th);
	if(err != 0) {
		printf("detach pool_main_thread failed, error : %s\n", strerror(err));
		return -1;
	}

	//矿池对于区块的线程
	err = pthread_create(&th, 0, pool_block_thread, 0);
	if(err != 0) {
		printf("create pool_block_thread failed: %s\n", strerror(err));
		return -1;
	}

	err = pthread_detach(th);
	if(err != 0) {
		printf("detach pool_block_thread failed: %s\n", strerror(err));
		return -1;
	}

	//矿池移除不活跃的连接
	err = pthread_create(&th, 0, pool_remove_inactive_connections, 0);
	if(err != 0) {
		printf("create pool_remove_inactive_connections failed: %s\n", strerror(err));
		return -1;
	}

	err = pthread_detach(th);
	if(err != 0) {
		printf("detach pool_remove_inactive_connections failed: %s\n", strerror(err));
		return -1;
	}

	//矿池支付的线程 支付矿工
	err = pthread_create(&th, 0, pool_payment_thread, 0);
	if(err != 0) {
		printf("create pool_payment_thread failed: %s\n", strerror(err));
		return -1;
	}

	err = pthread_detach(th);
	if(err != 0) {
		printf("detach pool_payment_thread failed: %s\n", strerror(err));
		return -1;
	}

	g_stop_general_mining = 0;

	//生成主块的线程
	err = pthread_create(&th, 0, general_mining_thread, 0);
	if(err != 0) {
		printf("create general_mining_thread failed, error : %s\n", strerror(err));
		return -1;
	}

	err = pthread_detach(th);
	if(err != 0) {
		printf("detach general_mining_thread failed, error : %s\n", strerror(err));
		return -1;
	}

	return 0;
}

//这里是每64s生成主块的地方
void *general_mining_thread(void *arg)
{
	while(!g_block_production_on && !g_stop_general_mining) {
		sleep(1);
	}

	xdag_mess("Starting main blocks creation...");

	while(!g_stop_general_mining) {
		fprintf(stdout,"general_mining_thread...\n");
		xdag_create_and_send_block(0, 0, 0, 0, 0, xdag_main_time() << 16 | 0xffff, NULL);
	}

	xdag_mess("Stopping general mining thread...");

	return 0;
}

/* sets pool parameters */
int xdag_pool_set_config(const char *pool_config)
{
	char buf[0x100] = {0}, *lasts = NULL;

	if(!g_xdag_pool) return -1;
	strncpy(buf, pool_config, 0xff);

	pool_config = strtok_r(buf, " \t\r\n:", &lasts);

	if(pool_config) {
		int max_connection_count_input;
		int open_max = (int)sysconf(_SC_OPEN_MAX);

		sscanf(pool_config, "%d", &max_connection_count_input);

		if(max_connection_count_input < 0) {
			max_connection_count_input = 0;
			xdag_warn("pool: wrong connections count");
		} else if(max_connection_count_input > MAX_CONNECTIONS_COUNT) {
			max_connection_count_input = MAX_CONNECTIONS_COUNT;
			xdag_warn("pool: exceed max connections count %d", MAX_CONNECTIONS_COUNT);
		} else if(max_connection_count_input > open_max - 64) {
			max_connection_count_input = open_max - 64;
			xdag_warn("pool: exceed max open files %d", open_max - 64);
		}
		g_max_connections_count = max_connection_count_input;
	}

	pool_config = strtok_r(0, " \t\r\n:", &lasts);
	if(pool_config) {
		sscanf(pool_config, "%d", &g_max_miner_ip_count);

		if(g_max_miner_ip_count <= 0)
			g_max_miner_ip_count = 1;
	}

	pool_config = strtok_r(0, " \t\r\n:", &lasts);
	if(pool_config) {
		sscanf(pool_config, "%d", &g_connections_per_miner_limit);

		if(g_connections_per_miner_limit <= 0)
			g_connections_per_miner_limit = 1;
	}

	pool_config = strtok_r(0, " \t\r\n:", &lasts);
	if(pool_config) {
		sscanf(pool_config, "%lf", &g_pool_fee);

		g_pool_fee /= 100;

		if(g_pool_fee < 0)
			g_pool_fee = 0;

		if(g_pool_fee > 1)
			g_pool_fee = 1;
	}

	pool_config = strtok_r(0, " \t\r\n:", &lasts);
	if(pool_config) {
		sscanf(pool_config, "%lf", &g_pool_reward);

		g_pool_reward /= 100;

		if(g_pool_reward < 0)
			g_pool_reward = 0;
		if(g_pool_fee + g_pool_reward > 1)
			g_pool_reward = 1 - g_pool_fee;
	}

	pool_config = strtok_r(0, " \t\r\n:", &lasts);
	if(pool_config) {
		sscanf(pool_config, "%lf", &g_pool_direct);

		g_pool_direct /= 100;

		if(g_pool_direct < 0)
			g_pool_direct = 0;
		if(g_pool_fee + g_pool_reward + g_pool_direct > 1)
			g_pool_direct = 1 - g_pool_fee - g_pool_reward;
	}

	pool_config = strtok_r(0, " \t\r\n:", &lasts);
	if(pool_config) {
		sscanf(pool_config, "%lf", &g_pool_fund);

		g_pool_fund /= 100;

		if(g_pool_fund < 0)
			g_pool_fund = 0;
		if(g_pool_fee + g_pool_reward + g_pool_direct + g_pool_fund > 1)
			g_pool_fund = 1 - g_pool_fee - g_pool_reward - g_pool_direct;
	}

	return 0;
}

/* gets pool parameters as a string, 0 - if the pool is disabled */
char *xdag_pool_get_config(char *buf)
{
	if(!g_xdag_pool) return 0;

	sprintf(buf, "%d:%d:%d:%.2lf:%.2lf:%.2lf:%.2lf", g_max_connections_count, g_max_miner_ip_count, g_connections_per_miner_limit,
		g_pool_fee * 100, g_pool_reward * 100, g_pool_direct * 100, g_pool_fund * 100);

	return buf;
}

//开启矿池服务器连接 供矿工连接 返回socket套接字（可以理解成serversocket）
static int open_pool_connection(const char *pool_arg)
{
	struct linger linger_opt = { 1, 0 }; // Linger active, timeout 0
	struct sockaddr_in peeraddr;
	int rcvbufsize = 1024;
	int reuseaddr = 1;
	char buf[0x100] = {0};
	char *nextParam = NULL;

	// Create a socket
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(sock == INVALID_SOCKET) {
		xdag_err("pool: cannot create a socket");
		return INVALID_SOCKET;
	}

	if(fcntl(sock, F_SETFD, FD_CLOEXEC) == -1) {
		xdag_err("pool: can't set FD_CLOEXEC flag on socket %d, %s\n", sock, strerror(errno));
	}

	// Fill in the address of server
	memset(&peeraddr, 0, sizeof(peeraddr));
	peeraddr.sin_family = AF_INET;

	// Resolve the server address (convert from symbolic name to IP number)
	if(pool_arg != NULL){
		strncpy(buf, pool_arg, 0xff);
	}
	pool_arg = strtok_r(buf, " \t\r\n:", &nextParam);
	if(!pool_arg) {
		xdag_err("pool: host is not given");
		return INVALID_SOCKET;
	}

	peeraddr.sin_addr.s_addr = htonl(INADDR_ANY);

	// Resolve port
	pool_arg = strtok_r(0, " \t\r\n:", &nextParam);
	if(!pool_arg) {
		xdag_err("pool: port is not given");
		return INVALID_SOCKET;
	}
	peeraddr.sin_port = htons(atoi(pool_arg));

	//绑定
	int res = bind(sock, (struct sockaddr*)&peeraddr, sizeof(peeraddr));
	if(res) {
		xdag_err("pool: cannot bind a socket (error %s)", strerror(res));
		return INVALID_SOCKET;
	}

	// Set the "LINGER" timeout to zero, to close the listen socket
	// immediately at program termination.
	setsockopt(sock, SOL_SOCKET, SO_LINGER, (char*)&linger_opt, sizeof(linger_opt));
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuseaddr, sizeof(int));
	setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&rcvbufsize, sizeof(int));

	pool_arg = strtok_r(0, " \t\r\n", &nextParam);
	if(pool_arg) {
		xdag_pool_set_config(pool_arg);
	}

	return sock;
}

//不能超过最大连接数
//同样ip地址的连接不能超过8个
static int connection_can_be_accepted(int sock, struct sockaddr_in *peeraddr)
{
	connection_list_element *elt;

	//firstly we check that total count of connection did not exceed max count of connection
	if(g_connections_count >= g_max_connections_count) {
		xdag_warn("Max connections %d exceed, new connections are not accepted.", g_max_connections_count);
		return 0;
	}

	//then we check that count of connections with the same IP address did not exceed the limit
	uint32_t count = 0;
	LL_FOREACH(g_connection_list_head, elt)
	{
		if(elt->connection_data.ip == peeraddr->sin_addr.s_addr) {
			if(++count >= g_max_miner_ip_count) {
				int ip = elt->connection_data.ip;
				xdag_warn("Max connection %d for ip %u.%u.%u.%u:%u exceed, new connections are not accepted.",
					g_max_miner_ip_count, ip & 0xff, ip >> 8 & 0xff, ip >> 16 & 0xff, ip >> 24 & 0xff,
					ntohs(elt->connection_data.port));
				return 0;
			}
		}
	}

	LL_FOREACH(g_accept_connection_list_head, elt)
	{
		if(elt->connection_data.ip == peeraddr->sin_addr.s_addr) {
			if(++count >= g_max_miner_ip_count) {
				int ip = elt->connection_data.ip;
				xdag_warn("Max connection %d for ip %u.%u.%u.%u:%u exceed, new connections are not accepted.",
					g_max_miner_ip_count, ip & 0xff, ip >> 8 & 0xff, ip >> 16 & 0xff, ip >> 24 & 0xff,
					ntohs(elt->connection_data.port));
				return 0;
			}
		}
	}

	return 1;
}

//网络线程 接收连接
void *pool_net_thread(void *arg)
{
	const char *pool_arg = (const char*)arg;
	struct sockaddr_in peeraddr;
	socklen_t peeraddr_len = sizeof(peeraddr);
	int rcvbufsize = 1024;

	while(!g_block_production_on) {
		sleep(1);
	}

	xdag_mess("Pool starts to accept connections...");

	//开启矿池连接
	int sock = open_pool_connection(pool_arg);
	if(sock == INVALID_SOCKET) {
		xdag_err("Pool: open connection error!");
		return 0;
	}

	// Now, listen for a connection
	//监听连接 最大8192
	int res = listen(sock, MAX_CONNECTIONS_COUNT);    // "1" is the maximal length of the queue
	if(res) {
		xdag_err("pool: cannot listen");
		return 0;
	}

	for(;;) {
		// Accept a connection (the "accept" command waits for a connection with
		// no timeout limit...)
		// sockfd -- socket()函数返回的描述符;

		// addr -- 输出一个的sockaddr_in变量地址，该变量用来存放发起连接请求的客户端的协议地址；

		// addrten -- 作为输入时指明缓冲器的长度，作为输出时指明addr的实际长度。
		//返回的fd套接字用来通信
		int fd = accept(sock, (struct sockaddr*)&peeraddr, &peeraddr_len);
		if(fd < 0) {
			xdag_err("pool: cannot accept connection");
			return 0;
		}

		pthread_mutex_lock(&g_connections_mutex);
		//判断该连接是否能接受
		//不能超过最大连接数
		//同样ip地址的连接不能超过8个
		if(!connection_can_be_accepted(sock, &peeraddr)) {
			close(fd);
			pthread_mutex_unlock(&g_connections_mutex);
			continue;
		}
		
		//设置接收缓冲区大小1k
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char*)&rcvbufsize, sizeof(int));

		//connection管理列表
		//新建一个connection管理
		struct connection_list_element *new_connection = (struct connection_list_element*)malloc(sizeof(connection_list_element));
		//清零
		memset(new_connection, 0, sizeof(connection_list_element));
		//连接的套接字设置为fd
		new_connection->connection_data.connection_descriptor.fd = fd;
		//接收和发送事件
		new_connection->connection_data.connection_descriptor.events = POLLIN | POLLOUT;
		//
		new_connection->connection_data.connection_descriptor.revents = 0;
		//ip设置为连接的ip 并赋值给新连接的ip
		uint32_t ip = new_connection->connection_data.ip = peeraddr.sin_addr.s_addr;
		//端口
		uint16_t port = new_connection->connection_data.port = peeraddr.sin_port;
		//新连接的时间
		new_connection->connection_data.connected_time = time(0);
		//新连接发送的最新share时间设置为新连接过来的时间 避免立刻断开
		new_connection->connection_data.last_share_time = new_connection->connection_data.connected_time; // we set time of last share to the current time in order to avoid immediate disconnection
		atomic_init_int(&new_connection->connection_data.deleted, 0);

		//将新连接加入全局管理列表中
		LL_APPEND(g_accept_connection_list_head, new_connection);
		//全局连接数（也是矿工数）加一 
		++g_connections_count;
		pthread_mutex_unlock(&g_connections_mutex);

		//
		xdag_info("Pool  : miner %d connected from %u.%u.%u.%u:%u", g_connections_count,
			ip & 0xff, ip >> 8 & 0xff, ip >> 16 & 0xff, ip >> 24 & 0xff, ntohs(port));
	}

	return 0;
}


//关闭连接 由于同个ip的连接可能有多个矿工 所以关闭的可能只是某个矿工的连接
static void close_connection(connection_list_element *connection, const char *message)
{
	//获取带关闭连接的详细信息
	struct connection_pool_data *conn_data = &connection->connection_data;
	//
	struct xdag_field id;
	enum miner_state state = MINER_UNKNOWN;

	pthread_mutex_lock(&g_connections_mutex);
	//将连接从全局连接列表中删除
	LL_DELETE(g_connection_list_head, connection);
	//矿工数量减一
	--g_connections_count;
	//连接状态改变
	g_connection_changed = 1;

	//关闭对应的套接字
	close(conn_data->connection_descriptor.fd);

	//连接时发送地址块 这里的block就是对应的block 
	if(conn_data->block) {
		free(conn_data->block);
	}
	//释放
	if(conn_data->worker_name) {
		free(conn_data->worker_name);
	}
	//如果连接的矿池是给定的
	if(conn_data->miner) {
		//同个连接可能有多个矿工 矿工-1
		--conn_data->miner->connections_count;
		//如果等于0
		if(conn_data->miner->connections_count == 0) {
			//存档
			state = conn_data->miner->state = MINER_ARCHIVE;
			id = conn_data->miner->id;
		} else {
			state = conn_data->miner->state;
		}	
	}
	pthread_mutex_unlock(&g_connections_mutex);

	//ip和端口
	uint32_t ip = conn_data->ip;
	uint16_t port = conn_data->port;


	if(conn_data->miner) {
		char address_buf[33] = {0};
		xdag_hash2address((state == MINER_ARCHIVE ? id.data : conn_data->miner->id.data), address_buf);
		xdag_info("Pool: miner %s disconnected from %u.%u.%u.%u:%u by %s", address_buf,
			ip & 0xff, ip >> 8 & 0xff, ip >> 16 & 0xff, ip >> 24 & 0xff, ntohs(port), message);
	} else {
		xdag_info("Pool: disconnected from %u.%u.%u.%u:%u by %s",
			ip & 0xff, ip >> 8 & 0xff, ip >> 16 & 0xff, ip >> 24 & 0xff, ntohs(port), message);
	}
	//释放
	free(connection);
}


/* @method      :- calculate_nopaid_shares
+  @param       :-
+               struct connection_pool_data* connection data :- miner's side data
+               struct xdag_pool_task* task data             :- pool's side data
+               xdag_hash_t hash                             :- is a digest computed by the pool starting from the
+                                                            miner's data 'conn_data->data' and pool side context task->ctx0
+  @return      :- void
+  @description :- calculate nopaid share */


//计算还未支付的share
static void calculate_nopaid_shares(struct connection_pool_data *conn_data, struct xdag_pool_task *task, xdag_hash_t hash)
{
	const xtime_t task_time = task->task_time;

	if(conn_data->task_time <= task_time) { // At the beginning conn_data->task_time=0. conn_data->task_time > task_time isn't accepted.
		double diff = ((uint64_t*)hash)[2];
		int i = task_time & (CONFIRMATIONS_COUNT - 1);	// CONFIRMATION_COUNT-1=15d=1111b, thus it just cut task_time to its 4 least significant bit

		// %%%%%% ldexp(double a, int b) -> ldexp(diff, -64) will return [diff/2^64] %%%%%%
		// Since max value of diff is 0xFFFFFFFFFFFFFFFF (it is a 64bit unsigned integer variable)
		// and 2^64 is 0xFFFFFFFFFFFFFFFF, ldexp(diff, -64) will return exactly 1 iff
		// diff value is equal to 0xFFFFFFFFFFFFFFFF (can't be higher by definition).
		// But because of the approximation from double to int
		// even when diff is "around" 0xFFFFFFFFFFFFFFFF diff will be 1.
		// Test: for diff >= FFFFFFFFFFFFFC00 (18446744073709550592) ldexp(diff, -64)=1
		// Test: for diff <= FFFFFFFFFFFFFBFF (18446744073709550591) ldexp(diff, -64)=0
		// Still need to investigate the purpose of using ldexp function to do it.

		// %%%%%% 		diff += ((uint64_t*)hash)[3];			     %%%%%%
		// Given that hash[3] is the most significant part of the 256 bit number
		// hash[3] || hash[2] || hash[1] || hash[0]
		// If, as explained previously, hash[2] is near its possible maximum value
		// then diff will be equal to hash[3]+1.

		// %%%%%% 		           diff 			     %%%%%%
		// At this point, diff, seems to be a condensate approximated representation 
		// of the 256 bit number hash[3] || hash[2] || hash[1] || hash[0].

		diff = ldexp(diff, -64);
		diff += ((uint64_t*)hash)[3];

		if(diff < 1) diff = 1;
		diff = 46 - log(diff);

		// Adding share for connection
		if(conn_data->task_time < task_time) { // conn_data->task_time will keep old value until pool doesn't accept the share of the task.
			conn_data->task_time = task_time;  // this will prevent to count more share for the same task, cannot join this block a new time for same task.

			if(conn_data->maxdiff[i] > 0) {
				conn_data->prev_diff += conn_data->maxdiff[i];
				conn_data->prev_diff_count++;
			}

			conn_data->maxdiff[i] = diff;
			// share already counted, but we will update the maxdiff so the most difficult share will be counted.
		} else if(diff > conn_data->maxdiff[i]) {
			conn_data->maxdiff[i] = diff;
		}

		// Adding share for miner
		if(conn_data->miner->task_time < task_time) {
			conn_data->miner->task_time = task_time;

			if(conn_data->miner->maxdiff[i] > 0) {
				conn_data->miner->prev_diff += conn_data->miner->maxdiff[i];
				conn_data->miner->prev_diff_count++;
			}

			conn_data->miner->maxdiff[i] = diff;
		} else if(diff > conn_data->miner->maxdiff[i]) {
			conn_data->miner->maxdiff[i] = diff;
		}
	}
}

//一矿工可以多连接
static int register_new_miner(connection_list_element *connection)
{
	miner_list_element *elt;
	//新连接的具体信息
	struct connection_pool_data *conn_data = &connection->connection_data;

	xtime_t tm;
	//从内存中找到对应的区块 conn_data->data存放区块的hash值 并获取区块在持久化中的存储位置和区块生成的时间 不用获取持久化数据
	const int64_t position = xdag_get_block_pos((const uint64_t*)conn_data->data, &tm, 0);

	//如果没有对应的区块 则关闭连接
	if(position < 0) {
		char address_buf[33] = {0};
		char message[100] = {0};
		xdag_hash2address((const uint64_t*)conn_data->data, address_buf);
		sprintf(message, "Miner's address is unknown (%s)", address_buf);
		close_connection(connection, message);
		return 0;
	}

	int exists = 0;
	pthread_mutex_lock(&g_connections_mutex);
	//循环矿工管理链表
	LL_FOREACH(g_miner_list_head, elt)
	{	
		//如果当前连接进来的矿工已经存在 即地址块都相同
		if(memcmp(elt->miner_data.id.data, conn_data->data, sizeof(xdag_hashlow_t)) == 0) {
			//一个矿工可以多个连接但不能超过最大值100 如果超过就关掉连接
			if(elt->miner_data.connections_count >= g_connections_per_miner_limit) {
				pthread_mutex_unlock(&g_connections_mutex);
				close_connection(connection, "Max count of connections per miner is exceeded");
				return 0;
			}

			//设置该连接所属的矿工信息
			conn_data->miner = &elt->miner_data;
			//所属的矿工连接数++
			++conn_data->miner->connections_count;
			//激活对应连接的矿工
			conn_data->miner->state = MINER_ACTIVE;
			//激活对应的连接
			conn_data->state = ACTIVE_CONNECTION;
			exists = 1;
			break;
		}
	}
	pthread_mutex_unlock(&g_connections_mutex);


	//如果连接进来的矿工是新的
	if(!exists) {
		pthread_mutex_lock(&g_connections_mutex);
		struct miner_list_element *new_miner = (struct miner_list_element*)malloc(sizeof(miner_list_element));
		memset(new_miner, 0, sizeof(miner_list_element));
		//矿工设置id.data 地址块hash
		memcpy(new_miner->miner_data.id.data, conn_data->data, sizeof(struct xdag_field));
		//当前矿工连接数为1
		new_miner->miner_data.connections_count = 1;
		//激活矿工
		new_miner->miner_data.state = MINER_ACTIVE;
		//矿工注册时间
		new_miner->miner_data.registered_time = time(0);
		//矿工管理链表添加新的矿工
		LL_APPEND(g_miner_list_head, new_miner);
		//当前的连接对应的矿工信息
		conn_data->miner = &new_miner->miner_data;
		//激活连接
		conn_data->state = ACTIVE_CONNECTION;
		pthread_mutex_unlock(&g_connections_mutex);
	}

	return 1;
}

static void clear_nonces_hashtable(struct miner_pool_data *miner)
{
	struct nonce_hash *eln, *tmp;
	HASH_ITER(hh, miner->nonces, eln, tmp)
	{
		HASH_DEL(miner->nonces, eln);
		free(eln);
	}
}

//首先得判断当前矿工在做的任务 是不是和当前任务是同一个 判断share有没有重复（不同矿工） 重复的不接受
static int share_can_be_accepted(struct miner_pool_data *miner, xdag_hash_t share, uint64_t task_index)
{
	if(!miner) {
		xdag_err("conn_data->miner is null");
		return 0;
	}
	struct nonce_hash *eln;
	uint64_t nonce = share[3]; //获取nonce
	//如果不是同个任务 将矿工的任务修改
	if(miner->task_index != task_index) {
		clear_nonces_hashtable(miner);
		miner->task_index = task_index;
	} else {
		//判断有没有重复 如果发送的是重复的不接受
		HASH_FIND(hh, miner->nonces, &nonce, sizeof(uint64_t), eln);
		if(eln != NULL) {
			return 0;	// we received the same nonce and will ignore duplicate
		}
	}
	eln = (struct nonce_hash*)malloc(sizeof(struct nonce_hash));
	eln->key = nonce;
	//添加新的share
	HASH_ADD(hh, miner->nonces, key, sizeof(uint64_t), eln);
	return 1;
}

// checks if received data belongs to block and processes that block
// returns:
// -1 - error
// 0 - received data does not belong to block
// 1 - block data is processed

//如果是区块的话 会把区块放入queue队列中 该队列的区块后续会处理（add）并发送给其他矿池
static int is_block_data_received(connection_list_element *connection)
{
	struct connection_pool_data *conn_data = &connection->connection_data;

	if(!conn_data->block_size && conn_data->data[0] == BLOCK_HEADER_WORD) {
		conn_data->block = malloc(sizeof(struct xdag_block));

		if(!conn_data->block) {
			return -1;
		}

		memcpy(conn_data->block->field, conn_data->data, sizeof(struct xdag_field));
		conn_data->block_size++;
	} else if(conn_data->nfield_in == 1) {
		close_connection(connection, "protocol mismatch");
		return -1;
	} else if(conn_data->block_size) {
		memcpy(conn_data->block->field + conn_data->block_size, conn_data->data, sizeof(struct xdag_field));
		conn_data->block_size++;
		if(conn_data->block_size == XDAG_BLOCK_FIELDS) {
			//获取校验码
			uint32_t crc = conn_data->block->field[0].transport_header >> 32;

			//清零传输头的校验码
			conn_data->block->field[0].transport_header &= (uint64_t)0xffffffffu;

			//看看计算出来的校验码是否正确
			if(crc == crc_of_array((uint8_t*)conn_data->block, sizeof(struct xdag_block))) {
				//校验成功 传输头清零
				conn_data->block->field[0].transport_header = 0;
				block_queue_append_new(conn_data->block);
			} else {
				free(conn_data->block);
			}

			conn_data->block = 0;
			conn_data->block_size = 0;
		}
	} else {
		return 0;
	}

	return 1;
}

// checks if received data belongs to worker name
// returns:
// 0 - received data does not belong to worker name
// 1 - worker name is processed
static int is_worker_name_received(connection_list_element *connection)
{
	struct connection_pool_data *conn_data = &connection->connection_data;

	if(conn_data->nfield_in == 17 && conn_data->data[0] == WORKERNAME_HEADER_WORD) {
		size_t worker_name_len = strnlen((const char*)&conn_data->data[1], 28);
		if(worker_name_len) {
			conn_data->worker_name = (char*)malloc(worker_name_len + 1);
			memcpy(conn_data->worker_name, (const char*)&conn_data->data[1], worker_name_len);
			conn_data->worker_name[worker_name_len] = 0;
			replace_all_nonprintable_characters(conn_data->worker_name, -1, '_');
			return 1;
		}
	}

	return 0;
}

// processes received share
// returns:
// 0 - error
// 1 - success

//如果是share加进来的话
static int process_received_share(connection_list_element *connection)
{
	//conn_data->data包含矿工地址和计算出来的nonce
	struct connection_pool_data *conn_data = &connection->connection_data;

	const uint64_t task_index = g_xdag_pool_task_index;
	struct xdag_pool_task *task = &g_xdag_pool_task[task_index & 1];

	//避免粉尘攻击 shares_count记录发送的share个数
	if(++conn_data->shares_count > SHARES_PER_TASK_LIMIT) {   //if shares count limit is exceded it is considered as spamming and current connection is disconnected
		close_connection(connection, "Spamming of shares");
		return 0;
	}
	//如果该连接的状态是未知 新开的连接的话 默认是UNKNOWN_ADDRESS
	if(conn_data->state == UNKNOWN_ADDRESS) {
		//把该连接注册为新矿工
		if(!register_new_miner(connection)) {
			return 0;
		}
	} else {
		if(!conn_data->miner) {
			close_connection(connection, "Miner is unregistered");
			return 0;
		}
		//连接的
		if(memcmp(conn_data->miner->id.data, conn_data->data, sizeof(xdag_hashlow_t)) != 0) {
			close_connection(connection, "Wallet address was unexpectedly changed");
			return 0;
		}
		//将接收字段（地址+nonce） 覆盖到原先到id.data中去
		memcpy(conn_data->miner->id.data, conn_data->data, sizeof(struct xdag_field));	//TODO:do I need to copy whole field?
	}

	conn_data->last_share_time = time(0);

	if(share_can_be_accepted(conn_data->miner, (uint64_t*)conn_data->data, task_index)) {
		xdag_hash_t hash;
		//ctx0存放的是去除最后一个字段的
		xdag_hash_final(task->ctx0, conn_data->data, sizeof(struct xdag_field), hash);
		//这里将task的lastfield设置为挖出最小hash的矿工的地址
		xdag_set_min_share(task, conn_data->miner->id.data, hash);
		update_mean_log_diff(conn_data, task, hash);

		//计算share该支付多少 task的lastfield设置为了最小hash的矿工地址 hash是最小hash
		calculate_nopaid_shares(conn_data, task, hash);
	}

	return 1;
}

//从连接中接收信息（可能是区块 可能是share 可能是workername）
static int receive_data_from_connection(connection_list_element *connection)
{
#if _DEBUG
	int ip = connection->connection_data.ip;
	xdag_debug("Pool  : receive data from %u.%u.%u.%u:%u",
		ip & 0xff, ip >> 8 & 0xff, ip >> 16 & 0xff, ip >> 24 & 0xff, ntohs(connection->connection_data.port));
#endif

	struct connection_pool_data *conn_data = &connection->connection_data;
	ssize_t data_size = sizeof(struct xdag_field) - conn_data->data_size;
	//将传进来的数据读到conn_data->data
	data_size = read(conn_data->connection_descriptor.fd, (uint8_t*)conn_data->data + conn_data->data_size, data_size);

	if(data_size < 0) {
		char message[100] = {0};
		sprintf(message, "read error : %s", strerror(errno));
		close_connection(connection, message);
		return 0;
	} else if(data_size == 0) {
		// fixme: read 0
		return 0;
	}

	//记录读进来的数据大小
	conn_data->data_size += data_size;

	//一个字段一个字段的接收
	if(conn_data->data_size == sizeof(struct xdag_field)) { //32
		conn_data->data_size = 0;
		//解密
		dfslib_uncrypt_array(g_crypt, conn_data->data, DATA_SIZE, conn_data->nfield_in++);

		// -1 - error
		// 0 - received data does not belong to block
		// 1 - block data is processed
		int result = is_block_data_received(connection);
		if(result < 0) {
			return 0;
		}
		if(result > 0) {
			return 1;
		}

		result = is_worker_name_received(connection);
		if(result > 0) {
			return 1;
		}

		//share is received
		//如果接收到的是一个字段 说明接收矿工发来的share 即conn_data->data存的是计算出最小hash对应的nonce的数据
		if(!process_received_share(connection)) {
			return 0;
		}
	}

	return 1;
}

//发送数据给连接
static int send_data_to_connection(connection_list_element *connection, int *processed)
{
	struct xdag_field data[2];
	memset(data, 0, sizeof(struct xdag_field) * 2);
	int fields_count = 0;
	//获取该连接的详细信息
	struct connection_pool_data *conn_data = &connection->connection_data;

	const uint64_t task_index = g_xdag_pool_task_index;
	struct xdag_pool_task *task = &g_xdag_pool_task[task_index & 1];
	time_t current_time = time(0);

	//该连接的任务有没有落后
	if(conn_data->task_index < task_index) {
		conn_data->task_index = task_index;
		conn_data->shares_count = 0;
		fields_count = 2;
		//复制任务（两个字段）到data中 task->task[0].data存放去除最后两个字段的ctx0状态 task->task[1].data存放主块倒数第二个字段的数据
		memcpy(data, task->task, fields_count * sizeof(struct xdag_field));

	}
	//如果没有落后的话就更新余额给矿工 10s更新一次
	else if(conn_data->miner && current_time - conn_data->balance_refreshed_time >= 10) {  //refresh balance each 10 seconds
		//TODO: optimize refreshing of balance
		conn_data->balance_refreshed_time = current_time;
		memcpy(data[0].data, conn_data->miner->id.data, sizeof(xdag_hash_t));
		//data[0]就是 余额+地址低192bit
		data[0].amount = xdag_get_balance(data[0].data);
		//只发送一个字段
		fields_count = 1;
	}

	if(fields_count) {
		*processed = 1;
		//加密
		for(int j = 0; j < fields_count; ++j) {
			dfslib_encrypt_array(g_crypt, (uint32_t*)(data + j), DATA_SIZE, conn_data->nfield_out++);
		}

		//把数据写到连接中
		size_t length = write(conn_data->connection_descriptor.fd, (void*)data, fields_count * sizeof(struct xdag_field));

		if(length != fields_count * sizeof(struct xdag_field)) {
			char message[100] = {0};
			sprintf(message, "write error  %s : write %zu bytes of %lu bytes", strerror(errno), length, fields_count * sizeof(struct xdag_field));
			close_connection(connection, message);
			return 0;
		}
	}

	return 1;
}

//接收 发送
void *pool_main_thread(void *arg)
{
	while(!g_xdag_sync_on) {
		sleep(1);
	}

	connection_list_element *elt, *eltmp;

	for(;;) {
		pthread_mutex_lock(&g_connections_mutex);

		// move accept connection to g_connection_list_head.
	
		LL_FOREACH_SAFE(g_accept_connection_list_head, elt, eltmp)
		{
			LL_DELETE(g_accept_connection_list_head, elt);
			LL_APPEND(g_connection_list_head, elt);
			g_connection_changed = 1;
		}
		int index = 0;
		if(g_connection_changed) {
			g_connection_changed = 0;
			LL_FOREACH(g_connection_list_head, elt)
			{
				memcpy(g_fds + index, &elt->connection_data.connection_descriptor, sizeof(struct pollfd));
				++index;
			}
		}

		int connections_count = g_connections_count;
		pthread_mutex_unlock(&g_connections_mutex);

		int res = poll(g_fds, connections_count, 1000);
		if(!res) continue;

		index = 0;
		int processed = 0;
		//循环所有的连接 判断是否有输入或输出
		LL_FOREACH_SAFE(g_connection_list_head, elt, eltmp)
		{
			struct pollfd *p = g_fds + index++;

			if(atomic_load_explicit_int(&elt->connection_data.deleted, memory_order_acquire)) {
				close_connection(elt, elt->connection_data.disconnection_reason);
				continue;
			}

			if(p->revents & POLLNVAL) {
				continue;
			}

			if(p->revents & POLLHUP) {
				processed = 1;
				close_connection(elt, "socket hangup");
				continue;
			}

			if(p->revents & POLLERR) {
				processed = 1;
				close_connection(elt, "socket error");
				continue;
			}


			if(p->revents & POLLIN) {
				processed = 1;
				if(!receive_data_from_connection(elt)) {
					continue;
				}
			}

			if(p->revents & POLLOUT) {
				if(!send_data_to_connection(elt, &processed)) {
					continue;
				}
			}
		}

		if(!processed) {
			sleep(1);
		}
	}

	return 0;
}

//该线程不断从block_queue中获取g_first加入到本地并发送给其他矿池 块池的管理 处理矿工发送过来的区块
void *pool_block_thread(void *arg)
{
	while(!g_xdag_sync_on) {
		sleep(1);
	}

	for(;;) {
		int processed = 0;

		struct xdag_block *b = block_queue_first();

		if(b) {
			processed = 1;
			b->field[0].transport_header = 2;

			int res = xdag_add_block(b);
			if(res > 0) {
				xdag_send_new_block(b);
			}
			free(b);
		}

		if(!processed) sleep(1);
	}

	return 0;
}

//支付线程
void *pool_payment_thread(void *arg)
{
	xtime_t prev_task_time = 0;

	while(!g_xdag_sync_on) {
		sleep(1);
	}

	for(;;) {
		int processed = 0;
		const uint64_t task_index = g_xdag_pool_task_index;
		struct xdag_pool_task *task = &g_xdag_pool_task[task_index & 1];
		const xtime_t current_task_time = task->task_time;

		if(current_task_time > prev_task_time) {
			uint64_t *hash = g_xdag_mined_hashes[(current_task_time - CONFIRMATIONS_COUNT + 1) & (CONFIRMATIONS_COUNT - 1)];

			processed = 1;
			prev_task_time = current_task_time;

			int res = pay_miners(current_task_time - CONFIRMATIONS_COUNT + 1);
			remove_inactive_miners();

			xdag_info("%s: %016llx%016llx%016llx%016llx t=%llx res=%d", (res ? "Nopaid" : "Paid  "),
				hash[3], hash[2], hash[1], hash[0], (current_task_time - CONFIRMATIONS_COUNT + 1) << 16 | 0xffff, res);
		}

		if(!processed) sleep(1);
	}

	return 0;
}

#define calculate_diff_summ(miner, sum, count) { \
	sum = miner->prev_diff; \
	count = miner->prev_diff_count;	\
	for(int j = 0; j < CONFIRMATIONS_COUNT; ++j) {	\
		if(miner->maxdiff[j] > 0) { \
			sum += miner->maxdiff[j]; \
			++count; \
		} \
	} \
}

#define diff2pay(d, n) ((n) ? exp((d) / (n) - 20) * (n) : 0)

static inline double miner_calculate_unpaid_shares(struct miner_pool_data *miner)
{
	double sum;
	int count;
	calculate_diff_summ(miner, sum, count);
	return diff2pay(sum, count);
}

static inline double connection_calculate_unpaid_shares(struct connection_pool_data *connection)
{
	double sum;
	int count;
	calculate_diff_summ(connection, sum, count);
	return diff2pay(sum, count);
}

// calculates the rest of shares and clear shares
//计算矿工的平均挖矿难度
static double process_outdated_miner(struct miner_pool_data *miner)
{
	double sum = 0;
	int diff_count = 0;

	for(int i = 0; i < CONFIRMATIONS_COUNT; ++i) {
		if(miner->maxdiff[i] > 0) {
			sum += miner->maxdiff[i];
			miner->maxdiff[i] = 0;
			++diff_count;
		}
	}

	if(diff_count > 0) {
		sum /= diff_count;
	}

	return sum;
}

static double countpay(struct miner_pool_data *miner, int confirmation_index, double *pay)
{
	double sum = 0;
	int diff_count = 0;

	//if miner is in archive state and last connection was disconnected more than 16 minutes ago we pay for the rest of shares and clear shares
	if(miner->state == MINER_ARCHIVE && g_xdag_pool_task_index - miner->task_index > CONFIRMATIONS_COUNT) {
		sum += process_outdated_miner(miner);
		diff_count++;
	} else if(miner->maxdiff[confirmation_index] > 0) {
		sum += miner->maxdiff[confirmation_index];
		miner->maxdiff[confirmation_index] = 0;
		++diff_count;
	}

	*pay = diff2pay(sum, diff_count);
	sum += miner->prev_diff;
	diff_count += miner->prev_diff_count;
	miner->prev_diff = 0;
	miner->prev_diff_count = 0;

	return diff2pay(sum, diff_count);
}

static double precalculate_payments(uint64_t *hash, int confirmation_index, struct payment_data *data, double *diff, double *prev_diff, uint64_t *nonce)
{
	miner_list_element *elt;

	data->reward = (xdag_amount_t)(data->balance * g_pool_reward);
	data->pay -= data->reward;

	if(g_pool_fund) {
		if(g_fund_miner.state == MINER_UNKNOWN) {
			xtime_t t;
			if(!xdag_address2hash(FUND_ADDRESS, g_fund_miner.id.hash) && xdag_get_block_pos(g_fund_miner.id.hash, &t, 0) >= 0) {
				g_fund_miner.state = MINER_SERVICE;
			}
		}

		if(g_fund_miner.state != MINER_UNKNOWN) {
			data->fund = data->balance * g_pool_fund;
			data->pay -= data->fund;
		}
	}

	data->prev_sum = countpay(&g_pool_miner, confirmation_index, &data->sum);

	int index = 0;
	pthread_mutex_lock(&g_connections_mutex);
	LL_FOREACH(g_miner_list_head, elt)
	{
		struct miner_pool_data *miner = &elt->miner_data;

		prev_diff[index] = countpay(miner, confirmation_index, &diff[index]);
		data->sum += diff[index];
		data->prev_sum += prev_diff[index];

		if(data->reward_index < 0 && !memcmp(nonce, miner->id.data, sizeof(xdag_hashlow_t))) {
			data->reward_index = index;
		}
		++index;
	}

	/* clear nopaid shares for each connection */
	connection_list_element *conn;
	LL_FOREACH(g_connection_list_head, conn)
	{
		if(conn->connection_data.maxdiff[confirmation_index] > 0) {
			conn->connection_data.maxdiff[confirmation_index] = 0;
		}

		conn->connection_data.prev_diff = 0;
		conn->connection_data.prev_diff_count = 0;
	}
	pthread_mutex_unlock(&g_connections_mutex);

	if(data->sum > 0) {
		data->direct = data->balance * g_pool_direct;
		data->pay -= data->direct;
	}

	return data->prev_sum;
}

static void transfer_payment(struct miner_pool_data *miner, xdag_amount_t payment_sum, struct xdag_field *fields, int payments_per_block, int *field_index)
{
	if(payment_sum < 5) {   // payment less than 0.000000001 XDAG is ignored
		return;
	}

	memcpy(fields[*field_index].data, miner->id.data, sizeof(xdag_hashlow_t));
	fields[*field_index].amount = payment_sum;
	fields[0].amount += payment_sum;

	xdag_log_xfer(fields[0].data, fields[*field_index].data, payment_sum);

	if(++*field_index == payments_per_block) {
		//创建支付矿工的区块
		struct xdag_block *payment_block = xdag_create_block(fields, 1, *field_index - 1, 0, 0, 0, NULL);
		block_queue_append_new(payment_block);

		*field_index = 1;
		fields[0].amount = 0;
	}
}

static void do_payments(uint64_t *hash, int payments_per_block, struct payment_data *data, double *diff, double *prev_diff)
{
	miner_list_element *elt;
	struct xdag_field fields[12];

	memcpy(fields[0].data, hash, sizeof(xdag_hashlow_t));
	fields[0].amount = 0;
	int field_index = 1;

	int index = 0;
	pthread_mutex_lock(&g_connections_mutex);
	LL_FOREACH(g_miner_list_head, elt)
	{
		xdag_amount_t payment_sum = 0;
		struct miner_pool_data *miner = &elt->miner_data;

		if(data->prev_sum > 0) {
			payment_sum += data->pay * (prev_diff[index] / data->prev_sum);
		}

		if(data->sum > 0) {
			payment_sum += data->direct * (diff[index] / data->sum);
		}

		if(index == data->reward_index) {
			payment_sum += data->reward;
		}

		transfer_payment(miner, payment_sum, fields, payments_per_block, &field_index);
		++index;
	}
	pthread_mutex_unlock(&g_connections_mutex);

	if(g_fund_miner.state != MINER_UNKNOWN) {
		transfer_payment(&g_fund_miner, data->fund, fields, payments_per_block, &field_index);
	}

	if(field_index > 1) {
		struct xdag_block *payment_block = xdag_create_block(fields, 1, field_index - 1, 0, 0, 0, NULL);
		block_queue_append_new(payment_block);
	}
}

int pay_miners(xtime_t time)
{
	int defkey;
	struct payment_data data;
	miner_list_element *elt;

	memset(&data, 0, sizeof(struct payment_data));
	data.reward_index = -1;

	int miners_count;
	pthread_mutex_lock(&g_connections_mutex);
	LL_COUNT(g_miner_list_head, elt, miners_count);
	pthread_mutex_unlock(&g_connections_mutex);
	if(!miners_count) return -1;

	const int confirmation_index = time & (CONFIRMATIONS_COUNT - 1);
	uint64_t *hash = g_xdag_mined_hashes[confirmation_index];
	uint64_t *nonce = g_xdag_mined_nonce[confirmation_index];

	data.balance = xdag_get_balance(hash);
	if(!data.balance) return -2;

	data.pay = data.balance - (xdag_amount_t)(g_pool_fee * data.balance);
	if(!data.pay) return -3;

	int key = xdag_get_key(hash);
	if(key < 0) return -4;

	if(!xdag_wallet_default_key(&defkey)) return -5;

	const int payments_per_block = (key == defkey ? 12 : 10);

	struct xdag_block buf;
	int64_t pos = xdag_get_block_pos(hash, &time, &buf);
	//如果pos==-2l说明是附加块
	if (pos == -2l) {
		;
	} else if (pos < 0) {
		return -6;
	} else {
		struct xdag_block *block = xdag_storage_load(hash, time, pos, &buf);
		if(!block) return -7;
	}

	double *diff = malloc(2 * miners_count * sizeof(double));
	if(!diff) return -8;

	double *prev_diff = diff + miners_count;
	double prev_sum = precalculate_payments(hash, confirmation_index, &data, diff, prev_diff, nonce);
	if(prev_sum <= DBL_EPSILON) {
		free(diff);
		return -9;
	}

	do_payments(hash, payments_per_block, &data, diff, prev_diff);

	free(diff);

	return 0;
}

void remove_inactive_miners(void)
{
	miner_list_element *elt, *eltmp;
	char address[33] = {0};

	pthread_mutex_lock(&g_connections_mutex);
	LL_FOREACH_SAFE(g_miner_list_head, elt, eltmp)
	{
		if(elt->miner_data.state == MINER_ARCHIVE && miner_calculate_unpaid_shares(&elt->miner_data) == 0.0) {
			xdag_hash2address(elt->miner_data.id.data, address);

			LL_DELETE(g_miner_list_head, elt);
			clear_nonces_hashtable(&elt->miner_data);
			free(elt);

			xdag_info("Pool: miner %s is removed from miners list", address);
		}
	}
	pthread_mutex_unlock(&g_connections_mutex);
}

static const char* miner_state_to_string(int miner_state)
{
	switch(miner_state) {
		case MINER_ACTIVE:
			return "active ";
		case MINER_ARCHIVE:
			return "archive";
		case MINER_SERVICE:
			return "fee    ";
		default:
			return "unknown";
	}
}

static const char* connection_state_to_string(int connection_state)
{
	switch(connection_state) {
		case ACTIVE_CONNECTION:
			return "active ";
		default:
			return "unknown";
	}
}

static int print_miner(FILE *out, int index, struct miner_pool_data *miner, int print_connections)
{
	char ip_port_str[32] = {0}, in_out_str[64] = {0};
	char address_buf[33] = {0};
	xdag_hash2address(miner->id.data, address_buf);

	fprintf(out, "%3d. %s  %s  %-21s  %-16s  %-13lf  -             %Lf\n", index, address_buf,
		miner_state_to_string(miner->state), "-", "-", miner_calculate_unpaid_shares(miner), xdag_log_difficulty2hashrate(miner->mean_log_difficulty));

	if(print_connections) {
		connection_list_element *elt;
		int conn_index = 0;
		LL_FOREACH(g_connection_list_head, elt)
		{
			if(elt->connection_data.miner == miner) {
				struct connection_pool_data *conn_data = &elt->connection_data;
				int ip = conn_data->ip;
				sprintf(ip_port_str, "%u.%u.%u.%u:%u", ip & 0xff, ip >> 8 & 0xff, ip >> 16 & 0xff, ip >> 24 & 0xff, ntohs(conn_data->port));
				sprintf(in_out_str, "%llu/%llu", (unsigned long long)conn_data->nfield_in * sizeof(struct xdag_field),
					(unsigned long long)conn_data->nfield_out * sizeof(struct xdag_field));

				//TODO: fix that logic
				fprintf(out, " C%d. -                                 -        %-21s  %-16s  %-13lf  %-12s  %Lf\n", ++conn_index,
					ip_port_str, in_out_str, connection_calculate_unpaid_shares(conn_data),
					conn_data->worker_name ? conn_data->worker_name : "-", xdag_log_difficulty2hashrate(conn_data->mean_log_difficulty));
			}
		}
	}

	return miner->state == MINER_ACTIVE ? 1 : 0;
}

static int print_miners(FILE *out)
{
	pthread_mutex_lock(&g_connections_mutex);
	int count_active = print_miner(out, -1, &g_pool_miner, 1);

	miner_list_element *elt;
	int index = 0;
	LL_FOREACH(g_miner_list_head, elt)
	{
		struct miner_pool_data *miner = &elt->miner_data;
		count_active += print_miner(out, index++, miner, 1);
	}
	pthread_mutex_unlock(&g_connections_mutex);

	return count_active;
}

static void print_connection(FILE *out, int index, struct connection_pool_data *conn_data)
{
	char ip_port_str[32] = {0}, in_out_str[64] = {0};
	char address[50] = {0};
	int ip = conn_data->ip;
	sprintf(ip_port_str, "%u.%u.%u.%u:%u", ip & 0xff, ip >> 8 & 0xff, ip >> 16 & 0xff, ip >> 24 & 0xff, ntohs(conn_data->port));
	sprintf(in_out_str, "%llu/%llu", (unsigned long long)conn_data->nfield_in * sizeof(struct xdag_field),
		(unsigned long long)conn_data->nfield_out * sizeof(struct xdag_field));

	if(conn_data->miner) {
		xdag_hash2address(conn_data->miner->id.data, address);
	} else {
		strncpy(address, "-                               ", 49);
	}

	//TODO: fix that logic
	fprintf(out, "%3d. %s  %s  %-21s  %-16s  %-13lf  %-12s  %Lf\n", index, address,
		connection_state_to_string(conn_data->state), ip_port_str, in_out_str, connection_calculate_unpaid_shares(conn_data),
		conn_data->worker_name ? conn_data->worker_name : "-", xdag_log_difficulty2hashrate(conn_data->mean_log_difficulty));
}

static int print_connections(FILE *out)
{
	connection_list_element *elt;
	int index = 0;
	pthread_mutex_lock(&g_connections_mutex);
	LL_FOREACH(g_connection_list_head, elt)
	{
		struct connection_pool_data *conn_data = &elt->connection_data;
		print_connection(out, index++, conn_data);
	}
	pthread_mutex_unlock(&g_connections_mutex);

	return index;
}

/* output to the file a list of miners */
int xdag_print_miners(FILE *out, int printOnlyConnections)
{
	fprintf(out, "List of miners:\n"
		" NN  Address for payment to            Status   IP and port            in/out bytes      unpaid shares  worker name   hashrate MH/s\n"
		"-----------------------------------------------------------------------------------------------------------------------------------\n");

	const int count_active = printOnlyConnections ? print_connections(out) : print_miners(out);

	fprintf(out,
		"-----------------------------------------------------------------------------------------------------------------------------------\n"
		"Total %d active %s.\n", count_active, printOnlyConnections ? "connections" : "miners");

	return count_active;
}

// disconnect connections by condition
// condition type: all, ip or address
// value: address of ip depending on type
void disconnect_connections(enum disconnect_type type, char *value)
{
	connection_list_element *elt;
	xdag_hash_t hash;
	uint32_t ip = 0;

	if(type == DISCONNECT_BY_ADRESS) {
		xdag_address2hash(value, hash);
	} else if(type == DISCONNECT_BY_IP) {
		ip = inet_addr(value);
	}

	pthread_mutex_lock(&g_connections_mutex);
	LL_FOREACH(g_connection_list_head, elt)
	{
		if(type == DISCONNECT_ALL) {
			elt->connection_data.disconnection_reason = "disconnected manually";
			atomic_store_explicit_int(&elt->connection_data.deleted, 1, memory_order_release);
		} else if(type == DISCONNECT_BY_ADRESS) {
			if(memcmp(elt->connection_data.data, hash, sizeof(xdag_hashlow_t)) == 0) {
				elt->connection_data.disconnection_reason = "disconnected manually";
				atomic_store_explicit_int(&elt->connection_data.deleted, 1, memory_order_release);
			}
		} else if(type == DISCONNECT_BY_IP) {
			if(elt->connection_data.ip == ip) {
				elt->connection_data.disconnection_reason = "disconnected manually";
				atomic_store_explicit_int(&elt->connection_data.deleted, 1, memory_order_release);
			}
		}
	}
	pthread_mutex_unlock(&g_connections_mutex);
}

//最新的share如果已经超过5分钟还没更新 移除连接
void* pool_remove_inactive_connections(void* arg)
{
	connection_list_element *elt;

	for(;;) {
		time_t current_time = time(0);

		pthread_mutex_lock(&g_connections_mutex);
		LL_FOREACH(g_connection_list_head, elt)
		{
			if(current_time - elt->connection_data.last_share_time > 300) { //last share is received more than 5 minutes ago
				elt->connection_data.disconnection_reason = "inactive connection";
				atomic_store_explicit_int(&elt->connection_data.deleted, 1, memory_order_release);
			}
		}
		pthread_mutex_unlock(&g_connections_mutex);

		sleep(60);
	}

	return NULL;
}

/* append new generated block and new blocks received from miner to list */
//queue通过transport_header链接
void block_queue_append_new(struct xdag_block *b)
{
	if(!b) return;

	pthread_mutex_lock(&g_pool_mutex);

	if(!g_firstb) {
		g_firstb = g_lastb = b;
	} else {
		g_lastb->field[0].transport_header = (uint64_t)(uintptr_t)b;
		g_lastb = b;
	}

	pthread_mutex_unlock(&g_pool_mutex);
}

/* get the first new block in list */
struct xdag_block *block_queue_first(void)
{
	struct xdag_block *b = 0;
	pthread_mutex_lock(&g_pool_mutex);

	if(g_firstb) {
		b = g_firstb;
		g_firstb = (struct xdag_block *)(uintptr_t)b->field[0].transport_header;
		if(!g_firstb) g_lastb = 0;
	} else {
		b = 0;
	}

	pthread_mutex_unlock(&g_pool_mutex);

	return b;
}

void update_mean_log_diff(struct connection_pool_data *conn_data, struct xdag_pool_task *task, xdag_hash_t hash)
{
	const xtime_t task_time = task->task_time;

	if(conn_data->task_time < task_time) {
		if(conn_data->task_time != 0) {
			conn_data->mean_log_difficulty =
				moving_average(conn_data->mean_log_difficulty, xdag_diff2log(xdag_hash_difficulty(conn_data->last_min_hash)), conn_data->bounded_task_counter);
			if(conn_data->bounded_task_counter < NSAMPLES_MAX) {
				++conn_data->bounded_task_counter;
			}
		}
		memcpy(conn_data->last_min_hash, hash, sizeof(xdag_hash_t));
	} else if(xdag_cmphash(hash, conn_data->last_min_hash) < 0) {
		memcpy(conn_data->last_min_hash, hash, sizeof(xdag_hash_t));
	}

	if(conn_data->miner->task_time < task_time) {
		if(conn_data->miner->task_time != 0) {
			conn_data->miner->mean_log_difficulty =
				moving_average(conn_data->miner->mean_log_difficulty, xdag_diff2log(xdag_hash_difficulty(conn_data->miner->last_min_hash)), conn_data->miner->bounded_task_counter);
			if(conn_data->miner->bounded_task_counter < NSAMPLES_MAX) {
				++conn_data->miner->bounded_task_counter;
			}
		}
		memcpy(conn_data->miner->last_min_hash, hash, sizeof(xdag_hash_t));
	} else if(xdag_cmphash(hash, conn_data->miner->last_min_hash) < 0) {
		memcpy(conn_data->miner->last_min_hash, hash, sizeof(xdag_hash_t));
	}
}

static void miner_print_time_intervals(struct miner_pool_data *miner, int current_interval_index, xdag_time_t current_task_time, FILE *out)
{
	char time_buf[60] = {0};

	fprintf(out, "----------------------------------------------------------------------\n");
	fprintf(out, "current  index  start time                difficulty  reward for block\n");
	fprintf(out, "----------------------------------------------------------------------\n");

	for(int i = 0; i < CONFIRMATIONS_COUNT; ++i) {
		// check if current miner mined block for current interval
		int is_reward = memcmp(g_xdag_mined_nonce[i], miner->id.data, sizeof(xdag_hashlow_t)) == 0;

		// here we calculate time offset for interval of time
		xtime_t task_time = current_task_time << 16 | 0xffff;
		if(i < current_interval_index) {
			task_time = task_time - (2 << 15) * (current_interval_index - i);	// 2 << 15 - 64 seconds
		} else if(i > current_interval_index) {
			task_time = task_time - (2 << 15) * (current_interval_index + CONFIRMATIONS_COUNT - i);
		}
		xdag_xtime_to_string(task_time, time_buf);

		fprintf(out, "      %s  %2d     %s  %10lf         %s\n",
			i == current_interval_index ? ">" : " ", i + 1, time_buf, miner->maxdiff[i], is_reward ? "+" : " ");
	}
}

static void connection_print_time_intervals(struct connection_pool_data *conn_data, int current_interval_index, FILE *out)
{
	fprintf(out, "--------------------------\n");
	fprintf(out, "current  index  difficulty\n");
	fprintf(out, "--------------------------\n");

	for(int i = 0; i < CONFIRMATIONS_COUNT; ++i) {
		fprintf(out, "      %s  %2d    %10lf\n",
			i == current_interval_index ? ">" : " ", i + 1, conn_data->maxdiff[i]);
	}
}

static void print_connection_stats(struct connection_pool_data *conn_data, int connection_index, int current_interval_index, FILE *out)
{
	char time_buf[50] = {0};
	xdag_time_to_string(conn_data->connected_time, time_buf);
	int ip = conn_data->ip;

	fprintf(out, "\nConnection %d\n", connection_index);
	fprintf(out, "IP and port: %u.%u.%u.%u:%u\n", ip & 0xff, ip >> 8 & 0xff, ip >> 16 & 0xff, ip >> 24 & 0xff, ntohs(conn_data->port));
	fprintf(out, "Connected at: %s\n", time_buf);
	fprintf(out, "In/out data: %llu/%llu\n", (unsigned long long)conn_data->nfield_in * sizeof(struct xdag_field),
		(unsigned long long)conn_data->nfield_out * sizeof(struct xdag_field));
	if(conn_data->worker_name) {
		fprintf(out, "Worker name: %s\n", conn_data->worker_name);
	}
	fprintf(out, "Unpaid shares rate: %lf\n", connection_calculate_unpaid_shares(conn_data));
	fprintf(out, "Approximate hashrate: %Lf\n", xdag_log_difficulty2hashrate(conn_data->mean_log_difficulty));
	if(conn_data->prev_diff_count > 0) {
		fprintf(out, "Outdated shares (indirect contribution):\n");
		fprintf(out, "Summ of difficulties: %lf\n", conn_data->prev_diff);
		fprintf(out, "Count of shares: %d\n", conn_data->prev_diff_count);
	}

	fprintf(out, "Time intervals:\n");
	connection_print_time_intervals(conn_data, current_interval_index, out);

	double total_difficulty_summ;
	int total_difficulty_count;
	calculate_diff_summ(conn_data, total_difficulty_summ, total_difficulty_count);
	fprintf(out, "Total summ of difficulties: %lf\n", total_difficulty_summ);
	fprintf(out, "Total count of difficulties: %d\n", total_difficulty_count);
}

static void print_miner_stats(struct miner_pool_data *miner, FILE *out)
{
	char time_buf[50] = {0};
	xdag_time_to_string(miner->registered_time, time_buf);

	const uint64_t task_index = g_xdag_pool_task_index;
	struct xdag_pool_task *task = &g_xdag_pool_task[task_index & 1];
	const xtime_t current_task_time = task->task_time;
	const int current_interval_index = current_task_time & (CONFIRMATIONS_COUNT - 1);

	uint64_t *h = miner->id.data;
	fprintf(out, "Hash: %016llx%016llx%016llx%016llx\n", 
		(unsigned long long)h[3], (unsigned long long)h[2], (unsigned long long)h[1], (unsigned long long)h[0]);
	fprintf(out, "Registered at: %s\n", time_buf);
	fprintf(out, "State: %s\n", miner_state_to_string(miner->state));
	fprintf(out, "Unpaid shares rate: %lf\n", miner_calculate_unpaid_shares(miner));
	fprintf(out, "Approximate hashrate: %Lf\n", xdag_log_difficulty2hashrate(miner->mean_log_difficulty));
	if(miner->prev_diff_count > 0) {
		fprintf(out, "Outdated shares (indirect contribution):\n");
		fprintf(out, "Summ of difficulties: %lf\n", miner->prev_diff);
		fprintf(out, "Count of difficulties: %d\n", miner->prev_diff_count);
	}

	fprintf(out, "Time intervals:\n");
	miner_print_time_intervals(miner, current_interval_index, current_task_time, out);

	double total_difficulty_summ;
	int total_difficulty_count;
	calculate_diff_summ(miner, total_difficulty_summ, total_difficulty_count);
	fprintf(out, "Total summ of difficulties: %lf\n", total_difficulty_summ);
	fprintf(out, "Total count of difficulties: %d\n", total_difficulty_count);

	connection_list_element *elt;
	int index = 1;
	LL_FOREACH(g_connection_list_head, elt)
	{
		if(elt->connection_data.miner == miner) {
			struct connection_pool_data *conn_data = &elt->connection_data;
			print_connection_stats(conn_data, index++, current_interval_index, out);
		}
	}
}

// prints detailed information about specified miner
int xdag_print_miner_stats(const char* address, FILE *out)
{
	miner_list_element *elt;
	xdag_hash_t hash;
	xdag_address2hash(address, hash);

	int exists = 0;
	pthread_mutex_lock(&g_connections_mutex);
	LL_FOREACH(g_miner_list_head, elt)
	{
		if(memcmp(elt->miner_data.id.data, hash, sizeof(xdag_hashlow_t)) == 0) {
			struct miner_pool_data *miner = &elt->miner_data;
			exists = 1;
			print_miner_stats(miner, out);

			break;
		}
	}
	pthread_mutex_unlock(&g_connections_mutex);

	return exists;
}
