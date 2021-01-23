
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;

struct ngx_listening_s {
    ngx_socket_t        fd;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;    /* size of sockaddr */
    size_t              addr_text_max_len;
    ngx_str_t           addr_text;

    int                 type;

    int                 backlog;
    int                 rcvbuf;
    int                 sndbuf;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    /* handler of accepted connection */
    ngx_connection_handler_pt   handler;

    void               *servers;  /* array of ngx_http_in_addr_t, for example */

    ngx_log_t           log;
    ngx_log_t          *logp;

    size_t              pool_size;
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
    ngx_msec_t          post_accept_timeout;

    ngx_listening_t    *previous;
    ngx_connection_t   *connection;

    ngx_rbtree_t        rbtree;
    ngx_rbtree_node_t   sentinel;

    ngx_uint_t          worker;

    unsigned            open:1;
    unsigned            remain:1;
    unsigned            ignore:1;

    unsigned            bound:1;       /* already bound */
    unsigned            inherited:1;   /* inherited from previous process */
    unsigned            nonblocking_accept:1;
    unsigned            listen:1;
    unsigned            nonblocking:1;
    unsigned            shared:1;    /* shared between threads or processes */
    unsigned            addr_ntop:1;
    unsigned            wildcard:1;

#if (NGX_HAVE_INET6)
    unsigned            ipv6only:1;
#endif
    unsigned            reuseport:1;
    unsigned            add_reuseport:1;
    unsigned            keepalive:2;

    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char               *accept_filter;
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    int                 fastopen;
#endif

};


typedef enum {
    NGX_ERROR_ALERT = 0,
    NGX_ERROR_ERR,
    NGX_ERROR_INFO,
    NGX_ERROR_IGNORE_ECONNRESET,
    NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;


typedef enum {
    NGX_TCP_NODELAY_UNSET = 0,
    NGX_TCP_NODELAY_SET,
    NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;


typedef enum {
    NGX_TCP_NOPUSH_UNSET = 0,
    NGX_TCP_NOPUSH_SET,
    NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01
#define NGX_HTTP_V2_BUFFERED   0x02

/* TCP连接结构体 下游请求过来建立的连接*/
struct ngx_connection_s {
    /*
     * 当Nginx服务器产生新的socket时，
     * 都会创建一个ngx_connection_s 结构体，
     * 该结构体用于保存socket的属性和数据；
     */

    /*
     * 当连接未被使用时，data充当连接池中空闲连接表中的next指针；
     * 当连接被使用时，data的意义由具体Nginx模块决定；
     */
    void               *data;
     /* 设置该链接的读事件 */
    ngx_event_t        *read;
    /* 设置该连接的写事件 */
    ngx_event_t        *write;
    /* 用于设置socket的套接字描述符 */
    ngx_socket_t        fd;
    /* 接收网络字符流的方法，是一个函数指针，指向接收函数 */
    ngx_recv_pt         recv;
     /* 发送网络字符流的方法，是一个函数指针，指向发送函数 */
    ngx_send_pt         send;
     /* 以ngx_chain_t链表方式接收网络字符流的方法 */
    ngx_recv_chain_pt   recv_chain;
    /* 以ngx_chain_t链表方式发送网络字符流的方法 */
    ngx_send_chain_pt   send_chain;
    /*
     * 当前连接对应的ngx_listening_t监听对象，
     * 当前连接由ngx_listening_t成员的listening监听端口的事件建立；
     * 成员connection指向当前连接；
     */
    ngx_listening_t    *listening;
    /* 当前连接已发生的字节数 */
    off_t               sent;

    ngx_log_t          *log;
     /* 内存池 */
    ngx_pool_t         *pool;

    int                 type;
    /* 对端的socket地址sockaddr属性*/
    struct sockaddr    *sockaddr;
    socklen_t           socklen;
    /* 字符串形式的IP地址 */
    ngx_str_t           addr_text;

    ngx_proxy_protocol_t  *proxy_protocol;

#if (NGX_SSL || NGX_COMPAT)
    ngx_ssl_connection_t  *ssl;
#endif

    ngx_udp_connection_t  *udp;
    /* 本端的监听端口对应的socket的地址sockaddr属性 */
    struct sockaddr    *local_sockaddr;
    socklen_t           local_socklen;
     /* 用于接收、缓存对端发来的字符流 */
    ngx_buf_t          *buffer;
    /*
     * 表示将当前连接作为双向连接中节点元素，
     * 添加到ngx_cycle_t结构体的成员
     * reuseable_connections_queue的双向链表中；
     */
    ngx_queue_t         queue;
    /* 连接使用次数 */
    ngx_atomic_uint_t   number;
    /* 处理请求的次数 */
    ngx_uint_t          requests;

    unsigned            buffered:8;

    unsigned            log_error:3;     /* ngx_connection_log_error_e */

    unsigned            timedout:1;
    unsigned            error:1;
    unsigned            destroyed:1;

    unsigned            idle:1;
    unsigned            reusable:1;
    unsigned            close:1;
    unsigned            shared:1;

    unsigned            sendfile:1;
    unsigned            sndlowat:1;
    unsigned            tcp_nodelay:2;   /* ngx_connection_tcp_nodelay_e */
    unsigned            tcp_nopush:2;    /* ngx_connection_tcp_nopush_e */

    unsigned            need_last_buf:1;

#if (NGX_HAVE_AIO_SENDFILE || NGX_COMPAT)
    unsigned            busy_count:2;
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_thread_task_t  *sendfile_task;
#endif
};


#define ngx_set_connection_log(c, l)                                         \
                                                                             \
    c->log->file = l->file;                                                  \
    c->log->next = l->next;                                                  \
    c->log->writer = l->writer;                                              \
    c->log->wdata = l->wdata;                                                \
    if (!(c->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {                   \
        c->log->log_level = l->log_level;                                    \
    }


ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, struct sockaddr *sockaddr,
    socklen_t socklen);
ngx_int_t ngx_clone_listening(ngx_cycle_t *cycle, ngx_listening_t *ls);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
void ngx_close_idle_connections(ngx_cycle_t *cycle);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
    ngx_uint_t port);
ngx_int_t ngx_tcp_nodelay(ngx_connection_t *c);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
