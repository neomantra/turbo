--- Turbo.lua C function declarations
--
-- Copyright 2013 John Abrahamsen
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
-- http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

local ffi = require "ffi"
local __WINDOWS = ffi.abi("win")
local __UNIX = not __WINDOWS
local __LINUX = not __UNIX
local __ABI32 = ffi.abi("32bit")
local __ABI64 = ffi.abi("64bit")

--- ******* stdlib UNIX *******
if __UNIX then
    ffi.cdef [[
        typedef int32_t pid_t;

        void *malloc(size_t sz);
        void *realloc(void*ptr, size_t size);
        void free(void *ptr);
        int sprintf(char *str, const char *format, ...);
        int printf(const char *format, ...);
        void *memmove(void *destination, const void *source, size_t num);
        int memcmp(const void *ptr1, const void *ptr2, size_t num);
        void *memchr(void *ptr, int value, size_t num);
        int strncasecmp(const char *s1, const char *s2, size_t n);
        int snprintf(char *s, size_t n, const char *format, ...);
        pid_t fork();
        pid_t wait(int *status);
        pid_t waitpid(pid_t pid, int *status, int options);
        pid_t getpid();
        int execvp(const char *path, char *const argv[]);
    ]]
end

--- ******* Socket UNIX *******
if __UNIX then
    ffi.cdef([[
        typedef int socklen_t;
        struct sockaddr{
            unsigned short sa_family;
            char sa_data[14];
        };
        struct sockaddr_storage{
            unsigned short int ss_family;
            unsigned long int __ss_align;
            char __ss_padding[128 - (2 *sizeof(unsigned long int))];
        };
        struct in_addr{
            unsigned long s_addr;
        };
        struct in6_addr{
            unsigned char s6_addr[16];
        };
        struct sockaddr_in{
            short sin_family;
            unsigned short sin_port;
            struct in_addr sin_addr;
            char sin_zero[8];
        } __attribute__ ((__packed__));
        struct sockaddr_in6{
            unsigned short sin6_family;
            unsigned short sin6_port;
            unsigned int sin6_flowinfo;
            struct in6_addr sin6_addr;
            unsigned int sin6_scope_id;
        };

        char *strerror(int errnum);
        int socket(int domain, int type, int protocol);
        int bind(int fd, const struct sockaddr *addr, socklen_t len);
        int listen(int fd, int backlog);
        int dup(int oldfd);
        int close(int fd);
        int connect(int fd, const struct sockaddr *addr, socklen_t len);
        int setsockopt(
            int fd, 
            int level,
            int optname,
            const void *optval,
            socklen_t optlen);
        int getsockopt(
            int fd,
            int level,
            int optname,
            void *optval,
            socklen_t *optlen);
        int accept(int fd, struct sockaddr *addr, socklen_t *addr_len);
        unsigned int ntohl(unsigned int netlong);
        unsigned int htonl(unsigned int hostlong);
        unsigned short ntohs(unsigned int netshort);
        unsigned short htons(unsigned int hostshort);
        int inet_pton(int af, const char *cp, void *buf);
        const char *inet_ntop(
            int af,
            const void *cp,
            char *buf,
            socklen_t len);
        char *inet_ntoa(struct in_addr in);
        int fcntl(int fd, int cmd, int opt);
    ]])

    if __ABI32 then
        ffi.cdef [[
            int send(int fd, const void *buf, size_t n, int flags);
            int recv(int fd, void *buf, size_t n, int flags);
        ]]
    elseif __ABI64 then
        ffi.cdef [[
            int64_t send(int fd, const void *buf, size_t n, int flags);
            int64_t recv(int fd, void *buf, size_t n, int flags);
        ]]
    end
end

--- ******* epoll.h Linux *******
if __LINUX then
    ffi.cdef[[
        typedef union epoll_data{
            void *ptr;
            int fd;
            unsigned int u32;
            uint64_t u64;
        } epoll_data_t;
    ]]
    if __ABI32 then
        ffi.cdef[[
            struct epoll_event{
                unsigned int events;
                epoll_data_t data;
            };
        ]]
    elseif __ABI64 then
        ffi.cdef[[
            struct epoll_event{
                unsigned int events;
                epoll_data_t data;
            } __attribute__ ((__packed__));
        ]]
        end
    ffi.cdef[[
        typedef struct epoll_event epoll_event;

        int epoll_create(int size);
        int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
        int epoll_wait(
            int epfd,
            struct epoll_event *events,
            int maxevents,
            int timeout);
    ]]
end


if _G.TURBO_AXTLS then
    ffi.cdef[[
        typedef void SSL_CTX;
        typedef void SSL;
        typedef struct{
            unsigned int state[4];
            unsigned int count[2];
            unsigned char buffer[64];
        } MD5_CTX;
        typedef struct{
            unsigned int Intermediate_Hash[20/4];
            unsigned int Length_Low;
            unsigned int Length_High;
            unsigned int Message_Block_Index;
            unsigned char Message_Block[64];
        } SHA1_CTX;

        SSL_CTX *ssl_ctx_new(unsigned int options, int num_sessions);
        void ssl_ctx_free(SSL_CTX *ssl_ctx);
        SSL *ssl_server_new(SSL_CTX *ssl_ctx, int client_fd);
        SSL *ssl_client_new(
            SSL_CTX *ssl_ctx, 
            int client_fd,
            const unsigned char *session_id, 
            unsigned char sess_id_size);
        void ssl_free(SSL *ssl);
        int ssl_read(SSL *ssl, unsigned char **in_data);
        int ssl_write(SSL *ssl, const unsigned char *out_data, int out_len);
        int ssl_handshake_status(const SSL *ssl);
        void ssl_display_error(int error_code);
        const char *ssl_get_cert_dn(const SSL *ssl, int component);
        const char *ssl_get_cert_subject_alt_dnsname(
            const SSL *ssl,
            int dnsindex);
        int ssl_obj_load(
            SSL_CTX *ssl_ctx,
            int obj_type,
            const char *filename,
            const char *password);
        void SHA1_Init(SHA1_CTX *ctx);
        void SHA1_Update(SHA1_CTX *ctx, const unsigned char *msg, int len);
        void SHA1_Final(unsigned char *digest, SHA1_CTX *ctx);
        void MD5_Init(MD5_CTX *ctx);
        void MD5_Update(MD5_CTX *ctx, const unsigned char *msg, int len);
        void MD5_Final(unsigned char *digest, MD5_CTX *ctx);
        void hmac_sha1(
            const unsigned char *msg, 
            int length, 
            const unsigned char *key,
            int key_len, 
            unsigned char *digest);
    ]]

elseif _G.TURBO_SSL then
    --- *******OpenSSL *******
    -- Note: Typedef SSL structs to void as we never access their members and 
    -- they are massive in ifdef's etc and are best left as blackboxes!
    ffi.cdef[[
        typedef void SSL_METHOD;
        typedef void SSL_CTX;
        typedef void SSL;
        typedef void X509;
        typedef void X509_NAME;
        typedef void X509_NAME_ENTRY;
        typedef void ASN1_STRING;
        typedef unsigned int SHA_LONG;
        typedef void EVP_MD;
        typedef struct SHAstate_st{
            SHA_LONG h0,h1,h2,h3,h4;
            SHA_LONG Nl,Nh;
            SHA_LONG data[16];
            unsigned int num;
        } SHA_CTX;

        const SSL_METHOD *SSLv3_server_method(void);
        const SSL_METHOD *SSLv3_client_method(void);
        const SSL_METHOD *SSLv23_method(void);
        const SSL_METHOD *SSLv23_server_method(void);
        const SSL_METHOD *SSLv23_client_method(void);
        const SSL_METHOD *TLSv1_method(void);
        const SSL_METHOD *TLSv1_server_method(void);
        const SSL_METHOD *TLSv1_client_method(void);
        const SSL_METHOD *TLSv1_1_method(void);
        const SSL_METHOD *TLSv1_1_server_method(void);
        const SSL_METHOD *TLSv1_1_client_method(void);
        const SSL_METHOD *TLSv1_2_method(void);
        const SSL_METHOD *TLSv1_2_server_method(void);
        const SSL_METHOD *TLSv1_2_client_method(void);
        void OPENSSL_add_all_algorithms_noconf(void);
        void SSL_load_error_strings(void);
        void ERR_free_strings(void);
        int SSL_library_init(void);
        void EVP_cleanup(void);
        SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);
        void SSL_CTX_free(SSL_CTX *);
        int SSL_CTX_use_PrivateKey_file(
            SSL_CTX *ctx,
            const char *file,
            int type);
        int SSL_CTX_use_certificate_file(
            SSL_CTX *ctx,
            const char *file,
            int type);
        int SSL_CTX_load_verify_locations(
            SSL_CTX *ctx,
            const char *CAfile,
            const char *CApath);
        int SSL_CTX_check_private_key(const SSL_CTX *ctx);
        SSL *SSL_new(SSL_CTX *ctx);
        void SSL_set_connect_state(SSL *s);
        void SSL_set_accept_state(SSL *s);
        int SSL_do_handshake(SSL *s);
        int SSL_set_fd(SSL *s, int fd);
        int SSL_accept(SSL *ssl);
        void SSL_free(SSL *ssl);
        int SSL_accept(SSL *ssl);
        int SSL_connect(SSL *ssl);
        int SSL_read(SSL *ssl,void *buf,int num);
        int SSL_peek(SSL *ssl,void *buf,int num);
        int SSL_write(SSL *ssl,const void *buf,int num);
        void SSL_set_verify(
            SSL *s,
            int mode,
            int (*callback)(int ok,void *ctx));
        int SSL_set_cipher_list(SSL *s, const char *str);
        int SSL_get_error(const SSL *s, int ret_code);
        void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth);
        void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, void *);
        X509 *SSL_get_peer_certificate(const SSL *s);
        long SSL_get_verify_result(const SSL *ssl);
        const char *X509_verify_cert_error_string(long n);
        unsigned long ERR_get_error(void);
        unsigned long ERR_peek_error(void);
        unsigned long ERR_peek_error_line(const char **file,int *line);
        unsigned long ERR_peek_error_line_data(
            const char **file,
            int *line,
            const char **data,int *flags);
        unsigned long ERR_peek_last_error(void);
        unsigned long ERR_peek_last_error_line(const char **file,int *line);
        unsigned long ERR_peek_last_error_line_data(
            const char **file,
            int *line,
            const char **data,int *flags);
        void ERR_clear_error(void );
        char *ERR_error_string(unsigned long e,char *buf);
        void ERR_error_string_n(unsigned long e, char *buf, size_t len);
        const char *ERR_lib_error_string(unsigned long e);
        const char *ERR_func_error_string(unsigned long e);
        const char *ERR_reason_error_string(unsigned long e);
        const EVP_MD *EVP_sha1(void);
        unsigned char *SHA1(
            const unsigned char *d,
            size_t n,
            unsigned char *md);
        int32_t SHA1_Init(SHA_CTX *c);
        int32_t SHA1_Update(SHA_CTX *c, const void *data, size_t len);
        int32_t SHA1_Final(unsigned char *md, SHA_CTX *c);
        unsigned char *MD5(
            const unsigned char *d,
            size_t n,
            unsigned char *md);
        unsigned char *HMAC(
            const EVP_MD *evp_md,
            const void *key,
            int key_len,
            const unsigned char *d,
            int n,
            unsigned char *md,
            unsigned int *md_len);
        int32_t validate_hostname(const char *hostname, const SSL *server);
    ]]
end

--- *******Signals *******
ffi.cdef[[
    typedef void(*sighandler_t) (int32_t);
    sighandler_t signal (int32_t signum, sighandler_t handler);
    int kill(pid_t pid, int sig);
]]

ffi.cdef(string.format([[
    typedef struct {
        unsigned long int __val[%d];
    } __sigset_t;
    typedef __sigset_t sigset_t;
    struct signalfd_siginfo{
        uint32_t ssi_signo;
        int32_t ssi_errno;
        int32_t ssi_code;
        uint32_t ssi_pid;
        uint32_t ssi_uid;
        int32_t ssi_fd;
        uint32_t ssi_tid;
        uint32_t ssi_band;
        uint32_t ssi_overrun;
        uint32_t ssi_trapno;
        int32_t ssi_status;
        int32_t ssi_int;
        uint64_t ssi_ptr;
        uint64_t ssi_utime;
        uint64_t ssi_stime;
        uint64_t ssi_addr;
        uint8_t __pad[48];
    };

    int sigemptyset(sigset_t *set);
    int sigfillset(sigset_t *set);
    int sigaddset(sigset_t *set, int signum);
    int sigdelset(sigset_t *set, int signum);
    int sigismember(const sigset_t *set, int signum);
    int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
    int signalfd(int fd, const sigset_t *mask, int flags);
    ]], (1024 / (8 *ffi.sizeof("unsigned long")))))

--- ******* Time *******
ffi.cdef([[
    typedef long time_t;
    typedef long suseconds_t;
    struct timeval{
        time_t tv_sec;
        suseconds_t tv_usec;
    };
    struct timezone{
        int tz_minuteswest;
        int tz_dsttime;
    };
    struct tm
    {
        int tm_sec;
        int tm_min;
        int tm_hour;
        int tm_mday;
        int tm_mon;
        int tm_year;
        int tm_wday;
        int tm_yday;
        int tm_isdst;
        long int __tm_gmtoff;
        const char *__tm_zone;
    };
    typedef struct timezone *timezone_ptr_t;

    size_t strftime(
        char *ptr,
        size_t maxsize,
        const char *format,
        const struct tm *timeptr);
    struct tm *localtime(const time_t *timer);
    time_t time(time_t *timer);
    // Stream defined as void to avoid pulling in FILE.
    int fputs(const char *str, void *stream);
    int snprintf(char *s, size_t n, const char *format, ...);
    int sprintf ( char *str, const char *format, ... );
    struct tm *gmtime(const time_t *timer);
    int gettimeofday(struct timeval *tv, timezone_ptr_t tz);
]])

--- ******* RealTime (for Monotonic time) *******
ffi.cdef[[
    struct timespec
    {
        time_t tv_sec;
        long tv_nsec;
    };
    typedef unsigned int clockid_t;
    enum clock_ids{
        CLOCK_REALTIME,
        CLOCK_MONOTONIC
    };

    int clock_gettime(clockid_t clk_id, struct timespec *tp);
]]

--- ******* Resolv *******
ffi.cdef[[
    struct hostent{
        char *h_name;
        char **h_aliases;
        int h_addrtype;
        int h_length;
        char **h_addr_list;
    };
    struct addrinfo{
        int ai_flags;
        int ai_family;
        int ai_socktype;
        int ai_protocol;
        socklen_t ai_addrlen;
        struct sockaddr *ai_addr;
        char *ai_canonname;
        struct addrinfo *ai_next;
    };

    struct hostent *gethostbyname(const char *name);
    int getaddrinfo(
        const char *nodename,
        const char *servname,
        const struct addrinfo *hints,
        struct addrinfo **res);
    void freeaddrinfo(struct addrinfo *ai);
    const char *gai_strerror(int ecode);
]]

--- *******HTTP parser and libtffi *******
ffi.cdef[[
    enum http_parser_url_fields{ 
        UF_SCHEMA = 0,
        UF_HOST = 1,
        UF_PORT = 2,
        UF_PATH = 3,
        UF_QUERY = 4,
        UF_FRAGMENT = 5,
        UF_USERINFO = 6,
        UF_MAX = 7
    };

    struct http_parser {
    /**PRIVATE **/
    unsigned char type : 2;     /*enum http_parser_type */
    unsigned char flags : 6;    /*F_*values from 'flags' enum; semi-public */
    unsigned char state;        /*enum state from http_parser.c */
    unsigned char header_state; /*enum header_state from http_parser.c */
    unsigned char index;        /*index into current matcher */

    uint32_t nread;          /*# bytes read in various scenarios */
    uint64_t content_length; /*# bytes in body (0 if no Content-Length header) */

    /**READ-ONLY **/
    unsigned short http_major;
    unsigned short http_minor;
    unsigned short status_code; /*responses only */
    unsigned char method;       /*requests only */
    unsigned char http_errno : 7;

    /*1 = Upgrade header was present and the parser has exited because of that.
     *0 = No upgrade header present.
     *Should be checked when http_parser_execute() returns in addition to
     *error checking.
     */
    unsigned char upgrade : 1;

    /**PUBLIC **/
    void *data; /*A pointer to get hook to the "connection" or "socket" object */
    };

    struct http_parser_url {
      uint16_t field_set;           /*Bitmask of (1 << UF_*) values */
      uint16_t port;                /*Converted UF_PORT string */

      struct {
        uint16_t off;               /*Offset into buffer in which field starts */
        uint16_t len;               /*Length of run in buffer */
      } field_data[7];
    };

    struct turbo_key_value_field{
        /*Size of strings.  */
        size_t key_sz;
        size_t value_sz;
        /*These are offsets for passed in char ptr. */
        const char *key;       ///< Header key.
        const char *value;     ///< Value corresponding to key.
    };

    /**Used internally  */
    enum header_state{
        NOTHING,
        FIELD,
        VALUE
    };

    /**Wrapper struct for http_parser.c to avoid using callback approach.   */
    struct turbo_parser_wrapper{
        int32_t url_rc;
        size_t parsed_sz;
        bool headers_complete;
        enum header_state _state; ///< Used internally

        const char *url_str; ///< Offset for passed in char ptr
        size_t url_sz;
        size_t hkv_sz;
        size_t hkv_mem;
        struct turbo_key_value_field **hkv;
        struct http_parser parser;
        struct http_parser_url url;
    };

    struct turbo_parser_wrapper *turbo_parser_wrapper_init(
            const char*data,
            size_t len,
            int32_t type);

    void turbo_parser_wrapper_exit(struct turbo_parser_wrapper *src);
    bool turbo_parser_check(struct turbo_parser_wrapper *s);
    int32_t http_parser_parse_url(const char *buf, size_t buflen, int32_t is_connect, struct http_parser_url *u);
     bool url_field_is_set(const struct http_parser_url *url, enum http_parser_url_fields prop);
     char *url_field(const char *url_str, const struct http_parser_url *url, enum http_parser_url_fields prop);
    const char *http_errno_name(int32_t err);
    const char *http_errno_description(int32_t err);
    char*turbo_websocket_mask(const char*mask32, const char*in, size_t sz);
    uint64_t turbo_bswap_u64(uint64_t swap);
]]


--- *******inotify *******
ffi.cdef [[
struct inotify_event
{
    int wd;
    uint32_t mask;
    uint32_t cookie;
    uint32_t len;
    char name [];
};

 int inotify_init (void) __attribute__ ((__nothrow__ , __leaf__));
 int inotify_add_watch (int __fd, const char *__name, uint32_t __mask)
    __attribute__ ((__nothrow__ , __leaf__));
 int inotify_rm_watch (int __fd, int __wd)
    __attribute__ ((__nothrow__ , __leaf__));
]]


--- *******file system *******
ffi.cdef [[
typedef long int __ssize_t;
typedef __ssize_t ssize_t;
 ssize_t read(int __fd, void *__buf, size_t __nbytes) ;
int syscall(int number, ...);
void *mmap(void *addr, size_t length, int prot, int flags, int fd, long offset);
int munmap(void *addr, size_t length);
int open(const char *pathname, int flags);
int close(int fd);

int fstat(int fd, struct stat *buf);
]]

-- stat structure is architecture dependent in Linux
if ffi.arch == "x86" then
    ffi.cdef[[
      struct stat {
        unsigned long  st_dev;
        unsigned long  st_ino;
        unsigned short st_mode;
        unsigned short st_nlink;
        unsigned short st_uid;
        unsigned short st_gid;
        unsigned long  st_rdev;
        unsigned long  st_size;
        unsigned long  st_blksize;
        unsigned long  st_blocks;
        unsigned long  st_atime;
        unsigned long  st_atime_nsec;
        unsigned long  st_mtime;
        unsigned long  st_mtime_nsec;
        unsigned long  st_ctime;
        unsigned long  st_ctime_nsec;
        unsigned long  __unused4;
        unsigned long  __unused5;
      };
    ]]
elseif ffi.arch =="x64" then
    ffi.cdef [[
      struct stat {
        unsigned long   st_dev;
        unsigned long   st_ino;
        unsigned long   st_nlink;
        unsigned int    st_mode;
        unsigned int    st_uid;
        unsigned int    st_gid;
        unsigned int    __pad0;
        unsigned long   st_rdev;
        long            st_size;
        long            st_blksize;
        long            st_blocks;
        unsigned long   st_atime;
        unsigned long   st_atime_nsec;
        unsigned long   st_mtime;
        unsigned long   st_mtime_nsec;
        unsigned long   st_ctime;
        unsigned long   st_ctime_nsec;
        long            __unused[3];
      };
    ]]
elseif ffi.arch == "ppc" then
    ffi.cdef[[
      struct stat {
        uint32_t  st_dev;
        uint32_t  st_ino;
        uint32_t st_mode;
        uint32_t st_nlink;
        uint32_t st_uid;
        uint32_t st_gid;
        uint32_t st_rdev;
        uint32_t st_size;
        uint32_t st_blksize;
        uint32_t  st_blocks;
        uint32_t  st_atime;
        uint32_t  st_atime_nsec;
        uint32_t  st_mtime;
        uint32_t  st_mtime_nsec;
        uint32_t  st_ctime;
        uint32_t  st_ctime_nsec;
        uint32_t  __unused4;
        uint32_t  __unused5;
      };
    ]]
end


--- *******glob *******
ffi.cdef[[
typedef struct {
    long unsigned int gl_pathc;
    char **gl_pathv;
    long unsigned int gl_offs;
    int gl_flags;
    void (*gl_closedir)(void *);
    void *(*gl_readdir)(void *);
    void *(*gl_opendir)(const char *);
    int (*gl_lstat)(const char *restrict, void *restrict);
    int (*gl_stat)(const char *restrict, void *restrict);
} glob_t;
int glob(const char *pattern, int flag, int (*)(const char *, int), glob_t *pglob);
void globfree(glob_t *pglob);
]]

--- ***Windows *******

if __WINDOWS then
  ffi.cdef[[
    typedef void*UINT_PTR;
    typedef UINT_PTR SOCKET;
    typedef struct fd_set {
        unsigned int fd_count;
        SOCKET fd_array[1024];
    } fd_set;

    int select(
      int nfds,
      fd_set *readfds,
      fd_set *writefds,
      fd_set *exceptfds,
      const struct timeval *timeout
    );

    int send(
      SOCKET s,
      const char *buf,
      int len,
      int flags
    );

    int recv(
      SOCKET s,
      char *buf,
      int len,
      int flags
    );
  ]]
end
