#include <err.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <tee_client_api.h>
#include <ra_demo_ta.h>

#define KEY_MAX 512
#define EVIDENCE_MAX 1024
static void write_all(int fd, const void *buf, size_t n) {
 const uint8_t *p=buf; while(n) { ssize_t k=write(fd,p,n); if(k<0&&errno==EINTR)continue; if(k<=0)err(1,"socket write"); p+=k;n-=k; }
}
static void read_all(int fd, void *buf, size_t n) {
 uint8_t *p=buf; while(n) { ssize_t k=read(fd,p,n); if(k<0&&errno==EINTR)continue; if(k<=0)errx(1,"verifier disconnected"); p+=k;n-=k; }
}
static int connect_host(const char *host, const char *port) {
 struct addrinfo hints={0}, *res, *p; int fd=-1; hints.ai_socktype=SOCK_STREAM; hints.ai_family=AF_UNSPEC;
 if(getaddrinfo(host,port,&hints,&res)) errx(1,"cannot resolve host %s",host);
 for(p=res;p;p=p->ai_next){ fd=socket(p->ai_family,p->ai_socktype,p->ai_protocol); if(fd>=0&&connect(fd,p->ai_addr,p->ai_addrlen)==0)break; if(fd>=0)close(fd);fd=-1; }
 freeaddrinfo(res); if(fd<0)err(1,"connect to verifier"); return fd;
}
static void get_pubkey(uint8_t *exp, size_t *elen, uint8_t *mod, size_t *mlen) {
 TEEC_Context c; TEEC_Session s; TEEC_Operation op={0}; TEEC_UUID uuid=RA_DEMO_PTA_ATTESTATION_UUID; TEEC_Result r; uint32_t origin;
 if((r=TEEC_InitializeContext(NULL,&c))!=TEEC_SUCCESS)errx(1,"InitializeContext: 0x%x",r);
 if((r=TEEC_OpenSession(&c,&s,&uuid,TEEC_LOGIN_PUBLIC,NULL,NULL,&origin))!=TEEC_SUCCESS)errx(1,"OpenSession PTA: 0x%x origin 0x%x",r,origin);
 op.paramTypes=TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,TEEC_MEMREF_TEMP_OUTPUT,TEEC_VALUE_OUTPUT,TEEC_NONE);
 op.params[0].tmpref.buffer=exp;op.params[0].tmpref.size=KEY_MAX;op.params[1].tmpref.buffer=mod;op.params[1].tmpref.size=KEY_MAX;
 if((r=TEEC_InvokeCommand(&s,RA_DEMO_PTA_ATTESTATION_GET_PUBKEY,&op,&origin))!=TEEC_SUCCESS)errx(1,"GET_PUBKEY: 0x%x origin 0x%x",r,origin);
 *elen=op.params[0].tmpref.size;*mlen=op.params[1].tmpref.size;TEEC_CloseSession(&s);TEEC_FinalizeContext(&c);
}
static size_t get_evidence(const char *challenge, uint8_t *evidence) {
 TEEC_Context c; TEEC_Session s; TEEC_Operation op={0}; TEEC_UUID uuid=TA_RA_DEMO_UUID; TEEC_Result r; uint32_t origin;
 if((r=TEEC_InitializeContext(NULL,&c))!=TEEC_SUCCESS)errx(1,"InitializeContext: 0x%x",r);
 if((r=TEEC_OpenSession(&c,&s,&uuid,TEEC_LOGIN_PUBLIC,NULL,NULL,&origin))!=TEEC_SUCCESS)errx(1,"OpenSession demo TA: 0x%x origin 0x%x",r,origin);
 op.paramTypes=TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_OUTPUT,TEEC_NONE,TEEC_NONE);
 op.params[0].tmpref.buffer=(void *)challenge;op.params[0].tmpref.size=strlen(challenge);op.params[1].tmpref.buffer=evidence;op.params[1].tmpref.size=EVIDENCE_MAX;
 if((r=TEEC_InvokeCommand(&s,TA_RA_CMD_GET_EVIDENCE,&op,&origin))!=TEEC_SUCCESS)errx(1,"GET_EVIDENCE: 0x%x origin 0x%x",r,origin);
 size_t n=op.params[1].tmpref.size;TEEC_CloseSession(&s);TEEC_FinalizeContext(&c);return n;
}
static void run_client(const char *host,const char *port) {
 int fd=connect_host(host,port); fprintf(stderr,"Connected to verifier %s:%s; leave this running and use the verifier prompt.\n",host,port);
 for(;;){ uint8_t head[66],exp[KEY_MAX],mod[KEY_MAX],ev[EVIDENCE_MAX];size_t elen,mlen,evlen;uint16_t a,b;uint32_t d;
  read_all(fd,head,65); /* 1 command byte + 64 challenge hex chars */ if((head[0]!='E'&&head[0]!='A'))errx(1,"invalid verifier command");head[65]='\0';
  for(int i=1;i<65;i++)if(!((head[i]>='0'&&head[i]<='9')||(head[i]>='a'&&head[i]<='f')))errx(1,"invalid challenge");
  get_pubkey(exp,&elen,mod,&mlen);evlen=get_evidence((char *)&head[1],ev);
  a=htons((uint16_t)elen);b=htons((uint16_t)mlen);d=htonl((uint32_t)evlen);write_all(fd,&a,2);write_all(fd,&b,2);write_all(fd,&d,4);write_all(fd,exp,elen);write_all(fd,mod,mlen);write_all(fd,ev,evlen);
  fprintf(stderr,"Sent %s response for verifier challenge.\n",head[0]=='E'?"enrollment":"attestation");
 }
}
static void usage(const char *p){fprintf(stderr,"Usage: %s connect <host> [port]\n       %s pubkey [outdir]  (legacy file export)\n       %s attest <nonce> [outdir] (legacy offline mode)\n",p,p,p);}
/* Retain the legacy offline commands for compatibility. */
static void save_file(const char *p,const void *b,size_t n){FILE*f=fopen(p,"wb");if(!f)err(1,"fopen %s",p);if(fwrite(b,1,n,f)!=n)err(1,"fwrite %s",p);fclose(f);}
static void legacy_pubkey(const char *dir){uint8_t e[KEY_MAX],m[KEY_MAX];size_t el,ml;char p[512];get_pubkey(e,&el,m,&ml);snprintf(p,sizeof(p),"%s/pubkey_exp.bin",dir);save_file(p,e,el);snprintf(p,sizeof(p),"%s/pubkey_mod.bin",dir);save_file(p,m,ml);}
static void legacy_attest(const char *nonce,const char *dir){uint8_t e[EVIDENCE_MAX];size_t n=get_evidence(nonce,e);char p[512];snprintf(p,sizeof(p),"%s/evidence.bin",dir);save_file(p,e,n);snprintf(p,sizeof(p),"%s/nonce.bin",dir);save_file(p,nonce,strlen(nonce));}
int main(int argc,char **argv){const char *dir=".";if(argc>=3&&!strcmp(argv[1],"connect")){run_client(argv[2],argc>=4?argv[3]:"5000");return 0;}if(argc>=2&&!strcmp(argv[1],"pubkey")){if(argc>=3)dir=argv[2];legacy_pubkey(dir);return 0;}if(argc>=3&&!strcmp(argv[1],"attest")){if(argc>=4)dir=argv[3];legacy_attest(argv[2],dir);return 0;}usage(argv[0]);return 1;}
