/* SPDX-License-Identifier: BUSL-1.1
 * Optional Linux credential adapter. FreeRDP 2.11.x (Apache-2.0).
 * Only a private pipe carries credentials; stdout carries bounded pixels.
 */
#define _GNU_SOURCE
#include <freerdp/freerdp.h>
#include <freerdp/settings.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/input.h>
#include <winpr/synch.h>
#include <winpr/wlog.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned char expected_pin[32];
static char expected_host[256];
static unsigned short expected_port;
static unsigned short desktop_width, desktop_height;
static int output_failed;

static int private_pages(void *data,size_t length) {
 long page=sysconf(_SC_PAGESIZE);if(page<=0)return 0;
 uintptr_t start=(uintptr_t)data&~((uintptr_t)page-1);
 uintptr_t end=((uintptr_t)data+length+(uintptr_t)page-1)&~((uintptr_t)page-1);
 return madvise((void*)start,end-start,MADV_DONTDUMP)==0;
}
static int read_all(void *buffer, size_t length) {
 unsigned char *p=buffer;
 while(length) { ssize_t n=read(STDIN_FILENO,p,length); if(n<=0)return 0; p+=n; length-=(size_t)n; }
 return 1;
}
static int write_all(const void *buffer,size_t length) {
 const unsigned char *p=buffer;
 while(length) { ssize_t n=write(STDOUT_FILENO,p,length); if(n<=0){output_failed=1;return 0;} p+=n; length-=(size_t)n; }
 return 1;
}
static unsigned short u16(const unsigned char *b){return ((unsigned short)b[0]<<8)|b[1];}
static int field(char *out,size_t capacity,int sensitive) {
 unsigned char size[2]; if(!read_all(size,2))return 0; size_t n=u16(size);
 if(n>=capacity || (!n&&sensitive))return 0;
 if(!read_all(out,n))return 0;
 if(memchr(out,0,n))return 0;
 out[n]=0; return 1;
}
static int packet(unsigned char kind,const void *payload,size_t size) {
 if(size>1280u*1024u*4u+4u)return 0;
 uint32_t n=(uint32_t)size+1; unsigned char header[5]={(n>>24)&255,(n>>16)&255,(n>>8)&255,n&255,kind};
 return write_all(header,sizeof(header))&&write_all(payload,size);
}
static void wipe_password(rdpSettings *settings) {
 if(settings->Password) explicit_bzero(settings->Password,strlen(settings->Password));
 if(settings->PasswordHash) explicit_bzero(settings->PasswordHash,strlen(settings->PasswordHash));
 if(settings->Password51) explicit_bzero(settings->Password51,settings->Password51Length);
 if(settings->RedirectionPassword) explicit_bzero(settings->RedirectionPassword,settings->RedirectionPasswordLength);
}
static int verify_cert(freerdp *instance,const BYTE *data,size_t size,const char *host,UINT16 port,DWORD flags) {
 (void)instance;(void)flags;
 if(!host||strcmp(host,expected_host)||port!=expected_port)return 0;
 if(size>65536)return 0;
 BIO *bio=BIO_new_mem_buf(data,(int)size); if(!bio)return 0;
 X509 *cert=PEM_read_bio_X509(bio,NULL,NULL,NULL); BIO_free(bio); if(!cert)return 0;
 unsigned char digest[EVP_MAX_MD_SIZE]; unsigned int length=0;
 int valid=X509_cmp_current_time(X509_get0_notBefore(cert))<0 && X509_cmp_current_time(X509_get0_notAfter(cert))>0 && X509_digest(cert,EVP_sha256(),digest,&length) && length==32 && CRYPTO_memcmp(expected_pin,digest,32)==0;
 OPENSSL_cleanse(digest,sizeof(digest)); X509_free(cert); return valid?2:0;
}
static BOOL begin_paint(rdpContext *context) {
 context->gdi->primary->hdc->hwnd->invalid->null=TRUE;
 context->gdi->primary->hdc->hwnd->ninvalid=0; return TRUE;
}
static BOOL end_paint(rdpContext *context) {
 rdpGdi *gdi=context->gdi;
 if(gdi->primary->hdc->hwnd->invalid->null)return TRUE;
 if(gdi->width!=desktop_width || gdi->height!=desktop_height)return FALSE;
 unsigned char dims[4]={desktop_width>>8,desktop_width&255,desktop_height>>8,desktop_height&255};
 uint32_t size=5u+(uint32_t)desktop_width*desktop_height*4u;
 unsigned char header[5]={size>>24,(size>>16)&255,(size>>8)&255,size&255,2};
 if(!write_all(header,5)||!write_all(dims,4))return FALSE;
 for(int y=0;y<gdi->height;y++)if(!write_all(gdi->primary_buffer+(size_t)y*gdi->stride,(size_t)gdi->width*4u))return FALSE;
 return TRUE;
}
static BOOL post_connect(freerdp *instance) {
 // No reconnect is allowed after this one connection's credential is erased.
 wipe_password(instance->settings);
 if(!gdi_init(instance,PIXEL_FORMAT_BGRX32))return FALSE;
 instance->update->BeginPaint=begin_paint; instance->update->EndPaint=end_paint;
 unsigned char dims[4]={desktop_width>>8,desktop_width&255,desktop_height>>8,desktop_height&255};
 return packet(1,dims,4);
}
static void post_disconnect(freerdp *instance) { wipe_password(instance->settings); gdi_free(instance); }
static BOOL no_auth_prompt(freerdp *instance,char **username,char **password,char **domain) {
 (void)instance;(void)username;(void)password;(void)domain;return FALSE;
}
static int input_packet(freerdp *instance) {
 unsigned char b[7]; if(!read_all(b,sizeof(b)))return 0;
 UINT16 flags=u16(b+1),a=u16(b+3),c=u16(b+5);
 switch(b[0]) {
 case 0:return 0;
 case 3:if(c || a>255 || (flags&~(KBD_FLAGS_RELEASE|KBD_FLAGS_EXTENDED)))return 0; return freerdp_input_send_keyboard_event(instance->input,flags,a);
 case 4:if(c || (flags&~KBD_FLAGS_RELEASE) || (a>=0xd800&&a<=0xdfff))return 0;return freerdp_input_send_unicode_keyboard_event(instance->input,flags,a);
 case 5:if(a>=desktop_width||c>=desktop_height || (flags&~(PTR_FLAGS_MOVE|PTR_FLAGS_DOWN|PTR_FLAGS_BUTTON1|PTR_FLAGS_BUTTON2|PTR_FLAGS_BUTTON3|PTR_FLAGS_WHEEL|PTR_FLAGS_WHEEL_NEGATIVE|0x00ff)))return 0;return freerdp_input_send_mouse_event(instance->input,flags,a,c);
 default:return 0;
 }
}
int main(int argc,char **argv) {
 struct rlimit core={0,0};
 if(setrlimit(RLIMIT_CORE,&core)||prctl(PR_SET_DUMPABLE,0)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||mlockall(MCL_CURRENT|MCL_FUTURE))return 70;
 signal(SIGPIPE,SIG_IGN); WLog_SetLogLevel(WLog_GetRoot(),WLOG_OFF);
 char magic[8],host[256]={0},user[129]={0},domain[129]={0},pin[65]={0},password[1025]={0}; unsigned char dimensions[7];
 int exit_code=71; freerdp *instance=NULL;
 if(!private_pages(password,sizeof(password)))goto finish;
 if(argc==2&&!strcmp(argv[1],"--check")) {
  static const char ready[]="TRSTCTL-RDP/1\n";
  return write_all(ready,sizeof(ready)-1)?0:70;
 }
 if(argc!=1)goto finish;
 if(!read_all(magic,8)||memcmp(magic,"TRDP0001",8)||!read_all(dimensions,7))goto finish;
 unsigned short port=u16(dimensions);desktop_width=u16(dimensions+2);desktop_height=u16(dimensions+4);
 if(!port||desktop_width<320||desktop_width>1280||desktop_height<200||desktop_height>1024||dimensions[6]>1)goto finish;
 if(!field(host,sizeof(host),0)||!host[0]||!field(user,sizeof(user),0)||!user[0]||!field(domain,sizeof(domain),0)||!field(pin,sizeof(pin),0)||strlen(pin)!=64||!field(password,sizeof(password),1))goto finish;
 for(size_t i=0;i<32;i++){unsigned int byte=0;if(sscanf(pin+2*i,"%2x",&byte)!=1)goto finish;expected_pin[i]=(unsigned char)byte;}
 memcpy(expected_host,host,sizeof(host));expected_port=port;
 instance=freerdp_new();if(!instance)goto finish;
 instance->ContextSize=sizeof(rdpContext);
 instance->VerifyX509Certificate=verify_cert;instance->Authenticate=no_auth_prompt;
 instance->PostConnect=post_connect;instance->PostDisconnect=post_disconnect;
 if(!freerdp_context_new(instance))goto finish;
 rdpSettings *s=instance->settings;
 if(!freerdp_settings_set_string(s,FreeRDP_ServerHostname,host)||!freerdp_settings_set_string(s,FreeRDP_Username,user)||!freerdp_settings_set_string(s,FreeRDP_Domain,domain)||!freerdp_settings_set_string(s,FreeRDP_Password,password))goto finish;
 if(!private_pages(s->Password,strlen(s->Password)+1))goto finish;
 explicit_bzero(password,sizeof(password));
 freerdp_settings_set_uint32(s,FreeRDP_ServerPort,port);
 freerdp_settings_set_uint32(s,FreeRDP_DesktopWidth,desktop_width);freerdp_settings_set_uint32(s,FreeRDP_DesktopHeight,desktop_height);
 freerdp_settings_set_uint32(s,FreeRDP_ColorDepth,32);
 freerdp_settings_set_bool(s,FreeRDP_SoftwareGdi,TRUE);freerdp_settings_set_bool(s,FreeRDP_ExternalCertificateManagement,TRUE);
 freerdp_settings_set_bool(s,FreeRDP_IgnoreCertificate,FALSE);
 freerdp_settings_set_bool(s,FreeRDP_NlaSecurity,dimensions[6]?FALSE:TRUE);
 freerdp_settings_set_bool(s,FreeRDP_TlsSecurity,dimensions[6]?TRUE:FALSE);freerdp_settings_set_bool(s,FreeRDP_RdpSecurity,FALSE);
 freerdp_settings_set_bool(s,FreeRDP_AutoLogonEnabled,TRUE);freerdp_settings_set_bool(s,FreeRDP_AutoReconnectionEnabled,FALSE);
 freerdp_settings_set_bool(s,FreeRDP_DeviceRedirection,FALSE);freerdp_settings_set_bool(s,FreeRDP_RedirectHomeDrive,FALSE);
 freerdp_settings_set_bool(s,FreeRDP_RedirectSmartCards,FALSE);freerdp_settings_set_bool(s,FreeRDP_RedirectSerialPorts,FALSE);freerdp_settings_set_bool(s,FreeRDP_RedirectParallelPorts,FALSE);
 freerdp_settings_set_bool(s,FreeRDP_RedirectClipboard,FALSE);freerdp_settings_set_bool(s,FreeRDP_RedirectDrives,FALSE);freerdp_settings_set_bool(s,FreeRDP_RedirectPrinters,FALSE);
 freerdp_settings_set_bool(s,FreeRDP_AudioPlayback,FALSE);freerdp_settings_set_bool(s,FreeRDP_AudioCapture,FALSE);
 freerdp_settings_set_bool(s,FreeRDP_DesktopResize,FALSE);
 if(!freerdp_connect(instance))goto finish;
 exit_code=0;
 while(!freerdp_shall_disconnect(instance)&&!output_failed) {
 HANDLE events[64];DWORD count=freerdp_get_event_handles(instance->context,events,64);
 if(!count||WaitForMultipleObjects(count,events,FALSE,20)==WAIT_FAILED||!freerdp_check_event_handles(instance->context)){exit_code=72;break;}
 fd_set readfds;FD_ZERO(&readfds);FD_SET(STDIN_FILENO,&readfds);struct timeval timeout={0,0};
 int selected=select(STDIN_FILENO+1,&readfds,NULL,NULL,&timeout);
 if(selected<0){exit_code=72;break;}
 if(selected>0&&!input_packet(instance)){exit_code=73;break;}
 }
 freerdp_disconnect(instance);
finish:
 explicit_bzero(password,sizeof(password));
 if(instance){wipe_password(instance->settings);freerdp_context_free(instance);freerdp_free(instance);}
 if(exit_code){unsigned char failure=(unsigned char)exit_code;packet(3,&failure,1);}
 OPENSSL_cleanse(expected_pin,sizeof(expected_pin)); return exit_code;
}
