/* apps/speed.c -*- mode:C; c-file-style: "eay" -*- */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by 
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The ECDH and ECDSA speed test software is originally written by 
 * Sumit Gupta of Sun Microsystems Laboratories.
 *
 */

/* most of this code has been pilfered from my libdes speed.c program */

#ifndef OPENSSL_NO_SPEED

#undef SECONDS
#define SECONDS		3	
#define RSA_SECONDS	10
#define DSA_SECONDS	10
#define ECDSA_SECONDS   10
#define ECDH_SECONDS    10

/* 11-Sep-92 Andrew Daviel   Support for Silicon Graphics IRIX added */
/* 06-Apr-92 Luke Brennan    Support for VMS and add extra signal calls */

#undef PROG
#define PROG speed_main

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <string.h>
#include <math.h>
#include "apps.h"
#ifdef OPENSSL_NO_STDIO
#define APPS_WIN16
#endif
#include "crypto.h"
#include "rand.h"
#include "err.h"
#include "evp.h"
#include "objects.h"
#if !defined(OPENSSL_SYS_MSDOS)
#include OPENSSL_UNISTD
#endif

#ifndef OPENSSL_SYS_NETWARE
#include <signal.h>
#endif

#ifdef _WIN32
#include <windows.h>
#endif

#include "bn.h"
#ifndef OPENSSL_NO_DES
#include "des.h"
#endif
#ifndef OPENSSL_NO_AES
#include "aes.h"
#endif
#ifndef OPENSSL_NO_CAMELLIA
#include "camellia.h"
#endif
#ifndef OPENSSL_NO_MD2
#include "md2.h"
#endif
#ifndef OPENSSL_NO_MDC2
#include "mdc2.h"
#endif
#ifndef OPENSSL_NO_MD4
#include "md4.h"
#endif
#ifndef OPENSSL_NO_MD5
#include "md5.h"
#endif
#ifndef OPENSSL_NO_HMAC
#include "hmac.h"
#endif
#include "evp.h"
#ifndef OPENSSL_NO_SHA
#include "sha.h"
#endif
#ifndef OPENSSL_NO_RIPEMD
#include "ripemd.h"
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
#include "whrlpool.h"
#endif
#ifndef OPENSSL_NO_RC4
#include "rc4.h"
#endif
#ifndef OPENSSL_NO_RC5
#include "rc5.h"
#endif
#ifndef OPENSSL_NO_RC2
#include "rc2.h"
#endif
#ifndef OPENSSL_NO_IDEA
#include "idea.h"
#endif
#ifndef OPENSSL_NO_SEED
#include "seed.h"
#endif
#ifndef OPENSSL_NO_BF
#include "blowfish.h"
#endif
#ifndef OPENSSL_NO_CAST
#include "cast.h"
#endif
#ifndef OPENSSL_NO_RSA
#include "rsa.h"
#endif
#include "x509.h"
#ifndef OPENSSL_NO_DSA
#include "dsa.h"
#endif
#ifndef OPENSSL_NO_ECDSA
#include "ecdsa.h"
#endif
#ifndef OPENSSL_NO_ECDH
#include "ecdh.h"
#endif

#ifndef HAVE_FORK
# if defined(OPENSSL_SYS_VMS) || defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MACINTOSH_CLASSIC) || defined(OPENSSL_SYS_OS2) || defined(OPENSSL_SYS_NETWARE)
#  define HAVE_FORK 0
# else
#  define HAVE_FORK 1
# endif
#endif

#if HAVE_FORK
#undef NO_FORK
#else
#define NO_FORK
#endif

#undef BUFSIZE
#define BUFSIZE	((long)1024*8+1)
int run=0;

static int mr=0;
static int usertime=1;

static double Time_F(int s);
static void print_message(const char *s,long num,int length);
static void pkey_print_message(const char *str, const char *str2,
	long num, int bits, int sec);
static void print_result(int alg,int run_no,int count,double time_used);
#ifndef NO_FORK
static int do_multi(int multi);
#endif

#define ALGOR_NUM	29
#define SIZE_NUM	5
#define RSA_NUM		4
#define DSA_NUM		3

#define EC_NUM       16
#define MAX_ECDH_SIZE 256

static const char *names[ALGOR_NUM]={
  "md2","mdc2","md4","md5","hmac(md5)","sha1","rmd160","rc4",
  "des cbc","des ede3","idea cbc","seed cbc",
  "rc2 cbc","rc5-32/12 cbc","blowfish cbc","cast cbc",
  "aes-128 cbc","aes-192 cbc","aes-256 cbc",
  "camellia-128 cbc","camellia-192 cbc","camellia-256 cbc",
  "evp","sha256","sha512","whirlpool",
  "aes-128 ige","aes-192 ige","aes-256 ige"};
static double results[ALGOR_NUM][SIZE_NUM];
static int lengths[SIZE_NUM]={16,64,256,1024,8*1024};
#ifndef OPENSSL_NO_RSA
static double rsa_results[RSA_NUM][2];
#endif
#ifndef OPENSSL_NO_DSA
static double dsa_results[DSA_NUM][2];
#endif
#ifndef OPENSSL_NO_ECDSA
static double ecdsa_results[EC_NUM][2];
#endif
#ifndef OPENSSL_NO_ECDH
static double ecdh_results[EC_NUM][1];
#endif

#if defined(OPENSSL_NO_DSA) && !(defined(OPENSSL_NO_ECDSA) && defined(OPENSSL_NO_ECDH))
static const char rnd_seed[] = "string to make the random number generator think it has entropy";
static int rnd_fake = 0;
#endif

#ifdef SIGALRM
#if defined(__STDC__) || defined(sgi) || defined(_AIX)
#define SIGRETTYPE void
#else
#define SIGRETTYPE int
#endif 

static SIGRETTYPE sig_done(int sig);
static SIGRETTYPE sig_done(int sig)
	{
	signal(SIGALRM,sig_done);
	run=0;
#ifdef LINT
	sig=sig;
#endif
	}
#endif

#define START	0
#define STOP	1

/* app_tminterval section */
#if defined(_WIN32)
double app_tminterval(int stop,int usertime)
	{
	FILETIME		now;
	double			ret=0;
	static ULARGE_INTEGER	tmstart;
	static int		warning=1;
#ifdef _WIN32_WINNT
	static HANDLE		proc=NULL;

	if (proc==NULL)
		{
		if (GetVersion() < 0x80000000)
			proc = OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,
						GetCurrentProcessId());
		if (proc==NULL) proc = (HANDLE)-1;
		}

	if (usertime && proc!=(HANDLE)-1)
		{
		FILETIME junk;
		GetProcessTimes(proc,&junk,&junk,&junk,&now);
		}
	else
#endif
		{
		SYSTEMTIME systime;

		if (usertime && warning)
			{
			BIO_printf(bio_err,"To get meaningful results, run "
					   "this program on idle system.\n");
			warning=0;
			}
		GetSystemTime(&systime);
		SystemTimeToFileTime(&systime,&now);
		}

	if (stop==TM_START)
		{
		tmstart.u.LowPart  = now.dwLowDateTime;
		tmstart.u.HighPart = now.dwHighDateTime;
		}
	else	{
		ULARGE_INTEGER tmstop;

		tmstop.u.LowPart   = now.dwLowDateTime;
		tmstop.u.HighPart  = now.dwHighDateTime;

		ret = (__int64)(tmstop.QuadPart - tmstart.QuadPart)*1e-7;
		}

	return (ret);
	}

#else
#include <sys/time.h>
#include <sys/resource.h>

double app_tminterval(int stop,int usertime)
	{
	double		ret = 0;
	struct rusage	rus;
	struct timeval	now;
	static struct timeval tmstart;

	if (usertime)		getrusage(RUSAGE_SELF,&rus), now = rus.ru_utime;
	else			gettimeofday(&now,NULL);

	if (stop==TM_START)	tmstart = now;
	else			ret = ( (now.tv_sec+now.tv_usec*1e-6)
					- (tmstart.tv_sec+tmstart.tv_usec*1e-6) );

	return ret;
	}
#endif

#if defined(_WIN32)

#define SIGALRM
static unsigned int lapse,schlock;
static void alarm(unsigned int secs) { lapse = secs*1000; }

static DWORD WINAPI sleepy(VOID *arg)
	{
	schlock = 1;
	Sleep(lapse);
	run = 0;
	return 0;
	}

static double Time_F(int s)
	{
	if (s == START)
		{
		HANDLE	thr;
		schlock = 0;
		thr = CreateThread(NULL,4096,sleepy,NULL,0,NULL);
		if (thr==NULL)
			{
			DWORD ret=GetLastError();
			BIO_printf(bio_err,"unable to CreateThread (%d)",ret);
			ExitProcess(ret);
			}
		CloseHandle(thr);		/* detach the thread	*/
		while (!schlock) Sleep(0);	/* scheduler spinlock	*/
		}

	return app_tminterval(s,usertime);
	}
#else

static double Time_F(int s)
	{
	return app_tminterval(s,usertime);
	}
#endif


#ifndef OPENSSL_NO_ECDH
static const int KDF1_SHA1_len = 20;
static void *KDF1_SHA1(const void *in, size_t inlen, void *out, size_t *outlen)
	{
#ifndef OPENSSL_NO_SHA
	if (*outlen < SHA_DIGEST_LENGTH)
		return NULL;
	else
		*outlen = SHA_DIGEST_LENGTH;
	return SHA1(in, inlen, out);
#else
	return NULL;
#endif	/* OPENSSL_NO_SHA */
	}
#endif	/* OPENSSL_NO_ECDH */


  extern int bf_test();
  extern int cast_test();
  extern int dsa_test();
  extern int ecdh_test();
  extern int ec_test();
  extern int hmac_test();
  extern int idea_test();
  extern int md4_test();
  extern int md5_test();
  extern int mdc2_test();
  extern int rc2_test();
  extern int rc4_test();
  extern int rmd_test();
  extern int rsa_test();
  extern int sha_test();
  extern int wp_test();

int run_test(int (*test_func)(), FILE *out, const char* string, unsigned REPS) {
  unsigned i;
  int result = 0;
  Time_F(START);
  for (i = 0; i < REPS; ++i)
    result |= test_func();
  double time = Time_F(STOP);
  fprintf(out, "%s: %.2f\n", string, time);
  if (result)
    fprintf(stderr, "error: %s failed!\n", string);
  return result;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <results-file>\n", argv[0]);
    return 1;
  }

#ifdef SMALL_PROBLEM_SIZE
  int small = 1;
#else
  int small = 0;
#endif
  int ret = 0;
  FILE *f = fopen(argv[1], "w");
  double time;

  ret |= run_test(&bf_test, f, "Result-Blowfish", small ?    100 :    750);
  //ret |= run_test(&cast_test, f, "Result-CAST", small ?      1 :      2);
  ret |= run_test(&dsa_test, f, "Result-DSA",     small ?     10 :     50);
  ret |= run_test(&ecdh_test, f, "Result-ECDH",   small ?      3 :     15);
  ret |= run_test(&ec_test, f, "Result-EC",       small ?      1 :      2);
  ret |= run_test(&hmac_test, f, "Result-HMAC",   small ?  10000 :  70000);
  ret |= run_test(&idea_test, f, "Result-IDEA",   small ?   6000 : 300000);
  ret |= run_test(&md4_test, f, "Result-MD4",     small ?  10000 :  70000);
  ret |= run_test(&md5_test, f, "Result-MD5",     small ?  10000 :  70000);
  ret |= run_test(&mdc2_test, f, "Result-MDC2",   small ?   6000 : 300000);
  ret |= run_test(&rc2_test, f, "Result-RC2",     small ? 100000 : 700000);
  ret |= run_test(&rc4_test, f, "Result-RC4",     small ?     40 :    200);
  ret |= run_test(&rmd_test, f, "Result-RipeMD",  small ?   8000 :  40000);
  ret |= run_test(&rsa_test, f, "Result-RSA",     small ?      1 :      6);
  ret |= run_test(&sha_test, f, "Result-SHA",     small ?     80 :    400);
  ret |= run_test(&wp_test, f, "Result-WHRLPOOL", small ?     20 :    100);
  
  fclose(f);
  
  return ret;
	}

static void print_message(const char *s, long num, int length)
	{
#ifdef SIGALRM
	BIO_printf(bio_err,mr ? "+DT:%s:%d:%d\n"
		   : "Doing %s for %ds on %d size blocks: ",s,SECONDS,length);
	(void)BIO_flush(bio_err);
	alarm(SECONDS);
#else
	BIO_printf(bio_err,mr ? "+DN:%s:%ld:%d\n"
		   : "Doing %s %ld times on %d size blocks: ",s,num,length);
	(void)BIO_flush(bio_err);
#endif
#ifdef LINT
	num=num;
#endif
	}

static void pkey_print_message(const char *str, const char *str2, long num,
	int bits, int tm)
	{
#ifdef SIGALRM
	BIO_printf(bio_err,mr ? "+DTP:%d:%s:%s:%d\n"
			   : "Doing %d bit %s %s's for %ds: ",bits,str,str2,tm);
	(void)BIO_flush(bio_err);
	alarm(RSA_SECONDS);
#else
	BIO_printf(bio_err,mr ? "+DNP:%ld:%d:%s:%s\n"
			   : "Doing %ld %d bit %s %s's: ",num,bits,str,str2);
	(void)BIO_flush(bio_err);
#endif
#ifdef LINT
	num=num;
#endif
	}

static void print_result(int alg,int run_no,int count,double time_used)
	{
	BIO_printf(bio_err,mr ? "+R:%d:%s:%f\n"
		   : "%d %s's in %.2fs\n",count,names[alg],time_used);
	results[alg][run_no]=((double)count)/time_used*lengths[run_no];
	}

#ifndef NO_FORK
static char *sstrsep(char **string, const char *delim)
    {
    char isdelim[256];
    char *token = *string;

    if (**string == 0)
        return NULL;

    memset(isdelim, 0, sizeof isdelim);
    isdelim[0] = 1;

    while (*delim)
        {
        isdelim[(unsigned char)(*delim)] = 1;
        delim++;
        }

    while (!isdelim[(unsigned char)(**string)])
        {
        (*string)++;
        }

    if (**string)
        {
        **string = 0;
        (*string)++;
        }

    return token;
    }

static int do_multi(int multi)
	{
	int n;
	int fd[2];
	int *fds;
	static char sep[]=":";

	fds=malloc(multi*sizeof *fds);
	for(n=0 ; n < multi ; ++n)
		{
		pipe(fd);
		fflush(stdout);
		fflush(stderr);
		if(fork())
			{
			close(fd[1]);
			fds[n]=fd[0];
			}
		else
			{
			close(fd[0]);
			close(1);
			dup(fd[1]);
			close(fd[1]);
			mr=1;
			usertime=0;
			free(fds);
			return 0;
			}
		printf("Forked child %d\n",n);
		}

	/* for now, assume the pipe is long enough to take all the output */
	for(n=0 ; n < multi ; ++n)
		{
		FILE *f;
		char buf[1024];
		char *p;

		f=fdopen(fds[n],"r");
		while(fgets(buf,sizeof buf,f))
			{
			p=strchr(buf,'\n');
			if(p)
				*p='\0';
			if(buf[0] != '+')
				{
				fprintf(stderr,"Don't understand line '%s' from child %d\n",
						buf,n);
				continue;
				}
			printf("Got: %s from %d\n",buf,n);
			if(!strncmp(buf,"+F:",3))
				{
				int alg;
				int j;

				p=buf+3;
				alg=atoi(sstrsep(&p,sep));
				sstrsep(&p,sep);
				for(j=0 ; j < SIZE_NUM ; ++j)
					results[alg][j]+=atof(sstrsep(&p,sep));
				}
			else if(!strncmp(buf,"+F2:",4))
				{
				int k;
				double d;
				
				p=buf+4;
				k=atoi(sstrsep(&p,sep));
				sstrsep(&p,sep);

				d=atof(sstrsep(&p,sep));
				if(n)
					rsa_results[k][0]=1/(1/rsa_results[k][0]+1/d);
				else
					rsa_results[k][0]=d;

				d=atof(sstrsep(&p,sep));
				if(n)
					rsa_results[k][1]=1/(1/rsa_results[k][1]+1/d);
				else
					rsa_results[k][1]=d;
				}
			else if(!strncmp(buf,"+F2:",4))
				{
				int k;
				double d;
				
				p=buf+4;
				k=atoi(sstrsep(&p,sep));
				sstrsep(&p,sep);

				d=atof(sstrsep(&p,sep));
				if(n)
					rsa_results[k][0]=1/(1/rsa_results[k][0]+1/d);
				else
					rsa_results[k][0]=d;

				d=atof(sstrsep(&p,sep));
				if(n)
					rsa_results[k][1]=1/(1/rsa_results[k][1]+1/d);
				else
					rsa_results[k][1]=d;
				}
			else if(!strncmp(buf,"+F3:",4))
				{
				int k;
				double d;
				
				p=buf+4;
				k=atoi(sstrsep(&p,sep));
				sstrsep(&p,sep);

				d=atof(sstrsep(&p,sep));
				if(n)
					dsa_results[k][0]=1/(1/dsa_results[k][0]+1/d);
				else
					dsa_results[k][0]=d;

				d=atof(sstrsep(&p,sep));
				if(n)
					dsa_results[k][1]=1/(1/dsa_results[k][1]+1/d);
				else
					dsa_results[k][1]=d;
				}
#ifndef OPENSSL_NO_ECDSA
			else if(!strncmp(buf,"+F4:",4))
				{
				int k;
				double d;
				
				p=buf+4;
				k=atoi(sstrsep(&p,sep));
				sstrsep(&p,sep);

				d=atof(sstrsep(&p,sep));
				if(n)
					ecdsa_results[k][0]=1/(1/ecdsa_results[k][0]+1/d);
				else
					ecdsa_results[k][0]=d;

				d=atof(sstrsep(&p,sep));
				if(n)
					ecdsa_results[k][1]=1/(1/ecdsa_results[k][1]+1/d);
				else
					ecdsa_results[k][1]=d;
				}
#endif 

#ifndef OPENSSL_NO_ECDH
			else if(!strncmp(buf,"+F5:",4))
				{
				int k;
				double d;
				
				p=buf+4;
				k=atoi(sstrsep(&p,sep));
				sstrsep(&p,sep);

				d=atof(sstrsep(&p,sep));
				if(n)
					ecdh_results[k][0]=1/(1/ecdh_results[k][0]+1/d);
				else
					ecdh_results[k][0]=d;

				}
#endif

			else if(!strncmp(buf,"+H:",3))
				{
				}
			else
				fprintf(stderr,"Unknown type '%s' from child %d\n",buf,n);
			}

		fclose(f);
		}
	free(fds);
	return 1;
	}
#endif
#endif
