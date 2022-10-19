#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include<unistd.h>
#include <limits.h>
#include <signal.h>
#include <malloc.h>
#include<string.h>

/*Error Handling*/
 #define handle_error(msg) \
           do { perror(msg); exit(EXIT_FAILURE); } while (0)

       static char *buffer;

       static void
       handler(int sig, siginfo_t *si, void *unused)
       {
           /* Note: calling printf() from a signal handler is not safe
              (and should not be done in production programs), since
              printf() is not async-signal-safe; see signal-safety(7).
              Nevertheless, we use printf() here as a simple way of
              showing that the handler was called. */

           printf("Got SIGSEGV at address: 0x%lx\n",
                   (long) si->si_addr);
           exit(EXIT_FAILURE);
       }
/*Main function*/
int main(int argc, char *argv[])
       {
           char *p,*buffer;
           char *q,*buffer2;
	   char c;
           int pagesize;
	   int i=0,size, size2;
           struct sigaction sa;

           char tempBuff[] = "";
           char *firstName = "Deepti";
           char *lastName = "Venkatesh";
           char *userName = "dvenkatesh7";

           sa.sa_flags = SA_SIGINFO;
           sigemptyset(&sa.sa_mask);
           sa.sa_sigaction = handler;
           if (sigaction(SIGSEGV, &sa, NULL) == -1)
               handle_error("sigaction");

           pagesize = sysconf(_SC_PAGE_SIZE);  /* Initializing Pagesize, here pagesize=4096 Bytes*/
           if (pagesize == -1)
               handle_error("sysconf");

    /* Allocate a buffer; it will have the default
       protection of PROT_READ|PROT_WRITE. */
    size=pagesize*10;
    p = memalign(pagesize,size);          /*Allocating buffer'p' of size = ten pages*/
    if (p == NULL)
    handle_error("memalign");

    memset(p,0x00,size);                     /*Copying 'B' to whole buffer*/
    memset(p,0x41,size); 
    
    for(i=0;i<10;i++)
    {
	printf("Address of %d Page: %lx\n",i+1,p+(i*4096));	/*Printing all pages first  bytes from first page. The usage of %d format specifier causes compilation warnings. Can you figure out why?*/
	
    }

// Can start writing code here and can define variables for functions above
 //printf("Ninth Page: \n\n");
 buffer=p;                      /*pointing buffer, 'buffer' to starting address of p*/
   i=32768;


    for(i=32768;i<(32768 + strlen(firstName));i++)
    {
         *(buffer+i) = firstName[i-32768];

    }			 
  

    /* for(i=32768;i<(32768 + strlen(firstName));i++)
    {
	printf("%d=%c, %lx\n",i+1,*(p+i),p+i);	Printing first 3 bytes from second page
	
    }*/


 //printf("Tenth Page: \n\n");


    for(i=36864;i<(36864 + strlen(firstName));i++)
    {
        *(buffer+i) = firstName[i-36864];
    }			 
  

    /* for(i=36864;i<(36864 + strlen(firstName));i++)
    {
	printf("%d=%c, %lx\n",i+1,*(p+i),p+i);	Printing first 3 bytes from second page
	
    }*/
//24576, 28672
   if (mprotect(p+pagesize*7, pagesize, PROT_READ|PROT_WRITE)==-1)
	{handle_error("mprotect");
        }

   if (mprotect(p+pagesize*8, pagesize, PROT_READ|PROT_WRITE)==-1)
	{handle_error("mprotect");
        }

    printf("Seventh Page: \n\n");


    for(i=24576;i<(24576 + strlen(lastName));i++)
    {
        *(buffer+i) = lastName[i-24576];
    }			 
  

     for(i=24576;i<(24576 + strlen(lastName));i++)
    {
	printf("%d=%c, %lx\n",i+1,*(p+i),p+i);	/*Printing first 3 bytes from second page*/
	
    }

    printf("Eight Page: \n\n");


    for(i=28672;i<(28672 + strlen(lastName));i++)
    {
        *(buffer+i) = lastName[i-28672];
    }			 
  

     for(i=28672;i<(28672 + strlen(lastName));i++)
    {
	printf("%d=%c, %lx\n",i+1,*(p+i),p+i);	/*Printing first 3 bytes from second page*/
	
    }
    //20480,16384
    

   if (mprotect(p+pagesize*6, pagesize, PROT_WRITE)==-1)
	{handle_error("mprotect");
        }
   if (mprotect(p+pagesize*5, pagesize, PROT_WRITE)==-1)
	{handle_error("mprotect");
        }
   printf("Fifth Page: \n\n");


    for(i=16384;i<(16384 + strlen(userName));i++)
    {
        *(buffer+i) = userName[i-16384];
    }			 
  

     for(i=16384;i<(16384 + strlen(userName));i++)
    {
	printf("%d=%c, %lx\n",i+1,*(p+i),p+i);	/*Printing first 3 bytes from second page*/
	
    }

     printf("Sixth Page: \n\n");


    for(i=20480;i<(20480 + strlen(userName));i++)
    {
        *(buffer+i) = userName[i-20480];
    }			 
  

     for(i=20480;i<(20480 + strlen(userName));i++)
    {
	printf("%d=%c, %lx\n",i+1,*(p+i),p+i);	/*Printing first 3 bytes from second page*/
	
    }

    q = memalign(pagesize,pagesize*2);          /*Allocating buffer'q' of size = two pages*/
    if (q == NULL)
    handle_error("memalign");


    memcpy(q, p+pagesize*6, pagesize);
    memcpy(q+pagesize, p+pagesize*7, pagesize);

    for(i=0;i<2;i++)
    {
	printf("Address of %d Page: %lx\n",i+1,q+(i*4096));	/*Printing all pages first  bytes from first page. The usage of %d format specifier causes compilation warnings. Can you figure out why?*/
	
    }

    printf("New Buffer first page: \n\n");
    for(i=0;i<10;i++)
    {
	printf("%d=%c, %lx\n",i+1,*(q+i),q+i);	/*Printing first 3 bytes from second page*/
	
    }
    printf("New Buffer second page: \n\n");
    for(i=pagesize;i<pagesize+10;i++)
    {
	printf("%d=%c, %lx\n",i+1,*(q+i),q+i);	/*Printing first 3 bytes from second page*/
	
    }
     memcpy(q, p+pagesize*5, pagesize);
    memcpy(q+pagesize, p+pagesize*8, pagesize);
    
    printf("New Buffer first page - old sixth: \n\n");
    for(i=0;i<10;i++)
    {
	printf("%d=%c, %lx\n",i+1,*(q+i),q+i);	/*Printing first 3 bytes from second page*/
	
    }
    printf("New Buffer second page - old ninth: \n\n");
    for(i=pagesize;i<pagesize+10;i++)
    {
	printf("%d=%c, %lx\n",i+1,*(q+i),q+i);	/*Printing first 3 bytes from second page*/
	
    }

           exit(EXIT_SUCCESS);
      
       }


