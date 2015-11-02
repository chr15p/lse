/* *
 * * Copyright (C) 2014 Chris Procter <lse at chrisprocter dot co dot uk>
 * *
 * * This copyrighted material is made available to anyone wishing to use,
 * * modify, copy, or redistribute it subject to the terms and conditions
 * * of the GNU General Public License v.2.
 * *
 * * You should have received a copy of the GNU General Public License
 * * along with this program; if not, write to the Free Software Foundation,
 * * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * */
#include <stdio.h>
#include <stdlib.h>
#include <selinux/context.h>
#include <selinux/selinux.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>

static struct option longopts[] = {
  { "process",		required_argument,	NULL,   'p'},
  { "directory",	required_argument,	NULL,	'd'},
  { NULL,  0,  NULL,  0 }
};


int main(int argc,char *argv[]){
	security_context_t con;
	security_context_t pidcon;
	//security_context_t currcon;
	struct av_decision av;
	struct stat statresult;
	security_class_t class;

	DIR * dirdesc;
	struct dirent * entry;
	//char *buffer;
	int process=1;
	char * dir;
	char ch;
	int len;

	len = strlen("./");
	dir = (char *) malloc(256 + len);
	strcpy(dir,"./");

    while((ch = getopt_long(argc, argv, "+p:d:",longopts,NULL)) != -1)
    {
        switch(ch){
            case 'd':
				len = strlen(optarg);
				dir = (char *) malloc(256 + len);
		        strcpy(dir,optarg);
				if(*(optarg+len-1) != '/'){
		            *(dir+len)='/';
					len++;
		            *(dir+len)=0;
				}
                break;
            case 'p':
				process =  strtol(optarg, NULL, 10);
                break;

		}
	}


	if(getpidcon(process,&pidcon) <0){
		fprintf(stderr,"failed to get context for process %d\n",process);
		exit(1);
	}
	printf("process %d context: %s\n",process,pidcon);


	if((dirdesc = opendir(dir)) == NULL ){
		perror("opendir");
		exit(2);
	}

	while((entry = readdir(dirdesc)) != NULL){
		if((strcmp(entry->d_name,"..") == 0)||(strcmp(entry->d_name,".") == 0)){
			continue;
		}
		strcpy(dir + len, entry->d_name);

		
		getfilecon(dir,&con);
		if(con != 0){
			stat(dir,&statresult);
			if (stat(dir,&statresult) == -1) {
				perror("stat");
				exit(EXIT_FAILURE);
			}

			class = mode_to_security_class(statresult.st_mode);
			printf("%-40s ",con);
			printf("%-10s ",security_class_to_string(class));
			printf("%-25s ",dir);
			security_compute_av_raw(pidcon,con,class,FILE__READ,&av);
			//printf("allowed =%d  ",av.allowed); 
			//printf("READ=%d  ",av.allowed & FILE__READ); 
			//printf("decided=%d  ",av.decided & FILE__READ); 
			//printf("WRITE=%d\n",av.allowed & FILE__WRITE);	
			print_access_vector(class,av.allowed);
			printf("\n");
			freecon(con);
		}else{
			printf("%-40s ","");
			printf("%-10s ","link");
			printf("%-25s\n",dir);
		}
	}

	closedir(dirdesc);
	freecon(pidcon);
	return 0;
}
