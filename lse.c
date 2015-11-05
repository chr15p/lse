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
#include <getopt.h>

#define __USE_XOPEN_EXTENDED
#define _XOPEN_SOURCE 500
#define __USE_GNU
#include <ftw.h>
#include <unistd.h>

static struct option longopts[] = {
  { "process",		required_argument,	NULL,   'p'},
  { "recurse",	required_argument,	NULL,	'r'},
  { NULL,  0,  NULL,  0 }
};
security_context_t pidcon;

int scanfile(const char *filepath, const struct stat *statresult, int typeflag){
	security_class_t class;
	security_context_t con;
	struct av_decision av;

	//if((strcmp(entry->d_name,"..") == 0)||(strcmp(entry->d_name,".") == 0)){
	//	return 0;
	//	
	if( typeflag==FTW_SL){
		printf("%-40s ","");
		printf("%-10s ","symlink");
		printf("%-25s\n",filepath);
		return 0;	
	}

	getfilecon(filepath,&con);
	if(con != 0){
		class = mode_to_security_class(statresult->st_mode);
		printf("%-40s ",con);
		printf("%-10s ",security_class_to_string(class));
		printf("%-25s ",filepath);
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
		printf("%-10s ","no context");
		printf("%-25s\n",filepath);
	}
	return 0;
}

 

int main(int argc,char *argv[]){
	struct stat statresult;
	int process=1;
	char ch;
	int recurse=0;
	char *cwd;


    while((ch = getopt_long(argc, argv, "+p:r",longopts,NULL)) != -1) {
        switch(ch){
			case 'r':
				recurse=1;
				break;
			/*
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
			*/
            case 'p':
				process =  strtol(optarg, NULL, 10);
                break;

		}
	}


	if(getpidcon(process,&pidcon) <0){
		fprintf(stderr,"failed to get context for process %d\n",process);
		exit(1);
	}


	if (optind < argc) {
		while (optind < argc){
			stat(argv[optind],&statresult);
			if (S_ISDIR(statresult.st_mode) && recurse) {
				ftw(argv[optind],&scanfile,20);
			}else{
				scanfile(argv[optind],&statresult,1);
			}
			optind++;
			//printf("%s ", argv[optind++]);
			//printf("\n");
		}
	}else{
		cwd = get_current_dir_name();
		if(recurse){
			ftw(cwd, &scanfile,20);
		}else{
			stat(cwd,&statresult);
			scanfile(cwd,&statresult,1);
		}
	}

	freecon(pidcon);

	return 0;
}
