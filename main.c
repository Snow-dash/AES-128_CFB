#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>
#include "AES.c"
#include "SHA1.h"
unsigned char data[4][4]={{0},{0}},k[4][4]={{0},{0}},cy[4][4]={{0},{0}};
FILE *fp,*fpk,*fpo,*fpt;
unsigned char start[4][4]={{0},{0}};//tic[8]={0};

void firstsec();
void dataset0();
int main(int argc, char *argv[]) {
	
	DLLIMPORT void SHA1(FILE *fp,char bf[]);
	HINSTANCE zhi=LoadLibrary("SHA1.dll");
	typedef void (*usedll)(FILE *fp, char bf[]);
	usedll USE =(usedll)GetProcAddress(zhi,"SHA1");
	
	
	
	
	bool en=true;
	int i,i1,i2,shi,yu=0;
	int fcon=0;
	unsigned long long size,sizek=0,iz=0;
	if(argc!=4 || strcmp(argv[1],"?")==0)
	{
		//printf("%d",argc);
		printf(" \nUsage: AES.exe [filepath about to Encrypt or Decrypt] [keyfilepath] [de/en]\n \"en\" for Encrypt and \"de\" for Decrypt.\n");
		printf(" 用法：程序 要加密或解密的文件 密钥文件 de或者en “en”表示加密，“de”表示解密\n");
		exit(2);
	}
	if(strcmp(argv[3],"en")==0)
	{
		en=true;
	}
	else
	{
		if(strcmp(argv[3],"de")==0)
		{
			en=false;
		}
		else
		{
			printf(" please type \"en\" or \"de\"");
			exit(2);
		}
	}
	//en=false;
	/*if((fpt=fopen("SHA1.dll","rb"))==NULL)
	{
		printf("SHA1.dll file missing\nSHA1.dll文件缺失\n");
		exit(2);
	}
	fclose(fpt);*/
	if((fp=fopen(argv[1],"rb"))==NULL)
	{
		printf(" Can not open input file\n");
		exit(2);
	}
	char path[256]={0};
	int end;
	strcpy(path,argv[1]);
	if(en) strcat(path,".aesfile");
	else
	{
		end=strlen(path);
		for(i=0;i<=8;i++)
		{
			path[end-i]=0;
		}
	}

	if((fpo=(fopen(path,"wb")))==NULL)
	{
		printf("Can not creat output file\n");
		fclose(fp);
		exit(2);
	}
	if((fpk=(fopen(argv[2],"rb")))==NULL)
	{
		printf("Can not open key file\n");
		fclose(fp);
		fclose(fpo);
		exit(2);
	}
	else
	{
		fseek(fpk,0,2);
		sizek=ftell(fpk);
		rewind(fpk);
		if(sizek!=16)
		{
			printf("key file error\n");
			fclose(fp);
			fclose(fpo);
			fclose(fpk);
			exit(2);
		}
	}
	fseek(fp,0,2);
	size=ftell(fp);
	//printf("size:%d\n",size);
	rewind(fp);
	//printf("t1:%d\n",ftell(fp));
	yu=(size+16)%16;
	yu=16-yu;
	//printf("yu:%d\n",yu);
	fread(k,16,1,fpk);
	char bf[45];
	int con=0;
	if(en)//0x530x6e0x6f0x770x640x610x730x68
	{
		printf(" Start encrypt\n");
		firstsec();
		rewind(fp);
		USE(fp,bf);
		rewind(fp);
		for(iz=0;iz<(size/16)+1+3;iz++)
		{
				dataset0();
				if(iz<(size/16))
				{
					fread(data,16,1,fp);
				}
				else
				{
					if(iz==(size/16))
					{
						//if(yu!=16)
						{
							int readcon=0;
							for(i1=0;i1<4;i1++)
							{
								for(i2=0;i2<4;i2++)
								{
									if(readcon>=(16-yu))
									{
										data[i1][i2]=yu;
									}
									else
									{
										//rewind(fp);
										//printf("t:%d\n",ftell(fp));
										fread(&data[i1][i2],1,1,fp);
										//printf("%d %d %d\n",i1,i2,data[i1][i2]);
									}
									readcon++;
								}
							}
						}
						//else
						{
							;
						}
						
						//for(i=0;i<(16-yu);i++)
					}
					else
					for(i=0;i<4;i++)
					{
						for(i1=0;i1<4;i1++)
						{
							if(con>=40)
							{
								data[i][i1]=0;
							}
							else
							{
								data[i][i1]=bf[con];
							}
							con++;
						}
					}
				}
				for(i=0;i<4;i++)
				{
					for(i1=0;i1<4;i1++)
					{
						data[i][i1]=data[i][i1] ^ start[i][i1];
					}
				}
				AES(data,k,cy);
				fwrite(cy,16,1,fpo);
				fcon++;
				if(fcon==1000)
				{
					fflush(fpo);
					fcon=0;
				}
				for(i=0;i<4;i++)
				{
					for(i1=0;i1<4;i1++)
					{
						start[i][i1]=cy[i][i1];
					}
				}
		}
		//fwrite(bf,40,1,fpo);
		printf(" Encrypt Complete\n");
		fclose(fpk);
		fclose(fpo);
		fclose(fp);
	}
	if(!en)
	{
		con=0;
		char yan[9]="Snowdash";
		char bf[45]={0};
		char bf1[45]={0};
		if(size%16!=0)
		{
			printf("Input file error\n");
			fclose(fpk);
			fclose(fpo);
			fclose(fp);
			remove(path);
			exit(2);
		}
		fread(cy,16,1,fp);
		AESde(cy,k,data);
		for(i=0;i<2;i++)
		{
			for(i1=0;i1<4;i1++)
			{
				if(data[i][i1]!=yan[con])
				{
					printf(" Input file error or key error\n");
					fclose(fpk);
					fclose(fpo);
					fclose(fp);
					exit(2);
				}
				con++;
			}
		}
		for(i=0;i<4;i++)
		{
			for(i1=0;i1<4;i1++)
			{
				start[i][i1]=data[i][i1];
			}
		}
		con=0;
		int yucon=0;
		for(iz=0;iz<((size-16)/16);iz++)
		{
			fread(cy,16,1,fp);
			AESde(cy,k,data);
			for(i=0;i<4;i++)
			{
				for(i1=0;i1<4;i1++)
				{
					data[i][i1]=data[i][i1] ^ start[i][i1];
				}
			}
			for(i=0;i<4;i++)
			{
				for(i1=0;i1<4;i1++)
				{
					start[i][i1]=cy[i][i1];
				}
			}
			
			
			if(iz>=(((size-16)/16)-3))
			{
				for(i=0;i<4;i++)
				{
					for(i1=0;i1<4;i1++)
					{
						bf[con]=data[i][i1];
						con++;
					}
				}
			}
			else
			{
				if(iz==(((size-16)/16)-4))
				{
					yucon=0;
					yu=data[3][3];
					yu=16-yu;
					//printf("de:yu:%d\n",yu);
					for(i=0;i<4;i++)
					{
						for(i1=0;i1<4;i1++)
						{
							if(yucon>=yu) break;
							fwrite(&data[i][i1],1,1,fpo);
							yucon++;
						}
						if(yucon>=yu) break;
					}
				}
				else
				fwrite(data,16,1,fpo);
				fcon++;
				if(fcon==1000)
				{
					fflush(fpo);
					fcon=0;
				}
			}
		}
		fclose(fpo);
		fpo=fopen(path,"rb");
		USE(fpo,bf1);
		if(strcmp(bf,bf1)!=0)
		{
			printf(" File has been changed\n");
			/*printf("bf :%s\n",bf);
			printf("bf1:%s",bf1);*/
		}
		else
		{
			printf(" Decrypt complete\n");
		}
	}
	
	//
	//USE(fpk,bf);
	fclose(fpk);
	fclose(fpo);
	fclose(fp);
	return 0;
}
void firstsec()
{
	unsigned long long ti=0;
	//unsigned long long dash=7526466486394646099;
	unsigned char dashc[8]={0x53,0x6e,0x6f,0x77,0x64,0x61,0x73,0x68};
	int i,i1;
	ti=time(NULL);
		//ltoa(ti,tic,2);
		//fwrite(&start,sizeof(start),1,fpo);
		//fwrite(&dash,8,1,fpo);
		//fwrite(&ti,sizeof(ti),1,fpo);
		int con=0;
		for(i=0;i<4;i++)
		{
			for(i1=0;i1<4;i1++)
			{
				if(con>=8)
				{
					start[i][i1]=( (ti >> ((con-8)*8)) & 0xff);
				}
				else
				{
					start[i][i1]=dashc[con];
				}
				con++;
			}
		}
		AES(start,k,cy);
		fwrite(cy,16,1,fpo);
}
void dataset0()
{
	int i,i1;
	for(i=0;i<4;i++)
	{
		for(i1=0;i1<4;i1++)
		{
			data[i][i1]=0;
		}
	}
}
/*void cyset0()
{
	
}*/

