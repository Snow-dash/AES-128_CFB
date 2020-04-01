#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#define ll long long
//448位 56字节

//全局变量
unsigned int Y[16];//一个明文分组
unsigned int M[16]={0};//子明文分组
unsigned int W[80];//扩充分组
unsigned int A	=0x67452301l,B	=0xefcdab89l,C	=0x98badcfel,D	=0x10325476l,E	=0xc3d2e1f0l;//A_,B_,C_,D_,E_;
unsigned int H0	=0x67452301l,H1	=0xefcdab89l,H2	=0x98badcfel,H3	=0x10325476l,H4	=0xc3d2e1f0l;
//unsigned int A1,B1,C1,D1,E1;
unsigned ll N=0,Nt=0;
bool t=false;
//声明子函数
unsigned int kt(int t);
unsigned int ft(unsigned int x,unsigned int y,unsigned int z,int t);
void op(int t);
void mtow(int t);
unsigned int S(unsigned int x,int n);
void mainonce();
unsigned int rv(unsigned int x);
void cha(char a[],unsigned int x);

void SHA1(FILE *fp,char bf[]) {
	
	//FILE *fp=NULL;
	int i=0;
	unsigned ll i1=0;
	unsigned ll size=0;//文件大小
	int yu=0;//对512取余余数
	char p[50]={0};//没啥用
	
	while(fread(p,1,1,fp)!=0)
	{
		size++;//算字节数
	}
	N=size/64+1;//一个N是64字节,多少块
	if(N>=5000) t=true;
	rewind(fp);
	A=H0;B=H1;C=H2;D=H3;E=H4;
	//printf("位置%ld\n",ftell(fp));
	yu=(size*8)%512;
	//if(yu>=448 || N>=1)
	{
		if(yu>=448) N=N+1;
		for(i1=1;i1<=N;i1++)
		{
			for(i=0;i<=15;i++)
			{
				Y[i]=0;
			}
			if(t)
			{
				for(i=1;i<=9;i++)
				//if(i1==(unsigned ll)((i/10.0)*N)) printf("\n%d0%% finished\n",i);
				/*if(i1==(unsigned ll)(0.2*N)) printf("\n20%% finished\n");
				if(i1==(unsigned ll)(0.3*N)) printf("\n30%% finished\n");
				if(i1==(unsigned ll)(0.4*N)) printf("\n40%% finished\n");
				if(i1==(unsigned ll)(0.6*N)) printf("\n60%% finished\n");
				if(i1==(unsigned ll)(0.8*N)) printf("\n80%% finished\n");*/
				;
			}
			if(yu>=448 && i1!=N && i1!=N-1)
			{
				i=0;
				while(fread(&Y[i],4,1,fp))
				{
					if(i==15) break;
					i++;
				}
				for(i=0;i<=15;i++)
				{
					Y[i]=rv(Y[i]);
					M[i]=Y[i];
				}
				//M[15]=size*8;
				//M[size/4]+=(0x80000000l>>(((size%4)*8)));
				mainonce();
			}
			else
			{
				if(yu>=448 && i1==N-1)
				{
					i=0;
					while(fread(&Y[i],4,1,fp))
					{
						if(i==15) break;
						i++;
					}
					for(i=0;i<=15;i++)
					{
						Y[i]=rv(Y[i]);
						M[i]=Y[i];
					}
					M[(size-64*(N-2))/4]+=(0x80000000l>>(((size%4)*8)));
					mainonce();
				}
				else
				{
					if(yu>=448 && i1==N)
					{
						for(i=0;i<=15;i++)
						{
							Y[i]=rv(Y[i]);
							M[i]=Y[i];
						}
						M[14]=((size*8)&(0xffffffff00000000ll))>>32;
						M[15]=((size*8)&(0x00000000ffffffffll));
						mainonce();
					}
					else
					{
						if(yu<448 && i1!=N)
						{
							i=0;
							while(fread(&Y[i],4,1,fp))
							{
								//printf("N=%d,i=%d,i1=%d\n循环内指针位置=%ld\n",N,i,i1,ftell(fp));
								if(i==15) break;
								i++;
							}
							//printf("指针位置=%ld\n",ftell(fp));
							for(i=0;i<=15;i++)
							{
								Y[i]=rv(Y[i]);
								M[i]=Y[i];
							//	printf("i1=%d,M%d=%08X\n",i1,i,M[i]);
							}
							mainonce();
						}
						else
						{
							if(yu<448 && i1==N)
							{
								i=0;
								//printf("指针位置=%ld\n",ftell(fp));
								while(fread(&Y[i],4,1,fp))
								{
									//printf("N=%d,i=%d,i1=%d\n循环内指针位置=%ld\n",N,i,i1,ftell(fp));
									if(i==15) break;
									i++;
								}
								//printf("2指针位置=%ld\n",ftell(fp));
								for(i=0;i<=15;i++)
								{
									Y[i]=rv(Y[i]);
									M[i]=Y[i];
									//printf("i1=%d,M%d=%08X\n",i1,i,M[i]);
								}
								M[14]=((size*8)&(0xffffffff00000000ll))>>32;
								M[15]=((size*8)&(0x00000000ffffffffll));
								M[(size-64*(N-1))/4]+=(0x80000000l>>(((size%4)*8)));
								/*for(i=0;i<=15;i++)
								{
									printf("M%d==%08X\n",i,M[i]);
								}*/
								//printf("M%d=%08X\n",(size-64*(N-1))/4,M[(size-64*(N-1))/4]);
								mainonce();
							}
						}
					}
				}
			}
		}
	}
	//printf("\nSHA1:%08X%08X%08X%08X%08X\n",H0,H1,H2,H3,H4);
	char temp[9]={0};
	//H0&0xff000000;
	cha(temp,H0);
	strcpy(bf,temp);
	cha(temp,H1);
	strcat(bf,temp);
	cha(temp,H2);
	strcat(bf,temp);
	cha(temp,H3);
	strcat(bf,temp);
	cha(temp,H4);
	strcat(bf,temp);
	//ltoa(H0,temp,16);
	rewind(fp);

}

void cha(char a[],unsigned int x)
{
	int i;
	char b16[]={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	for(i=0;i<8;i++)
	{
		a[i]=b16[((x>>((7-i)*4))&(0xf))];
	}
}

unsigned int ft(unsigned int x,unsigned int y,unsigned int z,int t)
{
	if(t>=0 && t<=19)
	return ((x & y) | (((~x))&z));
	if(t>=20 && t<=39)
	return (x ^ y) ^ z;
	if(t>=40 && t<=59)
	return ((x & y) | (x & z) | (y & z));
	if(t>=60 && t<=79)
	return (x ^ y) ^ z;
	else
	return 0;
}
void mainonce()
{
	//printf("使用mainonce\n");
	int i=0;
	A=H0;B=H1;C=H2;D=H3;E=H4;
	for(i=0;i<=79;i++)
	{
		mtow(i);
	}
	for(i=0;i<=79;i++)
	{
		op(i);
	}
	H0+=A;H1+=B;H2+=C;H3+=D;H4+=E;
}
void op(int t)
{
	unsigned int ta=0;
	ta=(S(A,5))+ft(B,C,D,t)+E+W[t]+kt(t);
	E=D;
	D=C;
	C=(S(B,30));
	B=A;
	A=ta;
}
unsigned int S(unsigned int x,int n)
{
	return x<<(n)|x>>(32-n);
}
void mtow(int t)
{
	if(t>=0 && t<=15)
	{
		W[t]=M[t];
	}

	if(t>=16 && t<=79)
	{
		W[t]=S((W[t-3]^W[t-8]^W[t-14]^W[t-16]),1);
	}
}
unsigned int kt(int t)//一个常量
{
	if(t>=0 && t<=19)
	return 0x5a827999l;
	if(t>=20 && t<=39)
	return 0x6ed9eba1l;
	if(t>=40 && t<=59)
	return 0x8f1BBcdcl;
	if(t>=60 && t<=79)
	return 0xca62c1d6l;
	else
	return 0;
}

unsigned int rv(unsigned int x)
{
	unsigned int xi=0;
	int i=0;
	for(i=0;i<=3;i++)
	{
		if(i>=0 && i<=1)
		xi=xi | (((0x000000ffl<<(8*i)) & (x)) << (24-2*8*i));
		if(i>=2 && i<=3)
		xi=xi | (((0x000000ffl<<(8*i)) & (x)) >> abs(24-2*8*i));
	}
	return xi;
}

