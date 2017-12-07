/* Libtrace program designed to demonstrate the use of the trace_get_source_*
 * shortcut functions. 
 *
 * This code also contains examples of sockaddr manipulation.
 */
#include "libtrace.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "link_list_counting.h"

void Linklist_Init(IPnode **Table, int value)
{
	int i;
  	
	for(i=0;i<value;i++)	Table[i] = NULL;
}


int Hash_Function(unsigned int x)
{
	int a=123,b=151,p=131071;
	int hash;

	hash = ((a*x+b)%p)%10000;

	return hash;
}

IPnode *addnode(unsigned int data)
{
	IPnode *newnode;
	newnode = (IPnode *) malloc(sizeof(IPnode));

	newnode->ip=data;    
   	newnode->link=NULL;
	
	return newnode;
}

void Linklist_Update(IPnode **Table, int value, unsigned int IP)
{
	IPnode *temp;
		
	if(Table[value]==NULL)	Table[value] = addnode(IP);
	else
	{
		temp = Table[value];
		while (temp!=NULL)
		{
			if(temp->ip==IP)	break;
			else if(temp->link==NULL)
			{
				temp->link = addnode(IP);
				break;
			}
			else	temp = temp->link;			
		}

	}	
}

int Linklist_Distinct(IPnode **Table)
{
	int i,count=0;	
	IPnode *temp;
	for(i=0;i<=10000;i++) 
	{
		temp = Table[i];  
		
		while(temp!=NULL)
		{      
       			count++;    
       			temp = temp->link;
		}   
   	}

	return count;  
}

void Linklist_Destroy(IPnode **Table)
{
	int i;
	IPnode *temp;
	
	for(i=0;i<=10000;i++) 
	{
		temp = Table[i];
		
		while(temp!=NULL)
		{      
			temp = Table[i]->link;
			free(Table[i]);
       			Table[i] = temp;
		}   
   	}
}

	

