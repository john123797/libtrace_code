
typedef struct IPnode {
	unsigned int ip;
	struct IPnode *link;
}IPnode;

extern void Linklist_Init(IPnode **, int);
extern int Hash_Function(unsigned int);
extern void Linklist_Update(IPnode **, int, unsigned int);
extern int Linklist_Distinct(IPnode **Table);
extern void Linklist_Destroy(IPnode **Table);
