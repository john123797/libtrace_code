all: FM_hw linklist compare_F_A CM_all CM_interval

FM_hw: FM_hw.c
	gcc -Wall -o FM_hw FM_hw.c header/fm.c header/prng.c -ltrace -lm

linklist: linklist.c
	gcc -Wall -o linklist linklist.c header/link_list_counting.c -ltrace

compare_F_A: compare_F_A.c
	gcc -Wall -o compare_F_A compare_F_A.c header/fm.c header/prng.c header/link_list_counting.c -ltrace -lm

CM_all: CM_all.c
	gcc -Wall -o CM_all CM_all.c header/countmin.c header/prng.c header/link_list_counting.c -ltrace -lm

CM_interval : CM_interval.c
	gcc -Wall -o CM_interval CM_interval.c header/countmin.c header/prng.c -ltrace -lm

clean:
	rm -f FM_hw timestamp linklist compare_F_A CM_all CM_interval 
