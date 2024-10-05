all:
	gcc clone.c -o clone_fast -llz -march=armv8.2-a
	gcc clone.c -o clone_scalable -DLZ_SCALABLE -llz -march=armv8.2-a
	gcc cycle.c -o cycle_scalable -DLZ_SCALABLE -DNDOM=128 -llz -march=armv8.2-a
	gcc esyscall.c -o esyscall_fast -llz -march=armv8.2-a
	gcc esyscall.c -o esyscall_scalable -DLZ_SCALABLE -llz -march=armv8.2-a
	gcc filemap.c -o filemap_fast -llz -march=armv8.2-a
	gcc filemap.c -o filemap_scalable -DLZ_SCALABLE -llz -march=armv8.2-a
	gcc fpu.c -o fpu_fast -llz -lpthread -march=armv8.2-a
	gcc fpu.c -o fpu_scalable -DLZ_SCALABLE -llz -lpthread -march=armv8.2-a
	gcc munmap.c -o munmap_fast -llz -march=armv8.2-a
	gcc munmap.c -o munmap_scalable -DLZ_SCALABLE -llz -march=armv8.2-a
	gcc signal.c -o signal_fast -llz -march=armv8.2-a
	gcc signal.c -o signal_scalable -DLZ_SCALABLE -llz -march=armv8.2-a
	gcc simple.c -o simple_fast -llz -march=armv8.2-a
	gcc simple.c -o simple_scalable -DLZ_SCALABLE -llz -march=armv8.2-a
	gcc threads.c -o threads_fast -llz -lpthread -march=armv8.2-a
	gcc threads.c -o threads_scalable -DLZ_SCALABLE -llz -lpthread -march=armv8.2-a
	gcc prot.c -o prot_fast -llz -lpthread -march=armv8.2-a
	gcc prot.c -o prot_scalable -DLZ_SCALABLE -llz -lpthread -march=armv8.2-a
	gcc sigcontext.c -o sigcontext_fast -llz -march=armv8.2-a
	gcc sigcontext.c -o sigcontext_scalable -DLZ_SCALABLE -llz -march=armv8.2-a
	# gcc ldtr.c -o ldtr_fast -llz -march=armv8.2-a
	gcc pf.c -o pf_fast -llz -march=armv8.2-a
	gcc pf.c -o pf_scalable -DLZ_SCALABLE -llz -march=armv8.2-a
	gcc mem.c -o mem_scalable -DLZ_SCALABLE -llz -march=armv8.2-a
