#ifndef _LZASM_H
#define _LZASM_H

// assembly routines from lz.S
extern void __lz_vectors(void);
extern void __lz_vectors_end(void);
extern long long __lz_ttbr0_tab[];
extern long long __lz_zone_ret_tab[];
extern char __lz_call_gate[];
extern char __lz_call_gate_end[];

#endif