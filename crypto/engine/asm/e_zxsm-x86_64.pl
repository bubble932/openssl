#! /usr/bin/env perl
#
# Copied and adapted from engines/asm/e_padlock-x86.pl to support 
# Zhaoxin's zxsm engine
#
# Copyright 2011-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# September 2011
#
# Assembler helpers for Padlock engine. See even e_zxsm-x86.pl for
# details.

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../../crypto/perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\"";
*STDOUT=*OUT;

$code=".text\n";

%ZXSM_PREFETCH=(ecb=>128, cbc=>64, ctr32=>32);	# prefetch errata
$ZXSM_CHUNK=512;	# Must be a power of 2 between 32 and 2^20

$ctx="%rdx";
$out="%rdi";
$inp="%rsi";
$len="%rcx";
$chunk="%rbx";

($arg1,$arg2,$arg3,$arg4)=$win64?("%rcx","%rdx","%r8", "%r9") : # Win64 order
                                 ("%rdi","%rsi","%rdx","%rcx"); # Unix order

$code.=<<___;
.globl	zxsm_capability
.type	zxsm_capability,\@abi-omnipotent
.align	16
zxsm_capability:
	mov	%rbx,%r8
	xor	%eax,%eax
	cpuid
	xor	%eax,%eax
	cmp	\$`"0x".unpack("H*",'hS  ')`,%ebx
	jne	.Lnoluck
	cmp	\$`"0x".unpack("H*",'hgna')`,%edx
	jne	.Lnoluck
	cmp	\$`"0x".unpack("H*",'  ia')`,%ecx
	jne	.Lnoluck
	mov	\$0xC0000000,%eax
	cpuid
	mov	%eax,%edx
	xor	%eax,%eax
	cmp	\$0xC0000001,%edx
	jb	.Lnoluck
	mov	\$0xC0000001,%eax
	cpuid
	mov	%edx,%eax
	and	\$0xffffffef,%eax
	or	\$0x10,%eax		# set Nano bit#4
.Lnoluck:
	mov	%r8,%rbx
	ret
.size	zxsm_capability,.-zxsm_capability

.globl	zxsm_key_bswap
.type	zxsm_key_bswap,\@abi-omnipotent,0
.align	16
zxsm_key_bswap:
	mov	240($arg1),%edx
.Lbswap_loop:
	mov	($arg1),%eax
	bswap	%eax
	mov	%eax,($arg1)
	lea	4($arg1),$arg1
	sub	\$1,%edx
	jnz	.Lbswap_loop
	ret
.size	zxsm_key_bswap,.-zxsm_key_bswap

.globl	zxsm_verify_context
.type	zxsm_verify_context,\@abi-omnipotent
.align	16
zxsm_verify_context:
	mov	$arg1,$ctx
	pushf
	lea	.Lzxsm_saved_context(%rip),%rax
	call	_zxsm_verify_ctx
	lea	8(%rsp),%rsp
	ret
.size	zxsm_verify_context,.-zxsm_verify_context

.type	_zxsm_verify_ctx,\@abi-omnipotent
.align	16
_zxsm_verify_ctx:
	mov	8(%rsp),%r8
	bt	\$30,%r8
	jnc	.Lverified
	cmp	(%rax),$ctx
	je	.Lverified
	pushf
	popf
.Lverified:
	mov	$ctx,(%rax)
	ret
.size	_zxsm_verify_ctx,.-_zxsm_verify_ctx

.globl	zxsm_reload_key
.type	zxsm_reload_key,\@abi-omnipotent
.align	16
zxsm_reload_key:
	pushf
	popf
	ret
.size	zxsm_reload_key,.-zxsm_reload_key

.globl	zxsm_aes_block
.type	zxsm_aes_block,\@function,3
.align	16
zxsm_aes_block:
	mov	%rbx,%r8
	mov	\$1,$len
	lea	32($ctx),%rbx		# key
	lea	16($ctx),$ctx		# control word
	.byte	0xf3,0x0f,0xa7,0xc8	# rep xcryptecb
	mov	%r8,%rbx
	ret
.size	zxsm_aes_block,.-zxsm_aes_block

.globl	zxsm_xstore
.type	zxsm_xstore,\@function,2
.align	16
zxsm_xstore:
	mov	%esi,%edx
	.byte	0x0f,0xa7,0xc0		# xstore
	ret
.size	zxsm_xstore,.-zxsm_xstore

.globl	zxsm_sha1_oneshot
.type	zxsm_sha1_oneshot,\@function,3
.align	16
zxsm_sha1_oneshot:
	mov	%rdx,%rcx
	mov	%rdi,%rdx		# put aside %rdi
	movups	(%rdi),%xmm0		# copy-in context
	sub	\$128+8,%rsp
	mov	16(%rdi),%eax
	movaps	%xmm0,(%rsp)
	mov	%rsp,%rdi
	mov	%eax,16(%rsp)
	xor	%rax,%rax
	.byte	0xf3,0x0f,0xa6,0xc8	# rep xsha1
	movaps	(%rsp),%xmm0
	mov	16(%rsp),%eax
	add	\$128+8,%rsp
	movups	%xmm0,(%rdx)		# copy-out context
	mov	%eax,16(%rdx)
	ret
.size	zxsm_sha1_oneshot,.-zxsm_sha1_oneshot

.globl	zxsm_sha1_blocks
.type	zxsm_sha1_blocks,\@function,3
.align	16
zxsm_sha1_blocks:
	mov	%rdx,%rcx
	mov	%rdi,%rdx		# put aside %rdi
	movups	(%rdi),%xmm0		# copy-in context
	sub	\$128+8,%rsp
	mov	16(%rdi),%eax
	movaps	%xmm0,(%rsp)
	mov	%rsp,%rdi
	mov	%eax,16(%rsp)
	mov	\$-1,%rax
	.byte	0xf3,0x0f,0xa6,0xc8	# rep xsha1
	movaps	(%rsp),%xmm0
	mov	16(%rsp),%eax
	add	\$128+8,%rsp
	movups	%xmm0,(%rdx)		# copy-out context
	mov	%eax,16(%rdx)
	ret
.size	zxsm_sha1_blocks,.-zxsm_sha1_blocks

.globl	zxsm_sha256_oneshot
.type	zxsm_sha256_oneshot,\@function,3
.align	16
zxsm_sha256_oneshot:
	mov	%rdx,%rcx
	mov	%rdi,%rdx		# put aside %rdi
	movups	(%rdi),%xmm0		# copy-in context
	sub	\$128+8,%rsp
	movups	16(%rdi),%xmm1
	movaps	%xmm0,(%rsp)
	mov	%rsp,%rdi
	movaps	%xmm1,16(%rsp)
	xor	%rax,%rax
	.byte	0xf3,0x0f,0xa6,0xd0	# rep xsha256
	movaps	(%rsp),%xmm0
	movaps	16(%rsp),%xmm1
	add	\$128+8,%rsp
	movups	%xmm0,(%rdx)		# copy-out context
	movups	%xmm1,16(%rdx)
	ret
.size	zxsm_sha256_oneshot,.-zxsm_sha256_oneshot

.globl	zxsm_sha256_blocks
.type	zxsm_sha256_blocks,\@function,3
.align	16
zxsm_sha256_blocks:
	mov	%rdx,%rcx
	mov	%rdi,%rdx		# put aside %rdi
	movups	(%rdi),%xmm0		# copy-in context
	sub	\$128+8,%rsp
	movups	16(%rdi),%xmm1
	movaps	%xmm0,(%rsp)
	mov	%rsp,%rdi
	movaps	%xmm1,16(%rsp)
	mov	\$-1,%rax
	.byte	0xf3,0x0f,0xa6,0xd0	# rep xsha256
	movaps	(%rsp),%xmm0
	movaps	16(%rsp),%xmm1
	add	\$128+8,%rsp
	movups	%xmm0,(%rdx)		# copy-out context
	movups	%xmm1,16(%rdx)
	ret
.size	zxsm_sha256_blocks,.-zxsm_sha256_blocks

.globl	zxsm_sha512_blocks
.type	zxsm_sha512_blocks,\@function,3
.align	16
zxsm_sha512_blocks:
	mov	%rdx,%rcx
	mov	%rdi,%rdx		# put aside %rdi
	movups	(%rdi),%xmm0		# copy-in context
	sub	\$128+8,%rsp
	movups	16(%rdi),%xmm1
	movups	32(%rdi),%xmm2
	movups	48(%rdi),%xmm3
	movaps	%xmm0,(%rsp)
	mov	%rsp,%rdi
	movaps	%xmm1,16(%rsp)
	movaps	%xmm2,32(%rsp)
	movaps	%xmm3,48(%rsp)
	.byte	0xf3,0x0f,0xa6,0xe0	# rep xha512
	movaps	(%rsp),%xmm0
	movaps	16(%rsp),%xmm1
	movaps	32(%rsp),%xmm2
	movaps	48(%rsp),%xmm3
	add	\$128+8,%rsp
	movups	%xmm0,(%rdx)		# copy-out context
	movups	%xmm1,16(%rdx)
	movups	%xmm2,32(%rdx)
	movups	%xmm3,48(%rdx)
	ret
.size	zxsm_sha512_blocks,.-zxsm_sha512_blocks
___

sub generate_mode {
my ($mode,$opcode) = @_;
# int zxsm_$mode_encrypt(void *out, const void *inp,
#		struct zxsm_cipher_data *ctx, size_t len);
$code.=<<___;
.globl	zxsm_${mode}_encrypt
.type	zxsm_${mode}_encrypt,\@function,4
.align	16
zxsm_${mode}_encrypt:
	push	%rbp
	push	%rbx

	xor	%eax,%eax
	test	\$15,$ctx
	jnz	.L${mode}_abort
	test	\$15,$len
	jnz	.L${mode}_abort
	lea	.Lzxsm_saved_context(%rip),%rax
	pushf
	cld
	call	_zxsm_verify_ctx
	lea	16($ctx),$ctx		# control word
	xor	%eax,%eax
	xor	%ebx,%ebx
	testl	\$`1<<5`,($ctx)		# align bit in control word
	jnz	.L${mode}_aligned
	test	\$0x0f,$out
	setz	%al			# !out_misaligned
	test	\$0x0f,$inp
	setz	%bl			# !inp_misaligned
	test	%ebx,%eax
	jnz	.L${mode}_aligned
	neg	%rax
	mov	\$$ZXSM_CHUNK,$chunk
	not	%rax			# out_misaligned?-1:0
	lea	(%rsp),%rbp
	cmp	$chunk,$len
	cmovc	$len,$chunk		# chunk=len>ZXSM_CHUNK?ZXSM_CHUNK:len
	and	$chunk,%rax		# out_misaligned?chunk:0
	mov	$len,$chunk
	neg	%rax
	and	\$$ZXSM_CHUNK-1,$chunk	# chunk%=ZXSM_CHUNK
	lea	(%rax,%rbp),%rsp
	mov	\$$ZXSM_CHUNK,%rax
	cmovz	%rax,$chunk			# chunk=chunk?:ZXSM_CHUNK
___
$code.=<<___				if ($mode eq "ctr32");
.L${mode}_reenter:
	mov	-4($ctx),%eax		# pull 32-bit counter
	bswap	%eax
	neg	%eax
	and	\$`$ZXSM_CHUNK/16-1`,%eax
	mov	\$$ZXSM_CHUNK,$chunk
	shl	\$4,%eax
	cmovz	$chunk,%rax
	cmp	%rax,$len
	cmova	%rax,$chunk		# don't let counter cross ZXSM_CHUNK
	cmovbe	$len,$chunk
___
$code.=<<___				if ($ZXSM_PREFETCH{$mode});
	cmp	$chunk,$len
	ja	.L${mode}_loop
	mov	$inp,%rax		# check if prefetch crosses page
	cmp	%rsp,%rbp
	cmove	$out,%rax
	add	$len,%rax
	neg	%rax
	and	\$0xfff,%rax		# distance to page boundary
	cmp	\$$ZXSM_PREFETCH{$mode},%rax
	mov	\$-$ZXSM_PREFETCH{$mode},%rax
	cmovae	$chunk,%rax		# mask=distance<prefetch?-prefetch:-1
	and	%rax,$chunk
	jz	.L${mode}_unaligned_tail
___
$code.=<<___;
	jmp	.L${mode}_loop
.align	16
.L${mode}_loop:
	cmp	$len,$chunk		# ctr32 artefact
	cmova	$len,$chunk		# ctr32 artefact
	mov	$out,%r8		# save parameters
	mov	$inp,%r9
	mov	$len,%r10
	mov	$chunk,$len
	mov	$chunk,%r11
	test	\$0x0f,$out		# out_misaligned
	cmovnz	%rsp,$out
	test	\$0x0f,$inp		# inp_misaligned
	jz	.L${mode}_inp_aligned
	shr	\$3,$len
	.byte	0xf3,0x48,0xa5		# rep movsq
	sub	$chunk,$out
	mov	$chunk,$len
	mov	$out,$inp
.L${mode}_inp_aligned:
	lea	-16($ctx),%rax		# ivp
	lea	16($ctx),%rbx		# key
	shr	\$4,$len
	.byte	0xf3,0x0f,0xa7,$opcode	# rep xcrypt*
___
$code.=<<___				if ($mode !~ /ecb|ctr/);
	movdqa	(%rax),%xmm0
	movdqa	%xmm0,-16($ctx)		# copy [or refresh] iv
___
$code.=<<___				if ($mode eq "ctr32");
	mov	-4($ctx),%eax		# pull 32-bit counter
	test	\$0xffff0000,%eax
	jnz	.L${mode}_no_carry
	bswap	%eax
	add	\$0x10000,%eax
	bswap	%eax
	mov	%eax,-4($ctx)
.L${mode}_no_carry:
___
$code.=<<___;
	mov	%r8,$out		# restore parameters
	mov	%r11,$chunk
	test	\$0x0f,$out
	jz	.L${mode}_out_aligned
	mov	$chunk,$len
	lea	(%rsp),$inp
	shr	\$3,$len
	.byte	0xf3,0x48,0xa5		# rep movsq
	sub	$chunk,$out
.L${mode}_out_aligned:
	mov	%r9,$inp
	mov	%r10,$len
	add	$chunk,$out
	add	$chunk,$inp
	sub	$chunk,$len
	mov	\$$ZXSM_CHUNK,$chunk
___
					if (!$ZXSM_PREFETCH{$mode}) {
$code.=<<___;
	jnz	.L${mode}_loop
___
					} else {
$code.=<<___;
	jz	.L${mode}_break
	cmp	$chunk,$len
	jae	.L${mode}_loop
___
$code.=<<___				if ($mode eq "ctr32");
	mov	$len,$chunk
	mov	$inp,%rax		# check if prefetch crosses page
	cmp	%rsp,%rbp
	cmove	$out,%rax
	add	$len,%rax
	neg	%rax
	and	\$0xfff,%rax		# distance to page boundary
	cmp	\$$ZXSM_PREFETCH{$mode},%rax
	mov	\$-$ZXSM_PREFETCH{$mode},%rax
	cmovae	$chunk,%rax
	and	%rax,$chunk
	jnz	.L${mode}_loop
___
$code.=<<___;
.L${mode}_unaligned_tail:
	xor	%eax,%eax
	cmp	%rsp,%rbp
	cmove	$len,%rax
	mov	$out,%r8		# save parameters
	mov	$len,$chunk
	sub	%rax,%rsp		# alloca
	shr	\$3,$len
	lea	(%rsp),$out
	.byte	0xf3,0x48,0xa5		# rep movsq
	mov	%rsp,$inp
	mov	%r8, $out		# restore parameters
	mov	$chunk,$len
	jmp	.L${mode}_loop
.align	16
.L${mode}_break:
___
					}
$code.=<<___;
	cmp	%rbp,%rsp
	je	.L${mode}_done

	pxor	%xmm0,%xmm0
	lea	(%rsp),%rax
.L${mode}_bzero:
	movaps	%xmm0,(%rax)
	lea	16(%rax),%rax
	cmp	%rax,%rbp
	ja	.L${mode}_bzero

.L${mode}_done:
	lea	(%rbp),%rsp
	jmp	.L${mode}_exit

.align	16
.L${mode}_aligned:
___
$code.=<<___				if ($mode eq "ctr32");
	mov	-4($ctx),%eax		# pull 32-bit counter
	bswap	%eax
	neg	%eax
	and	\$0xffff,%eax
	mov	\$`16*0x10000`,$chunk
	shl	\$4,%eax
	cmovz	$chunk,%rax
	cmp	%rax,$len
	cmova	%rax,$chunk		# don't let counter cross 2^16
	cmovbe	$len,$chunk
	jbe	.L${mode}_aligned_skip

.L${mode}_aligned_loop:
	mov	$len,%r10		# save parameters
	mov	$chunk,$len
	mov	$chunk,%r11

	lea	-16($ctx),%rax		# ivp
	lea	16($ctx),%rbx		# key
	shr	\$4,$len		# len/=AES_BLOCK_SIZE
	.byte	0xf3,0x0f,0xa7,$opcode	# rep xcrypt*

	mov	-4($ctx),%eax		# pull 32-bit counter
	bswap	%eax
	add	\$0x10000,%eax
	bswap	%eax
	mov	%eax,-4($ctx)

	mov	%r10,$len		# restore parameters
	sub	%r11,$len
	mov	\$`16*0x10000`,$chunk
	jz	.L${mode}_exit
	cmp	$chunk,$len
	jae	.L${mode}_aligned_loop

.L${mode}_aligned_skip:
___
$code.=<<___				if ($ZXSM_PREFETCH{$mode});
	lea	($inp,$len),%rbp
	neg	%rbp
	and	\$0xfff,%rbp		# distance to page boundary
	xor	%eax,%eax
	cmp	\$$ZXSM_PREFETCH{$mode},%rbp
	mov	\$$ZXSM_PREFETCH{$mode}-1,%rbp
	cmovae	%rax,%rbp
	and	$len,%rbp		# remainder
	sub	%rbp,$len
	jz	.L${mode}_aligned_tail
___
$code.=<<___;
	lea	-16($ctx),%rax		# ivp
	lea	16($ctx),%rbx		# key
	shr	\$4,$len		# len/=AES_BLOCK_SIZE
	.byte	0xf3,0x0f,0xa7,$opcode	# rep xcrypt*
___
$code.=<<___				if ($mode !~ /ecb|ctr/);
	movdqa	(%rax),%xmm0
	movdqa	%xmm0,-16($ctx)		# copy [or refresh] iv
___
$code.=<<___				if ($ZXSM_PREFETCH{$mode});
	test	%rbp,%rbp		# check remainder
	jz	.L${mode}_exit

.L${mode}_aligned_tail:
	mov	$out,%r8
	mov	%rbp,$chunk
	mov	%rbp,$len
	lea	(%rsp),%rbp
	sub	$len,%rsp
	shr	\$3,$len
	lea	(%rsp),$out
	.byte	0xf3,0x48,0xa5		# rep movsq
	lea	(%r8),$out
	lea	(%rsp),$inp
	mov	$chunk,$len
	jmp	.L${mode}_loop
___
$code.=<<___;
.L${mode}_exit:
	mov	\$1,%eax
	lea	8(%rsp),%rsp
.L${mode}_abort:
	pop	%rbx
	pop	%rbp
	ret
.size	zxsm_${mode}_encrypt,.-zxsm_${mode}_encrypt
___
}

&generate_mode("ecb",0xc8);
&generate_mode("cbc",0xd0);
&generate_mode("cfb",0xe0);
&generate_mode("ofb",0xe8);
&generate_mode("ctr32",0xd8);	# all 64-bit CPUs have working CTR...

$code.=<<___;
.asciz	"Shanghai ZXSM x86_64 module"
.align	16
.data
.align	8
.Lzxsm_saved_context:
	.quad	0
___
$code =~ s/\`([^\`]*)\`/eval($1)/gem;

print $code;

close STDOUT;
