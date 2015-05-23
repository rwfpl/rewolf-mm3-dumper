/**************************************************************
    lzhuf.c
    written by Haruyasu Yoshizaki 1988/11/20
    
	some minor changes 1989/04/06
    
	comments translated by Haruhiko Okumura 1989/04/07
    
	getbit and getbyte modified 1990/03/23 by Paul Edwards
    so that they would work on machines where integers are
    not necessarily 16 bits (although ANSI guarantees a
    minimum of 16).  This program has compiled and run with
    no errors under Turbo C 2.0, Power C, and SAS/C 4.5
    (running on an IBM mainframe under MVS/XA 2.2).  Could
    people please use YYYY/MM/DD date format so that everyone
    in the world can know what format the date is in?
    
	external storage of filesize changed 1990/04/18 by Paul Edwards to
    Intel's "little endian" rather than a machine-dependant style so
    that files produced on one machine with lzhuf can be decoded on
    any other.  "little endian" style was chosen since lzhuf
    originated on PC's, and therefore they should dictate the
    standard.
    
	initialization of something predicting spaces changed 1990/04/22 by
    Paul Edwards so that when the compressed file is taken somewhere
    else, it will decode properly, without changing ascii spaces to
    ebcdic spaces.  This was done by changing the ' ' (space literal)
    to 0x20 (which is the far most likely character to occur, if you
    don't know what environment it will be running on.

	2015/05/03 - by ReWolf - cut off all code except compression, 
	                         changed interface a bit, changed types
							 of integers to the set from <cstdint>,
							 moved global variables to the class,
							 changed input/output from files to memory
							 buffers
**************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <cstdint>

#define N_CHAR		(256 - THRESHOLD + F)	/* kinds of characters (character code = 0..N_CHAR-1) */
#define T			(N_CHAR * 2 - 1)		/* size of table */
#define R			(T - 1)					/* position of root */
#define MAX_FREQ	0x8000					/* updates tree when the */
#define N			4096					/* buffer size */
#define F			60						/* lookahead buffer size */
#define THRESHOLD	2
#define NIL			N						/* leaf of tree */

/* table for encoding the upper 6 bits of position */
static const uint8_t p_len[64] = 
{
    0x03, 0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08
};

static const uint8_t p_code[64] = 
{
    0x00, 0x20, 0x30, 0x40, 0x50, 0x58, 0x60, 0x68,
    0x70, 0x78, 0x80, 0x88, 0x90, 0x94, 0x98, 0x9C,
    0xA0, 0xA4, 0xA8, 0xAC, 0xB0, 0xB4, 0xB8, 0xBC,
    0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE,
    0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE,
    0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
};

class LzHuffCompress
{
private:
	uint8_t* g_outBuf;
	uint16_t textsize = 0, codesize = 0;
	
	uint8_t text_buf[N + F - 1];
	uint16_t match_position, match_length, lson[N + 1], rson[N + 257], dad[N + 1];
	
	uint16_t freq[T + 1];		/* frequency table */
	uint16_t prnt[T + N_CHAR];	/* pointers to parent nodes, except for the */
								/* elements [T..T + N_CHAR - 1] which are used to get */
								/* the positions of leaves corresponding to the codes. */
	
	uint16_t son[T];			/* pointers to child nodes (son[], son[] + 1) */
	
	uint16_t putbuf = 0;
	uint8_t putlen = 0;

	void InitTree(void);
	void InsertNode(uint16_t r);
	void DeleteNode(uint16_t p);
	void Putcode(uint16_t l, uint16_t c);
	void StartHuff(void);
	void reconst(void);
	void update(uint16_t c);
	void EncodeChar(uint16_t c);
	void EncodePosition(uint16_t c);
	void EncodeEnd(void);
public:
	LzHuffCompress() { memset(this, 0, sizeof(LzHuffCompress)); };
	size_t Compress(uint8_t* inBuf, size_t inSize, uint8_t* outBuf, size_t outSize, uint8_t initValue);
};

void LzHuffCompress::InitTree(void)  /* initialize trees */
{
    int  i;

    for (i = N + 1; i <= N + 256; i++)
        rson[i] = NIL;        /* root */
    for (i = 0; i < N; i++)
        dad[i] = NIL;         /* node */
}

void LzHuffCompress::InsertNode(uint16_t r)  /* insert to tree */
{
    uint16_t  i, p, cmp;
    uint8_t  *key;
    uint16_t c;

    cmp = 1;
    key = &text_buf[r];
    p = N + 1 + key[0];
    rson[r] = lson[r] = NIL;
    match_length = 0;
    for ( ; ; ) {
        if (cmp >= 0) {
            if (rson[p] != NIL)
                p = rson[p];
            else {
                rson[p] = r;
                dad[r] = p;
                return;
            }
        } else {
            if (lson[p] != NIL)
                p = lson[p];
            else {
                lson[p] = r;
                dad[r] = p;
                return;
            }
        }
        for (i = 1; i < F; i++)
            if ((cmp = key[i] - text_buf[p + i]) != 0)
                break;
        if (i > THRESHOLD) {
            if (i > match_length) {
                match_position = ((r - p) & (N - 1)) - 1;
                if ((match_length = i) >= F)
                    break;
            }
            if (i == match_length) {
                if ((c = ((r - p) & (N-1)) - 1) < (unsigned)match_position) {
                    match_position = c;
                }
            }
        }
    }
    dad[r] = dad[p];
    lson[r] = lson[p];
    rson[r] = rson[p];
    dad[lson[p]] = r;
    dad[rson[p]] = r;
    if (rson[dad[p]] == p)
        rson[dad[p]] = r;
    else
        lson[dad[p]] = r;
    dad[p] = NIL; /* remove p */
}

void LzHuffCompress::DeleteNode(uint16_t p)  /* remove from tree */
{
    uint16_t  q;

    if (dad[p] == NIL)
        return;         /* not registered */
    if (rson[p] == NIL)
        q = lson[p];
    else
    if (lson[p] == NIL)
        q = rson[p];
    else {
        q = lson[p];
        if (rson[q] != NIL) {
            do {
                q = rson[q];
            } while (rson[q] != NIL);
            rson[dad[q]] = lson[q];
            dad[lson[q]] = dad[q];
            lson[q] = lson[p];
            dad[lson[p]] = q;
        }
        rson[q] = rson[p];
        dad[rson[p]] = q;
    }
    dad[q] = dad[p];
    if (rson[dad[p]] == p)
        rson[dad[p]] = q;
    else
        lson[dad[p]] = q;
    dad[p] = NIL;
}

void LzHuffCompress::Putcode(uint16_t l, uint16_t c)     /* output c bits of code */
{
    putbuf |= c >> putlen;
    if ((putlen += l) >= 8) {
		*g_outBuf++ = putbuf >> 8;
        if ((putlen -= 8) >= 8) {
			*g_outBuf++ = (uint8_t)putbuf;
            codesize += 2;
            putlen -= 8;
            putbuf = c << (l - putlen);
        } else {
            putbuf <<= 8;
            codesize++;
        }
    }
}

/* initialization of tree */
void LzHuffCompress::StartHuff(void)
{
    uint16_t i, j;

    for (i = 0; i < N_CHAR; i++) {
        freq[i] = 1;
        son[i] = i + T;
        prnt[i + T] = i;
    }
    i = 0; j = N_CHAR;
    while (j <= R) {
        freq[j] = freq[i] + freq[i + 1];
        son[j] = i;
        prnt[i] = prnt[i + 1] = j;
        i += 2; j++;
    }
    freq[T] = 0xffff;
    prnt[R] = 0;
}

/* reconstruction of tree */
void LzHuffCompress::reconst(void)
{
    uint16_t i, j, k;
    uint16_t f, l;

    /* collect leaf nodes in the first half of the table */
    /* and replace the freq by (freq + 1) / 2. */
    j = 0;
    for (i = 0; i < T; i++) {
        if (son[i] >= T) {
            freq[j] = (freq[i] + 1) / 2;
            son[j] = son[i];
            j++;
        }
    }
    /* begin constructing tree by connecting sons */
    for (i = 0, j = N_CHAR; j < T; i += 2, j++) {
        k = i + 1;
        f = freq[j] = freq[i] + freq[k];
        for (k = j - 1; f < freq[k]; k--);
        k++;
        l = (j - k) * 2;
        memmove(&freq[k + 1], &freq[k], l);
        freq[k] = f;
        memmove(&son[k + 1], &son[k], l);
        son[k] = i;
    }
    /* connect prnt */
    for (i = 0; i < T; i++) {
        if ((k = son[i]) >= T) {
            prnt[k] = i;
        } else {
            prnt[k] = prnt[k + 1] = i;
        }
    }
}

/* increment frequency of given code by one, and update tree */
void LzHuffCompress::update(uint16_t c)
{
    uint16_t i, j, k, l;

    if (freq[R] == MAX_FREQ) {
        reconst();
    }
    c = prnt[c + T];
    do {
        k = ++freq[c];

        /* if the order is disturbed, exchange nodes */
        if ((unsigned)k > freq[l = c + 1]) {
            while ((unsigned)k > freq[++l]);
            l--;
            freq[c] = freq[l];
            freq[l] = k;

            i = son[c];
            prnt[i] = l;
            if (i < T) prnt[i + 1] = l;

            j = son[l];
            son[l] = i;

            prnt[j] = c;
            if (j < T) prnt[j + 1] = c;
            son[c] = j;

            c = l;
        }
    } while ((c = prnt[c]) != 0); /* repeat up to root */
}

void LzHuffCompress::EncodeChar(uint16_t c)
{
    uint16_t j = 0;
    uint16_t i = 0;
    uint16_t k = prnt[c + T];

    /* travel from leaf to root */
    do {
        i >>= 1;

        /* if node's address is odd-numbered, choose bigger brother node */
        if (k & 1) i += 0x8000;

        j++;
    } while ((k = prnt[k]) != R);
    Putcode(j, i);
    update(c);
}

void LzHuffCompress::EncodePosition(uint16_t c)
{
    uint16_t i;

    /* output upper 6 bits by table lookup */
    i = c >> 6;
    Putcode(p_len[i], p_code[i] << 8);

    /* output lower 6 bits verbatim */
    Putcode(6, (c & 0x3f) << 10);
}

void LzHuffCompress::EncodeEnd(void)
{
    if (putlen) {
		*g_outBuf++ = putbuf >> 8;
        codesize++;
    }
}

/* compression */
size_t LzHuffCompress::Compress(uint8_t* inBuf, size_t inSize, uint8_t* outBuf, size_t outSize, uint8_t initValue)
{
    uint16_t  i, c, len, r, s, last_match_length;

	g_outBuf = outBuf;
	uint8_t* crPtr = inBuf;

    textsize = 0;
    StartHuff();
    InitTree();
    s = 0;
    r = N - F;
    for (i = s; i < r; i++)
        text_buf[i] = initValue;

    for (len = 0; len < F && (crPtr < inBuf + inSize); len++)
        text_buf[r + len] = *crPtr++;

    textsize = len;
    for (i = 1; i <= F; i++)
        InsertNode(r - i);
    InsertNode(r);
    do 
	{
        if (match_length > len)
            match_length = len;
        if (match_length <= THRESHOLD) {
            match_length = 1;
            EncodeChar(text_buf[r]);
        } else {
            EncodeChar(255 - THRESHOLD + match_length);
            EncodePosition(match_position);
        }
        last_match_length = match_length;
        for (i = 0; i < last_match_length && (crPtr < inBuf + inSize); i++) 
		{
			c = *crPtr++;
            DeleteNode(s);
            text_buf[s] = (uint8_t)c;
            if (s < F - 1)
                text_buf[s + N] = (uint8_t)c;
            s = (s + 1) & (N - 1);
            r = (r + 1) & (N - 1);
            InsertNode(r);
        }

        while (i++ < last_match_length) {
            DeleteNode(s);
            s = (s + 1) & (N - 1);
            r = (r + 1) & (N - 1);
            if (--len) InsertNode(r);
        }
    } while (len > 0);
    EncodeEnd();
	return codesize;
}

size_t lzhuf_compress(uint8_t* inBuf, size_t inSize, uint8_t* outBuf, size_t outSize, uint8_t initValue)
{
	return LzHuffCompress().Compress(inBuf, inSize, outBuf, outSize, initValue);
}
