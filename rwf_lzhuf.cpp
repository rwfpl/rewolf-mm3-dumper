#include <cstdint>
#include <intrin.h>
#include <cstring>
#include <cstdio>

static const uint8_t d_len[0x100] =
{
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 
	5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 
	5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 
	5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 
	5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8
};

static const uint8_t d_code[0x100] =
{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 
	4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 
	6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 
	8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 
	10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 
	12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15, 
	16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18, 19, 19, 19, 19, 
	20, 20, 20, 20, 21, 21, 21, 21, 22, 22, 22, 22, 23, 23, 23, 23, 
	24, 24, 25, 25, 26, 26, 27, 27, 28, 28, 29, 29, 30, 30, 31, 31,
	32, 32, 33, 33, 34, 34, 35, 35, 36, 36, 37, 37, 38, 38, 39, 39,
	40, 40, 41, 41, 42, 42, 43, 43, 44, 44, 45, 45, 46, 46, 47, 47,
	48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
};

static const uint16_t LZHUF_MAX_FREQ	= 0x8000;
static const uint16_t LZHUF_N			= 0x1000;
static const uint16_t LZHUF_F			= 0x3c;
static const uint16_t LZHUF_THRESHOLD	= 2;
static const uint16_t LZHUF_N_CHAR		= 0x100 - LZHUF_THRESHOLD + LZHUF_F;		// 0x13A
static const uint16_t LZHUF_T			= LZHUF_N_CHAR * 2 - 1;						// 0x273
static const uint16_t LZHUF_R			= LZHUF_T - 1;								// 0x272

size_t rwf_lzhuf_decompress(uint8_t* inBuf, size_t inSize, uint8_t* outBuf, uint16_t outSize, uint8_t initValue)
{
	uint8_t* outBufBegin = outBuf;
	uint16_t freq[LZHUF_T + 1] = { 0 };
	uint16_t prnt[LZHUF_T + LZHUF_N_CHAR] = { 0 };
	uint16_t son[LZHUF_T] = { 0 };
	uint16_t cache = 0x8000;

	// huffmann init
	for (uint16_t i = 0; i < LZHUF_N_CHAR; i++)
	{
		freq[i] = 1;
		prnt[i + LZHUF_T] = i;
		son[i] = i + LZHUF_T;
	}	
	for (uint16_t i = 0, j = LZHUF_N_CHAR; j < LZHUF_T; i+=2, j++)
	{
		freq[j] = freq[i] + freq[i + 1];
		son[j] = i;
		prnt[i] = j;
		prnt[i + 1] = j;
	}
	prnt[LZHUF_R] = 0;
	freq[LZHUF_T] = 0xFFFF;

	uint16_t textBufIndex = LZHUF_N - LZHUF_F;
	uint8_t textBuf[LZHUF_N];
	for (int i = 0; i < LZHUF_N - LZHUF_F; i++)
		textBuf[i] = initValue;

	uint16_t outBufIndex = 0;
	while (outBufIndex < outSize)
	{
		// decode char
		uint16_t c = son[LZHUF_R];
		while (c < LZHUF_T)
		{
			uint16_t bit = cache >> 0xF;
			cache <<= 1;
			if (0 == cache)
			{
				uint16_t tmp = _rotl16(*(uint16_t*)inBuf, 8);
				inBuf += 2;
				bit = tmp >> 0xF;
				cache = (tmp << 1) | 1;
			}
			c += bit;
			c = son[c];
		}
		c -= LZHUF_T;

		if (freq[LZHUF_R] == LZHUF_MAX_FREQ)
		{
			// tree reconstruction (this part is taken 1:1 from original LZHUF, as
			// it is not triggered for files from MM3.CC, so I decided to not reverse
			// engineer it. When it was clear that it is LZHUF, I just put it here to
			// have complete decmpression just in case)
			
			for (int i = 0, j = 0; i < LZHUF_T; i++) 
			{
			    if (son[i] >= LZHUF_T) 
				{
			        freq[j] = (freq[i] + 1) / 2;
			        son[j] = son[i];
					j++;
			    }
			}

			for (uint16_t i = 0, j = LZHUF_N_CHAR; j < LZHUF_T; i += 2, j++) 
			{
			    int k = i + 1;
			    uint16_t f = freq[j] = freq[i] + freq[k];
			    for (k = j - 1; f < freq[k]; k--);
			    k++;
			    int l = j - k;
			    memmove(freq + k + 1, freq + k, l * sizeof(uint16_t));
			    freq[k] = f;
			    memmove(son + k + 1, son + k, l * sizeof(uint16_t));
			    son[k] = i;
			}
			
			for (uint16_t i = 0; i < LZHUF_T; i++) 
			{
				int k = son[i];
			    if (k >= LZHUF_T) 
			        prnt[k] = i;
				else 
			        prnt[k] = prnt[k + 1] = i;
			}
		}

		//update tree
		uint16_t b = prnt[c + LZHUF_T];
		do
		{
			uint16_t k = ++freq[b];
			if (k > freq[b + 1])
			{
				uint16_t l = b + 1;
				do { l++; } while (k > freq[l]);
				
				l--;
				freq[b] = freq[l];
				freq[l] = k;
				
				uint16_t i = son[b];
				prnt[i] = l;
				if (i < LZHUF_T)
					prnt[i + 1] = l;
				
				uint16_t j = son[l];
				son[l] = i;
				prnt[j] = b;
				if (j < LZHUF_T)
					prnt[j + 1] = b;
				
				son[b] = j;
				b = l;
			}
			b = prnt[b];
		} 
		while (b != 0);

		if (c < 0x100)
		{
			*outBuf++ = (uint8_t)c;
			textBuf[textBufIndex++] = (uint8_t)c;
			textBufIndex &= (LZHUF_N - 1);
			outBufIndex++;
			continue;
		}

		uint16_t bt = 0;
		for (int i = 0; i < 8; i++)
		{
			uint16_t bit = cache >> 0xF;
			cache <<= 1;
			if (cache == 0)
			{
				cache = _rotl16(*(uint16_t*)inBuf, 8);
				inBuf += 2;				
				bit = 1;
				for (int j = 0; j < 8 - i; j++)
				{
					uint16_t tmp_bit = cache >> 0xF;
					cache <<= 1;
					cache |= bit;
					bit = tmp_bit;
					tmp_bit = bt >> 0xF;
					bt <<= 1;
					bt |= bit;
					bit = tmp_bit;
				}
				break;
			}
			bt <<= 1;
			bt |= bit;
		}
		
		uint16_t dc = d_code[bt] << 6;
		uint16_t i = d_len[bt] - 1;
		while (--i != 0)
		{
			uint16_t bit = cache >> 0xF;
			cache <<= 1;
			if (cache == 0)
			{
				cache = _rotl16(*(uint16_t*)inBuf, 8);
				inBuf += 2;
				bit = cache >> 0xF;
				cache <<= 1;
				cache |= 1;
			}
			bt <<= 1;
			bt |= bit;
		}
		dc |= (bt & 0x3F);
		uint16_t textBufIndex2 = textBufIndex - dc - 1;
		for (uint16_t i = c - 0xFD; i > 0; i--)
		{
			textBufIndex2 &= 0xFFF;
			uint8_t tmp = textBuf[textBufIndex2];
			*outBuf++ = tmp;
			textBuf[textBufIndex++] = tmp;
			textBufIndex &= (LZHUF_N - 1);
			outBufIndex++;
			textBufIndex2++;
		}
	}
	return outBuf - outBufBegin;
}
